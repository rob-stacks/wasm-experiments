//! Benchmarks the Clarity conversion and hashing/crypto built-ins:
//!   * natively (the `kernels` crate linked into this binary),
//!   * as a pure wasm module (the same crate built for wasm32-unknown-unknown)
//!     under wasmtime with Cranelift and wasmi,
//!   * plus the hand-written WAT keccak256 / secp256k1-verify modules.
//!
//! Usage: bench [--quick] [filter]   (build the guest first, see run.sh)

mod fixtures;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use fixtures::{Case, Code};

const GUEST_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/wasm32-unknown-unknown/release/guest.wasm"
);
const KECCAK_WAT: &str = include_str!("../../wat/keccak256.wat");
const ECDSA_WAT: &str = include_str!("../../wat/ecdsa.wat");

// ---------------------------------------------------------------------------
// Runners
// ---------------------------------------------------------------------------

/// Where a case's input lives once loaded into a runner.
#[derive(Clone, Copy)]
struct Loaded {
    ptr: u32,
    len: u32,
}

trait Runner {
    fn load(&mut self, input: &[u8]) -> Result<Loaded>;
    /// Run `iters` iterations entirely inside the runner; returns the checksum.
    fn run(&mut self, case: u32, input: Loaded, iters: u32) -> Result<u64>;
}

struct Native {
    input: Vec<u8>,
}

impl Runner for Native {
    fn load(&mut self, input: &[u8]) -> Result<Loaded> {
        self.input = input.to_vec();
        Ok(Loaded { ptr: 0, len: input.len() as u32 })
    }
    fn run(&mut self, case: u32, _input: Loaded, iters: u32) -> Result<u64> {
        Ok(kernels::run(case, &self.input, iters))
    }
}

/// The two kinds of module: the Rust guest (`alloc` + `run(case, ptr, len, iters)`)
/// and the hand-written WAT modules (`heap_base` + `bench(ptr, len, iters)`).
enum Entry<G, W> {
    Guest { alloc: G, run: W },
    Wat { heap_base: u32, bench: W },
}

struct WasmtimeRunner {
    store: wasmtime::Store<()>,
    memory: wasmtime::Memory,
    entry: Entry<wasmtime::TypedFunc<u32, u32>, wasmtime::Func>,
}

impl WasmtimeRunner {
    fn new(engine: &wasmtime::Engine, wasm: &[u8]) -> Result<Self> {
        Self::instantiate(engine, &wasmtime::Module::new(engine, wasm)?)
    }

    fn instantiate(engine: &wasmtime::Engine, module: &wasmtime::Module) -> Result<Self> {
        let mut store = wasmtime::Store::new(engine, ());
        let instance = wasmtime::Instance::new(&mut store, module, &[])?;
        let memory = instance.get_memory(&mut store, "memory").context("memory export")?;
        let entry = if let Some(heap_base) = instance.get_global(&mut store, "heap_base") {
            let heap_base = heap_base.get(&mut store).i32().context("heap_base")? as u32;
            Entry::Wat { heap_base, bench: instance.get_func(&mut store, "bench").context("bench")? }
        } else {
            Entry::Guest {
                alloc: instance.get_typed_func(&mut store, "alloc")?,
                run: instance.get_func(&mut store, "run").context("run")?,
            }
        };
        Ok(Self { store, memory, entry })
    }
}

impl Runner for WasmtimeRunner {
    fn load(&mut self, input: &[u8]) -> Result<Loaded> {
        let ptr = match &self.entry {
            // room for the input plus the WAT modules' output buffer
            Entry::Guest { alloc, .. } => alloc.call(&mut self.store, input.len() as u32 + 64)?,
            Entry::Wat { heap_base, .. } => *heap_base,
        };
        // The WAT modules start with one page; grow it for large inputs.
        let needed = ptr as u64 + input.len() as u64 + 64;
        let have = self.memory.data_size(&self.store) as u64;
        if needed > have {
            self.memory.grow(&mut self.store, (needed - have).div_ceil(65536))?;
        }
        self.memory.write(&mut self.store, ptr as usize, input)?;
        Ok(Loaded { ptr, len: input.len() as u32 })
    }
    fn run(&mut self, case: u32, input: Loaded, iters: u32) -> Result<u64> {
        let r = match &self.entry {
            Entry::Guest { run, .. } => run
                .typed::<(u32, u32, u32, u32), u64>(&self.store)?
                .call(&mut self.store, (case, input.ptr, input.len, iters))?,
            Entry::Wat { bench, .. } => bench
                .typed::<(u32, u32, u32), u64>(&self.store)?
                .call(&mut self.store, (input.ptr, input.len, iters))?,
        };
        Ok(r)
    }
}

struct WasmiRunner {
    store: wasmi::Store<()>,
    memory: wasmi::Memory,
    entry: Entry<wasmi::TypedFunc<u32, u32>, wasmi::Func>,
}

impl WasmiRunner {
    fn new(engine: &wasmi::Engine, wasm: &[u8]) -> Result<Self> {
        Self::instantiate(engine, &wasmi::Module::new(engine, wasm).map_err(|e| anyhow!("{e}"))?)
    }

    fn instantiate(engine: &wasmi::Engine, module: &wasmi::Module) -> Result<Self> {
        let mut store = wasmi::Store::new(engine, ());
        let linker = wasmi::Linker::<()>::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, module)
            .map_err(|e| anyhow!("{e}"))?;
        let memory = instance.get_memory(&store, "memory").context("memory export")?;
        let entry = if let Some(heap_base) = instance.get_global(&store, "heap_base") {
            let heap_base = heap_base.get(&store).i32().context("heap_base")? as u32;
            Entry::Wat { heap_base, bench: instance.get_func(&store, "bench").context("bench")? }
        } else {
            Entry::Guest {
                alloc: instance.get_typed_func(&store, "alloc").map_err(|e| anyhow!("{e}"))?,
                run: instance.get_func(&store, "run").context("run")?,
            }
        };
        Ok(Self { store, memory, entry })
    }
}

impl WasmiRunner {
    /// Fuel consumed by one iteration of `case` (requires a fuel-metered engine).
    /// Measured as the difference between a 1- and a 3-iteration run, after a
    /// warm-up, so lazy translation, per-case setup and call overhead cancel out.
    fn fuel_per_iter(&mut self, case: u32, input: Loaded) -> Result<u64> {
        const START: u64 = u64::MAX / 2;
        self.run(case, input, 1)?; // warm-up: translates the functions it touches
        let mut consumed = |iters: u32| -> Result<u64> {
            self.store.set_fuel(START).map_err(|e| anyhow!("{e}"))?;
            self.run(case, input, iters)?;
            Ok(START - self.store.get_fuel().map_err(|e| anyhow!("{e}"))?)
        };
        let one = consumed(1)?;
        let three = consumed(3)?;
        let per_iter = (three - one) / 2;
        if three - one != 2 * per_iter {
            bail!("case {case}: fuel per iteration is not constant ({one} vs {three})");
        }
        Ok(per_iter)
    }
}

impl Runner for WasmiRunner {
    fn load(&mut self, input: &[u8]) -> Result<Loaded> {
        let ptr = match &self.entry {
            Entry::Guest { alloc, .. } => alloc
                .call(&mut self.store, input.len() as u32 + 64)
                .map_err(|e| anyhow!("{e}"))?,
            Entry::Wat { heap_base, .. } => *heap_base,
        };
        let needed = ptr as u64 + input.len() as u64 + 64;
        let have = self.memory.data_size(&self.store) as u64;
        if needed > have {
            self.memory
                .grow(&mut self.store, (needed - have).div_ceil(65536))
                .map_err(|e| anyhow!("{e}"))?;
        }
        self.memory
            .write(&mut self.store, ptr as usize, input)
            .map_err(|e| anyhow!("{e}"))?;
        Ok(Loaded { ptr, len: input.len() as u32 })
    }
    fn run(&mut self, case: u32, input: Loaded, iters: u32) -> Result<u64> {
        let r = match &self.entry {
            Entry::Guest { run, .. } => run
                .typed::<(u32, u32, u32, u32), u64>(&self.store)
                .map_err(|e| anyhow!("{e}"))?
                .call(&mut self.store, (case, input.ptr, input.len, iters)),
            Entry::Wat { bench, .. } => bench
                .typed::<(u32, u32, u32), u64>(&self.store)
                .map_err(|e| anyhow!("{e}"))?
                .call(&mut self.store, (input.ptr, input.len, iters)),
        };
        r.map_err(|e| anyhow!("{e}"))
    }
}

/// One wasm engine configuration, instantiated once per module.
struct Engine {
    name: &'static str,
    guest: Box<dyn Runner>,
    keccak_wat: Box<dyn Runner>,
    ecdsa_wat: Box<dyn Runner>,
}

impl Engine {
    fn wasmtime(name: &'static str, config: &wasmtime::Config, mods: &Modules) -> Result<Self> {
        let engine = wasmtime::Engine::new(config)?;
        Ok(Self {
            name,
            guest: Box::new(WasmtimeRunner::new(&engine, &mods.guest)?),
            keccak_wat: Box::new(WasmtimeRunner::new(&engine, &mods.keccak)?),
            ecdsa_wat: Box::new(WasmtimeRunner::new(&engine, &mods.ecdsa)?),
        })
    }
    fn wasmi(mods: &Modules) -> Result<Self> {
        let mut config = wasmi::Config::default();
        config.wasm_wide_arithmetic(true).wasm_simd(true);
        let engine = wasmi::Engine::new(&config);
        Ok(Self {
            name: "wasmi",
            guest: Box::new(WasmiRunner::new(&engine, &mods.guest)?),
            keccak_wat: Box::new(WasmiRunner::new(&engine, &mods.keccak)?),
            ecdsa_wat: Box::new(WasmiRunner::new(&engine, &mods.ecdsa)?),
        })
    }
    fn runner(&mut self, code: Code) -> &mut dyn Runner {
        match code {
            Code::Kernel(_) => self.guest.as_mut(),
            Code::KeccakWat => self.keccak_wat.as_mut(),
            Code::EcdsaWat => self.ecdsa_wat.as_mut(),
        }
    }
}

struct Modules {
    guest: Vec<u8>,
    keccak: Vec<u8>,
    ecdsa: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Settings {
    calibrate: Duration,
    sample: Duration,
    samples: usize,
}

fn time(r: &mut dyn Runner, case: u32, input: Loaded, iters: u32) -> Result<Duration> {
    let start = Instant::now();
    std::hint::black_box(r.run(case, input, iters)?);
    Ok(start.elapsed())
}

/// Best-of-N nanoseconds per iteration, after calibrating the iteration count.
fn measure(r: &mut dyn Runner, case: u32, input: Loaded, s: &Settings) -> Result<f64> {
    time(r, case, input, 1)?; // warm-up (lazy compilation, first-touch memory)
    let mut iters = 1u32;
    let mut elapsed;
    loop {
        elapsed = time(r, case, input, iters)?;
        if elapsed >= s.calibrate || iters >= 1 << 28 {
            break;
        }
        iters = iters.saturating_mul(if elapsed < s.calibrate / 10 { 10 } else { 2 });
    }
    let per_sample =
        ((iters as f64) * s.sample.as_secs_f64() / elapsed.as_secs_f64()).clamp(1.0, u32::MAX as f64) as u32;
    let mut best = f64::MAX;
    for _ in 0..s.samples {
        let t = time(r, case, input, per_sample)?;
        best = best.min(t.as_nanos() as f64 / per_sample as f64);
    }
    Ok(best)
}

fn fmt_ns(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{ns:.1} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else {
        format!("{:.2} ms", ns / 1_000_000.0)
    }
}

// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let quick = args.iter().any(|a| a == "--quick");
    let filter = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && (*i == 0 || args[i - 1] != "--codesize"))
        .map(|(_, a)| a.clone());
    let settings = if quick {
        Settings { calibrate: Duration::from_millis(5), sample: Duration::from_millis(20), samples: 3 }
    } else {
        Settings { calibrate: Duration::from_millis(20), sample: Duration::from_millis(100), samples: 5 }
    };

    let mods = Modules {
        guest: {
            // GUEST_WASM overrides the module, e.g. to compare differently built guests.
            let path = std::env::var("GUEST_WASM").unwrap_or_else(|_| GUEST_WASM.to_string());
            eprintln!("guest: {path}");
            std::fs::read(&path).with_context(|| format!("reading {path} (build it first: see run.sh)"))?
        },
        keccak: wat::parse_str(KECCAK_WAT)?,
        ecdsa: wat::parse_str(ECDSA_WAT)?,
    };

    // Proposals the optimised guest builds may use (no effect on modules that don't).
    if let Some(i) = args.iter().position(|a| a == "--codesize") {
        let dir = args.get(i + 1).context("--codesize <dir with case-<id>.wasm>")?;
        return codesize_report(&mods, std::path::Path::new(dir));
    }
    if args.iter().any(|a| a == "--cold") {
        return cold_report(&mods, filter.as_deref().unwrap_or("consensus"));
    }
    if args.iter().any(|a| a == "--fuel") {
        return fuel_report(&mods, filter.as_deref());
    }

    let mut cranelift = wasmtime::Config::new();
    cranelift.strategy(wasmtime::Strategy::Cranelift).wasm_wide_arithmetic(true).wasm_simd(true);
    // (wasmtime's Pulley interpreter was measured too; it was 2–3× slower than
    // wasmi on every case, so it is no longer run.)
    let mut engines = vec![Engine::wasmtime("wasmtime (Cranelift)", &cranelift, &mods)?, Engine::wasmi(&mods)?];

    let cases: Vec<Case> = fixtures::cases()?
        .into_iter()
        .filter(|c| filter.as_ref().is_none_or(|f| c.label().contains(f.as_str())))
        .collect();
    fixtures::check_expected(&cases)?;

    let mut header = String::from("| Function | Input | native |");
    let mut rule = String::from("|---|---|--:|");
    for e in &engines {
        header += &format!(" {} |", e.name);
        rule += "--:|";
    }
    let mut out = vec![header, rule];
    println!("{}\n{}", out[0], out[1]);

    let mut native_times: HashMap<String, f64> = HashMap::new();
    let mut group = "";
    for case in &cases {
        if case.group != group {
            group = case.group;
            let line = format!("| **{group}** | | | {}", "| ".repeat(engines.len()));
            println!("{line}");
            out.push(line);
        }

        // Native result, and the reference checksum every engine must reproduce.
        let mut native = Native { input: vec![] };
        let (native_ns, reference) = match case.code {
            Code::Kernel(id) => {
                let input = native.load(&case.input)?;
                (Some(measure(&mut native, id, input, &settings)?), native.run(id, input, 3)?)
            }
            // compare the WAT modules with their first engine's checksum instead
            Code::KeccakWat | Code::EcdsaWat => (None, 0),
        };
        if let Some(ns) = native_ns {
            native_times.insert(case.label(), ns);
        }
        // WAT rows are compared with the native time of the equivalent kernel case.
        let baseline = native_ns.or_else(|| case.baseline.as_ref().and_then(|b| native_times.get(b).copied()));

        let mut row = format!(
            "| `{}` | {} | {} |",
            case.function,
            case.input_desc,
            native_ns.map_or("—".into(), fmt_ns)
        );
        let mut wat_reference = None;
        for e in engines.iter_mut() {
            let id = match case.code {
                Code::Kernel(id) => id,
                _ => 0,
            };
            let runner = e.runner(case.code);
            let input = runner.load(&case.input)?;
            let check = runner.run(id, input, 3)?;
            let expected = match case.code {
                Code::Kernel(_) => reference,
                Code::EcdsaWat => 3, // three successful verifications
                Code::KeccakWat => *wat_reference.get_or_insert(check),
            };
            if check != expected {
                bail!("{}: {} checksum {check:#x} != expected {expected:#x}", case.label(), e.name);
            }
            let ns = measure(runner, id, input, &settings)?;
            let ratio = baseline.map_or(String::new(), |b| format!(" ({:.1}×)", ns / b));
            row += &format!(" {}{} |", fmt_ns(ns), ratio);
        }
        println!("{row}");
        out.push(row);
    }

    // Only a complete, default run replaces the recorded results.
    if filter.is_none() && !quick && std::env::var_os("GUEST_WASM").is_none() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../results.md");
        std::fs::write(path, out.join("\n") + "\n")?;
        eprintln!("\nwrote {path}");
    }
    Ok(())
}

/// `--fuel`: wasmi fuel (default costs: 1 per Wasm instruction, structural ones
/// free, bulk memory ops per byte) consumed by one call of each case. Prints and
/// writes `fuel.tsv` (label, fuel).
fn fuel_report(mods: &Modules, filter: Option<&str>) -> Result<()> {
    let mut config = wasmi::Config::default();
    config.wasm_wide_arithmetic(true).wasm_simd(true).consume_fuel(true);
    let engine = wasmi::Engine::new(&config);
    let mut guest = WasmiRunner::new(&engine, &mods.guest)?;
    let mut keccak = WasmiRunner::new(&engine, &mods.keccak)?;
    let mut ecdsa = WasmiRunner::new(&engine, &mods.ecdsa)?;
    // Stores start empty; top them up so loading inputs and warm-ups can run.
    for r in [&mut guest, &mut keccak, &mut ecdsa] {
        r.store.set_fuel(u64::MAX / 2).map_err(|e| anyhow!("{e}"))?;
    }
    let mut tsv = String::new();
    for case in fixtures::cases()?
        .into_iter()
        .filter(|c| filter.is_none_or(|f| c.label().contains(f)))
    {
        let (runner, id) = match case.code {
            Code::Kernel(id) => (&mut guest, id),
            Code::KeccakWat => (&mut keccak, 0),
            Code::EcdsaWat => (&mut ecdsa, 0),
        };
        let input = runner.load(&case.input)?;
        let fuel = runner.fuel_per_iter(id, input)?;
        let line = format!("{}\t{fuel}", case.label());
        println!("{line}");
        tsv += &line;
        tsv.push('\n');
    }
    if filter.is_none() {
        let name = if std::env::var_os("GUEST_WASM").is_some() { "fuel-custom-guest.tsv" } else { "fuel.tsv" };
        let path = format!("{}/../{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::write(&path, tsv)?;
        eprintln!("wrote {path}");
    }
    Ok(())
}

/// Wasm instructions and bytes of all function bodies in a module.
/// `skip_exports` leaves out the named exported functions (the WAT `bench` loops).
fn code_stats(wasm: &[u8], skip_exports: &[&str]) -> Result<(u64, u64)> {
    use wasmparser::{ExternalKind, Parser, Payload};
    let mut imported_funcs = 0u32;
    let mut skip = std::collections::HashSet::new();
    let mut body_index = 0u32;
    let (mut instrs, mut bytes) = (0u64, 0u64);
    for payload in Parser::new(0).parse_all(wasm) {
        match payload? {
            Payload::ImportSection(r) => {
                for imp in r.into_imports() {
                    if matches!(imp?.ty, wasmparser::TypeRef::Func(_)) {
                        imported_funcs += 1;
                    }
                }
            }
            Payload::ExportSection(r) => {
                for e in r {
                    let e = e?;
                    if e.kind == ExternalKind::Func && skip_exports.contains(&e.name) {
                        skip.insert(e.index);
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let index = imported_funcs + body_index;
                body_index += 1;
                if skip.contains(&index) {
                    continue;
                }
                let range = body.range();
                bytes += (range.end - range.start) as u64;
                let mut ops = body.get_operators_reader()?;
                while !ops.eof() {
                    ops.read()?;
                    instrs += 1;
                }
            }
            _ => {}
        }
    }
    Ok((instrs, bytes))
}

/// `--codesize <dir>`: per case, the wasm instructions and code bytes of a guest
/// built for that case only (`case-<id>.wasm`, see codesize.sh) minus the EMPTY
/// guest (minus the CONSENSUS_SETUP guest for TO_CONSENSUS_BUFF, whose setup
/// deserializes its input); WAT cases count their whole module minus the `bench` loop.
/// Prints and writes `codesize.tsv` (label, instructions, bytes).
fn codesize_report(mods: &Modules, dir: &std::path::Path) -> Result<()> {
    let read = |id: u32| -> Result<Vec<u8>> {
        let path = dir.join(format!("case-{id}.wasm"));
        std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
    };
    let (base_instrs, base_bytes) = code_stats(&read(kernels::cases::EMPTY)?, &[])?;
    eprintln!("EMPTY guest baseline: {base_instrs} instructions, {base_bytes} bytes");
    let mut tsv = format!("baseline\t{base_instrs}\t{base_bytes}\n");
    for case in fixtures::cases()? {
        let (instrs, bytes) = match case.code {
            Code::Kernel(id) => {
                // Cases whose setup needs code the built-in doesn't are measured
                // against a guest containing just that setup.
                let (bi, bb) = match id {
                    kernels::cases::TO_CONSENSUS_BUFF => code_stats(&read(kernels::cases::CONSENSUS_SETUP)?, &[])?,
                    _ => (base_instrs, base_bytes),
                };
                let (i, b) = code_stats(&read(id)?, &[])?;
                (i - bi, b - bb)
            }
            Code::KeccakWat => code_stats(&mods.keccak, &["bench"])?,
            Code::EcdsaWat => code_stats(&mods.ecdsa, &["bench"])?,
        };
        let line = format!("{}\t{instrs}\t{bytes}", case.label());
        println!("{line}");
        tsv += &line;
        tsv.push('\n');
    }
    let path = format!("{}/../codesize.tsv", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(&path, tsv)?;
    eprintln!("wrote {path}");
    Ok(())
}

/// `--cold [filter]`: first-call time in a fresh instance (module already compiled),
/// i.e. an instance-per-transaction VM. One-time work inside the guest — e.g. the
/// `regex` crate compiling its patterns on first use — is paid on every instance.
/// Median of 31 fresh instances, next to the warm per-call time.
fn cold_report(mods: &Modules, filter: &str) -> Result<()> {
    const RUNS: usize = 31;
    fn median(mut v: Vec<f64>) -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    }
    let wt_engine = wasmtime::Engine::new(wasmtime::Config::new().wasm_wide_arithmetic(true).wasm_simd(true))?;
    let wt_module = wasmtime::Module::new(&wt_engine, &mods.guest)?;
    let mut wi_config = wasmi::Config::default();
    wi_config.wasm_wide_arithmetic(true).wasm_simd(true);
    let wi_engine = wasmi::Engine::new(&wi_config);
    let wi_module = wasmi::Module::new(&wi_engine, &mods.guest).map_err(|e| anyhow!("{e}"))?;
    // Translate wasmi's lazily compiled functions once, so "cold" is about guest state.
    {
        let mut warm = WasmiRunner::instantiate(&wi_engine, &wi_module)?;
        for case in fixtures::cases()?.iter().filter(|c| c.label().contains(filter)) {
            if let Code::Kernel(id) = case.code {
                let input = warm.load(&case.input)?;
                warm.run(id, input, 1)?;
            }
        }
    }

    let mut out = String::from("| Function | Input | engine | first call (fresh instance) | warm call |\n|---|---|---|--:|--:|\n");
    for case in fixtures::cases()?.into_iter().filter(|c| c.label().contains(filter)) {
        let Code::Kernel(id) = case.code else { continue };
        for engine in ["wasmtime (Cranelift)", "wasmi"] {
            let mut first = vec![];
            let mut warm = vec![];
            for _ in 0..RUNS {
                let mut r: Box<dyn Runner> = match engine {
                    "wasmi" => Box::new(WasmiRunner::instantiate(&wi_engine, &wi_module)?),
                    _ => Box::new(WasmtimeRunner::instantiate(&wt_engine, &wt_module)?),
                };
                let input = r.load(&case.input)?;
                first.push(time(r.as_mut(), id, input, 1)?.as_nanos() as f64);
                warm.push(time(r.as_mut(), id, input, 1)?.as_nanos() as f64);
            }
            let line = format!(
                "| `{}` | {} | {engine} | {} | {} |",
                case.function,
                case.input_desc,
                fmt_ns(median(first)),
                fmt_ns(median(warm))
            );
            println!("{line}");
            out += &line;
            out.push('\n');
        }
    }
    let path = format!("{}/../cold.md", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(&path, out)?;
    eprintln!("wrote {path}");
    Ok(())
}
