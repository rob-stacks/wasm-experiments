import fs from "node:fs";
import crypto from "node:crypto";
import wabtInit from "wabt";

const wabt = await wabtInit();
const mod = wabt.parseWat("keccak256.wat", fs.readFileSync(new URL("keccak256.wat", import.meta.url), "utf8"));
mod.validate();
const { buffer } = mod.toBinary({});
fs.writeFileSync(new URL("keccak256.wasm", import.meta.url), buffer);

const { instance } = await WebAssembly.instantiate(buffer);
const { memory, heap_base, keccak256, sha3_256 } = instance.exports;

function run(fn, data) {
  const base = heap_base.value;
  const need = base + data.length + 64;
  const have = memory.buffer.byteLength;
  if (need > have) memory.grow(Math.ceil((need - have) / 65536));
  const mem = new Uint8Array(memory.buffer);
  mem.set(data, base);
  const out = base + data.length;
  fn(base, data.length, out);
  return Buffer.from(mem.slice(out, out + 32)).toString("hex");
}

let fail = 0;
const check = (name, got, want) => {
  if (got !== want) { fail++; console.log(`FAIL ${name}\n  got  ${got}\n  want ${want}`); }
};

// Known Keccak-256 vectors
const enc = (s) => new TextEncoder().encode(s);
check("keccak('')", run(keccak256, enc("")),
  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
check("keccak('abc')", run(keccak256, enc("abc")),
  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
check("keccak(fox)", run(keccak256, enc("The quick brown fox jumps over the lazy dog")),
  "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15");

// Same sponge with SHA3 padding vs. Node's OpenSSL, across block boundaries
let n = 0;
for (const len of [...Array(600).keys(), 1000, 4096, 100_000]) {
  const data = crypto.randomBytes(len);
  check(`sha3_256 len=${len}`, run(sha3_256, data),
    crypto.createHash("sha3-256").update(data).digest("hex"));
  n++;
}

console.log(fail ? `${fail} failures` : `all ${n + 3} checks passed (${buffer.length} byte wasm)`);
process.exit(fail ? 1 : 0);
