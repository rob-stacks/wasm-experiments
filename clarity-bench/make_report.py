#!/usr/bin/env python3
"""Build clarity-wasm-bench.pdf (via report.html, needs weasyprint) and clarity-wasm-bench.md.

Inputs (all produced by the bench):
  results.md       ./run.sh            native, wasmtime (Cranelift), wasmi — default guest
  results-wide.md  WIDE=1 ./run.sh > results-wide.md   (only its wasmi column is used)
  fuel.tsv         ./run.sh --fuel     wasmi fuel per call
  codesize.tsv     ./codesize.sh       wasm instructions / code bytes per case
  cold.md          ./run.sh --cold from-consensus   first call in a fresh instance

Green: wasmi + wide-arithmetic is >= 10% faster than plain wasmi.
"""
import html
import os
import re
import subprocess

os.chdir(os.path.dirname(os.path.abspath(__file__)))


def table(path):
    rows = [[c.strip() for c in l.strip().strip('|').split('|')] for l in open(path) if l.startswith('|')]
    return rows[0], rows[2:]


def tsv(path):
    return [l.rstrip('\n').split('\t') for l in open(path) if l.strip()]


def ns(s):
    m = re.match(r'([\d.]+) (ns|µs|ms)', s)
    return float(m.group(1)) * {'ns': 1, 'µs': 1e3, 'ms': 1e6}[m.group(2)] if m else None


hdr, base = table('results.md')
_, wide = table('results-wide.md')
fuel = tsv('fuel.tsv')
codesize = tsv('codesize.tsv')
baseline = next(r for r in codesize if r[0] == 'baseline')
codesize = [r for r in codesize if r[0] != 'baseline']
assert hdr[:5] == ['Function', 'Input', 'native', 'wasmtime (Cranelift)', 'wasmi'], hdr
assert len(base) == len(wide)

COLS = ['Function', 'Input', 'native', 'wasmtime (Cranelift)', 'wasmi', 'wasmi + wide-arithmetic',
        'wasmi fuel / call', 'wasm instructions', 'code bytes']

# Merge into rows: ('group', name) or ('case', cells, green, fuel_per_ns)
rows, green, i = [], 0, 0
for b, w in zip(base, wide):
    assert b[:2] == w[:2], (b[:2], w[:2])
    if b[0].startswith('**'):
        rows.append(('group', b[0].strip('*')))
        continue
    label = f"{b[0].strip('`')} [{b[1]}]"
    assert fuel[i][0] == label and codesize[i][0] == label, (label, fuel[i][0], codesize[i][0])
    is_green = ns(w[4]) <= ns(b[4]) * 0.9
    green += is_green
    cells = b[:5] + [w[4], f"{int(fuel[i][1]):,}", f"{int(codesize[i][1]):,}", f"{int(codesize[i][2]):,}"]
    rows.append(('case', cells, is_green, int(fuel[i][1]) / ns(b[4])))
    i += 1
assert i == len(fuel) == len(codesize)

# --- the regex issue: from-consensus-buff? with the chain's regex vs the hand-written check
def find_case(suffix):
    for r in rows:
        if r[0] == 'case' and r[1][0] == '`from-consensus-buff?`' and r[1][1].endswith(suffix):
            return r[1]
    raise SystemExit(f'from-consensus-buff? row {suffix!r} missing')


rx, nrx = find_case('(194 B)'), find_case('no regex')
cold_rows = [[c.strip() for c in l.strip().strip('|').split('|')] for l in open('cold.md') if l.startswith('| `')]
cold = {(r[1], r[2]): r[3] for r in cold_rows}
cold_rx, cold_nrx = (lambda e: cold[(rx[1], e)]), (lambda e: cold[(nrx[1], e)])


def strip_ratio(x):
    return re.sub(r' \(.*\)$', '', x)


REGEX_COLS = ['', 'regex (as in clarity-types)', 'hand-written check']
REGEX_ROWS = [
    ('wasm instructions', rx[7], nrx[7]),
    ('code bytes', rx[8], nrx[8]),
    ('wasmi fuel / call', rx[6], nrx[6]),
    ('native, per call', rx[2], nrx[2]),
    ('wasmtime (Cranelift), per call', strip_ratio(rx[3]), strip_ratio(nrx[3])),
    ('wasmi, per call', strip_ratio(rx[4]), strip_ratio(nrx[4])),
    ('wasmtime (Cranelift), first call in a fresh instance', cold_rx('wasmtime (Cranelift)'), cold_nrx('wasmtime (Cranelift)')),
    ('wasmi, first call in a fresh instance', cold_rx('wasmi'), cold_nrx('wasmi')),
]
REGEX_INTRO = (
    'Deserialization validates every tuple key as a ClarityName and every contract principal\'s name as a '
    'ContractName. clarity-types (`representations.rs`) does it with the `regex` crate: '
    '`^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$` for names, and '
    '`^([a-zA-Z](([a-zA-Z0-9]|[-_])){0,127})$|^__transient$` for contract names. These two patterns only need a '
    'byte loop, but in a wasm build the `regex` crate costs:')
REGEX_POINTS = [
    ('Code size', 'the regex engine (regex_automata, regex_syntax, aho_corasick, regex, memchr) is ~560 KB of the '
     '~830 KB from-consensus-buff? needs, plus generic code instantiated for it.'),
    ('Per-instance start-up', 'the patterns are compiled lazily on first use, inside the guest. Every fresh '
     'instance — e.g. one per transaction — pays that on its first name check: ~0.1 ms on Cranelift, ~1 ms on '
     'wasmi. The first call on a fresh instance takes 27× (Cranelift) / 15× (wasmi) as long as the second one; '
     'without regex the two are within ~20%. (Both calls include the benchmark\'s one-time setup, a deserialize '
     'and type_of, for both variants; the module is compiled before the instance is created.)'),
    ('Per call', 'matching itself is cheap: the hand-written check is ~5–15% faster per call.'),
]
REGEX_FIX = (
    'The hand-written check (`ManualNames` in `kernels/src/consensus.rs`, ~30 lines) accepts exactly the same '
    'strings: `kernels/tests/names_equiv.rs` compares it with clarity-types\' `ClarityName`/`ContractName` on ~1M '
    'strings (exhaustive up to length 4, every character in every position, length boundaries, random). The same '
    'replacement would apply to the node: `guarded_string!` in clarity-types.')

per_ns = sorted((r[3], r[1][0].strip('`') + ' ' + r[1][1]) for r in rows if r[0] == 'case')
lo, hi = per_ns[0], per_ns[-1]

TITLE = 'Clarity built-ins: native vs WebAssembly'
SUB = ('Conversions and Hashing & Crypto functions extracted from stacks-core (branch `marf/g3-db-snapshot`), '
       'run natively and as a pure (import-free) wasm module. Apple M4 Pro · Rust 1.98 · wasmtime 49.0.2 · '
       'wasmi 2.0.0 · time per call, best of 5 × 100 ms samples · (×) = slowdown vs native.')
LEGEND_GREEN = f'wasmi + wide-arithmetic is ≥ 10% faster than plain wasmi ({green} cells)'
NOTES = [
    ('wasmi fuel / call',
     'fuel consumed by one call under wasmi\'s default metering (1 per Wasm instruction; `block`/`loop`/`end`/'
     '`nop`/`drop`/`return` free; bulk memory ops per byte), default guest. Difference between a 1- and a '
     '3-iteration run, so lazy translation and setup are excluded; includes the benchmark loop\'s few-instruction '
     'checksum fold. Deterministic.'),
    ('Fuel is not proportional to time',
     f'wasmi burns from {lo[0]:.1f} fuel/ns ({lo[1]}) to {hi[0]:.1f} fuel/ns ({hi[1]}). Default fuel charges every '
     'Wasm instruction 1, including `local.get`/`local.set`/`i32.const` that wasmi\'s register IR mostly folds '
     'away, while multiply-heavy crypto spends real time per instruction — a gas schedule on default fuel would '
     'over-charge allocation/copy-heavy functions relative to crypto.'),
    ('wasm instructions / code bytes',
     'static size of the code each built-in needs: a guest is built with only that case (constant case id, so '
     f'LTO drops the others) and the empty guest ({int(baseline[1]):,} instructions, {int(baseline[2]):,} bytes: '
     'allocator, panic handling) is subtracted. Counted with wasmparser over all function bodies; bytes are body '
     'sizes. Hash code size does not depend on input size. to-consensus-buff? is measured against a guest that '
     'only runs its benchmark setup (deserializing the input), so the deserializer is not charged to it. '
     'Hand-written WAT rows count the whole module except the `bench` loop (keccak256.wat also contains sha3_256, '
     'which shares the sponge).'),
    ('Why from-consensus-buff? is 831 KB',
     'the `regex` crate, used for Clarity name validation — see "The regex issue" below; the "no regex" row is the '
     'same function with an equivalent hand-written check. Serializing (to-consensus-buff?) never validates names, '
     'hence its small size.'),
    ('wide-arithmetic',
     'guest built with `-C target-feature=+wide-arithmetic` (64×64→128 multiply) and `curve25519_dalek_bits="64"`; '
     'it helps code doing 64-bit-limb or u128 math (secp256r1, ed25519, u128 parsing/printing). Pure-Rust '
     'libsecp256k1 uses 32-bit limbs, so secp256k1 is unaffected. Differences under ~5% are run-to-run noise.'),
    ('secp256k1 "chain backend"',
     'what stacks-core uses on each target — the C library natively, pure-Rust libsecp256k1 in wasm. '
     '"libsecp256k1 everywhere" runs the Rust library on all targets; in wasm both rows are the same code '
     '(identical fuel and size).'),
    ('Other',
     'native SHA-2 uses the ARMv8 SHA instructions (as in stacks-common), which inflates the sha256/hash160 '
     'ratios. wasmtime\'s Pulley interpreter was 2–3× slower than wasmi on every case and is no longer measured. '
     'Times are measured without fuel metering. The benchmark loop runs inside the module; every engine\'s result '
     'checksum is checked against native before timing. Hand-written WAT rows are compared with the native time '
     'of the same function.'),
]

# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def md_inline(s):
    s = html.escape(s)
    s = re.sub(r'`([^`]+)`', r'<code>\1</code>', s)
    return re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', s)


def time_cell(s):
    m = re.match(r'(.+?) \((.+)\)$', s)
    return f'{html.escape(m.group(1))}<span class="r">{html.escape(m.group(2))}</span>' if m else html.escape(s)


trs = []
for r in rows:
    if r[0] == 'group':
        trs.append(f'<tr class="group"><td colspan="{len(COLS)}">{html.escape(r[1])}</td></tr>')
        continue
    _, c, is_green, _ = r
    tds = [f'<td class="fn">{md_inline(c[0])}</td>', f'<td class="in">{html.escape(c[1])}</td>']
    tds += [f'<td class="num">{time_cell(x)}</td>' for x in c[2:5]]
    tds.append(f'<td class="num{" green" if is_green else ""}">{time_cell(c[5])}</td>')
    tds += [f'<td class="num size">{x}</td>' for x in c[6:]]
    trs.append('<tr>' + ''.join(tds) + '</tr>')

ths = ''.join(f'<th>{html.escape(h)}</th>' for h in COLS)
notes_html = ''.join(f'<li><b>{html.escape(k)}</b>: {md_inline(v)}</li>' for k, v in NOTES)
doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>{TITLE}</title>
<style>
@page {{ size: A4 landscape; margin: 11mm 10mm 13mm 10mm;
  @bottom-center {{ content: counter(page) " / " counter(pages); font: 8pt sans-serif; color: #888; }} }}
body {{ font-family: -apple-system, "Helvetica Neue", Arial, sans-serif; color: #1b1b24; font-size: 8pt; }}
h1 {{ font-size: 15pt; margin: 0 0 2mm; color: #3b2fd9; }}
.sub {{ color: #555; margin: 0 0 3mm; }}
table {{ border-collapse: collapse; width: 100%; }}
thead {{ display: table-header-group; }}
th {{ background: #3b2fd9; color: #fff; font-weight: 600; padding: 4px 5px; text-align: right; }}
th:nth-child(1), th:nth-child(2) {{ text-align: left; }}
th:nth-child(n+7) {{ background: #5b51e0; }}
td {{ padding: 2.4px 5px; border-bottom: 1px solid #e3e3ea; }}
tr:nth-child(even) td {{ background: #fafafe; }}
td.num {{ text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }}
td.size {{ color: #333; }}
.r {{ color: #777; font-size: 7pt; margin-left: 3px; }}
td.green {{ background: #c9f2dc !important; color: #0b5c33; font-weight: 600; }}
td.green .r {{ color: inherit; font-weight: 400; }}
tr.group td {{ background: #ececf6 !important; font-weight: 700; padding-top: 5px; }}
code {{ font-family: Menlo, monospace; font-size: 7.6pt; }}
td.in {{ color: #444; }}
.legend {{ margin: 3mm 0; }}
.chip {{ display: inline-block; padding: 1px 6px; border-radius: 3px; margin-right: 4px; font-weight: 600;
  background: #c9f2dc; color: #0b5c33; }}
.notes {{ margin-top: 4mm; color: #444; font-size: 7.6pt; padding-left: 4mm; }}
.notes li {{ margin: 1.5px 0; }}
h2 {{ font-size: 13pt; color: #3b2fd9; margin: 0 0 2mm; page-break-before: always; }}
table.small {{ width: auto; min-width: 55%; }}
table.small th:first-child, table.small td:first-child {{ text-align: left; }}
</style></head><body>
<h1>{TITLE}</h1>
<p class="sub">{md_inline(SUB)}</p>
<p class="legend"><span class="chip">green</span> {html.escape(LEGEND_GREEN)}</p>
<table><thead><tr>{ths}</tr></thead><tbody>{"".join(trs)}</tbody></table>
<ul class="notes">{notes_html}</ul>
<h2>The regex issue: from-consensus-buff?</h2>
<p class="sub">{md_inline(REGEX_INTRO)}</p>
<ul class="notes">{"".join(f'<li><b>{html.escape(k)}</b>: {md_inline(v)}</li>' for k, v in REGEX_POINTS)}</ul>
<table class="small"><thead><tr>{"".join(f'<th>{html.escape(c)}</th>' for c in REGEX_COLS)}</tr></thead><tbody>
{"".join(f'<tr><td>{html.escape(a)}</td><td class="num">{html.escape(b)}</td><td class="num green">{html.escape(c)}</td></tr>' for a, b, c in REGEX_ROWS)}
</tbody></table>
<p class="sub" style="margin-top:3mm">{md_inline(REGEX_FIX)}</p></body></html>"""
open('report.html', 'w').write(doc)
subprocess.run(['weasyprint', 'report.html', 'clarity-wasm-bench.pdf'], check=True)
print(f'green {green} -> clarity-wasm-bench.pdf')

# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
md = [f'# {TITLE}', '', SUB, '', f'- 🟢 {LEGEND_GREEN}', '',
      '| ' + ' | '.join(COLS) + ' |', '|---|---|' + '--:|' * (len(COLS) - 2)]
for r in rows:
    if r[0] == 'group':
        md.append(f'| **{r[1]}** |' + ' |' * (len(COLS) - 1))
        continue
    _, c, is_green, _ = r
    c = list(c)
    if is_green:
        c[5] = f'🟢 **{c[5]}**'
    md.append('| ' + ' | '.join(c) + ' |')
md += ['', '## Notes', ''] + [f'- **{k}**: {v}' for k, v in NOTES]
md += ['', '## The regex issue: from-consensus-buff?', '', REGEX_INTRO, '']
md += [f'- **{k}**: {v}' for k, v in REGEX_POINTS]
md += ['', '| ' + ' | '.join(REGEX_COLS) + ' |', '|---|--:|--:|']
md += [f'| {a} | {b} | {c} |' for a, b, c in REGEX_ROWS]
md += ['', REGEX_FIX, '']
open('clarity-wasm-bench.md', 'w').write('\n'.join(md))
print('-> clarity-wasm-bench.md')
