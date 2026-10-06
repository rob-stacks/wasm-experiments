import fs from "node:fs";
import crypto from "node:crypto";
import wabtInit from "wabt";

const wabt = await wabtInit();
const mod = wabt.parseWat("ecdsa.wat", fs.readFileSync(new URL("ecdsa.wat", import.meta.url), "utf8"));
mod.validate();
const { buffer } = mod.toBinary({});
fs.writeFileSync(new URL("ecdsa.wasm", import.meta.url), buffer);
const { instance } = await WebAssembly.instantiate(buffer);
const { memory, heap_base, ecdsa_verify } = instance.exports;

function verify(hash, sig, pub) {
  const mem = new Uint8Array(memory.buffer);
  const h = heap_base.value, s = h + 32, p = s + 64;
  mem.set(hash, h); mem.set(sig, s); mem.set(pub, p);
  return ecdsa_verify(h, s, p, pub.length);
}

// --- BigInt helpers / reference signer ---
const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G = [0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
           0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n];
const md = (a, m) => ((a % m) + m) % m;
const inv = (a, m) => { let [r0, r1, s0, s1] = [md(a, m), m, 1n, 0n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return md(s0, m); };
const add = (A, B) => { if (!A) return B; if (!B) return A;
  if (A[0] === B[0] && md(A[1] + B[1], P) === 0n) return null;
  const l = A[0] === B[0] ? md(3n * A[0] * A[0] * inv(2n * A[1], P), P) : md((B[1] - A[1]) * inv(B[0] - A[0], P), P);
  const x = md(l * l - A[0] - B[0], P); return [x, md(l * (A[0] - x) - A[1], P)]; };
const mul = (k, A) => { let R = null; for (; k; k >>= 1n, A = add(A, A)) if (k & 1n) R = add(R, A); return R; };
const be = (v, len = 32) => Buffer.from(v.toString(16).padStart(len * 2, "0"), "hex");
const big = (b) => BigInt("0x" + Buffer.from(b).toString("hex"));
const lowS = (s) => (s > N / 2n ? N - s : s);
function refSign(d, hash) {
  const z = md(big(hash), N);
  for (;;) {
    const k = md(big(crypto.randomBytes(32)), N); if (!k) continue;
    const r = md(mul(k, G)[0], N); if (!r) continue;
    const s = md(inv(k, N) * (z + r * d), N); if (!s) continue;
    return Buffer.concat([be(r), be(lowS(s))]);
  }
}
function keys() {
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  const jwk = privateKey.export({ format: "jwk" });
  const x = Buffer.from(jwk.x, "base64url"), y = Buffer.from(jwk.y, "base64url");
  return { privateKey, d: big(Buffer.from(jwk.d, "base64url")),
    unc: Buffer.concat([Buffer.from([4]), x, y]),
    cmp: Buffer.concat([Buffer.from([2 | (y[31] & 1)]), x]) };
}
function opensslSign(k, msg) {
  const sig = crypto.sign("sha256", msg, { key: k.privateKey, dsaEncoding: "ieee-p1363" });
  return Buffer.concat([sig.subarray(0, 32), be(lowS(big(sig.subarray(32))))]);
}

let fail = 0, count = 0;
const expect = (name, got, want) => { count++; if (got !== want) { fail++; console.log(`FAIL ${name}: got ${got}, want ${want}`); } };
const flip = (b, i, bit = 1) => { const c = Buffer.from(b); c[i] ^= bit; return c; };

// Random keys/messages signed by OpenSSL, plus tampering
for (let t = 0; t < 40; t++) {
  const k = keys(), other = keys();
  const msg = crypto.randomBytes(1 + t * 7);
  const hash = crypto.createHash("sha256").update(msg).digest();
  const sig = opensslSign(k, msg);
  expect(`valid uncompressed #${t}`, verify(hash, sig, k.unc), 1);
  expect(`valid compressed #${t}`, verify(hash, sig, k.cmp), 1);
  expect(`hash bit flip #${t}`, verify(flip(hash, t % 32), sig, k.cmp), 0);
  expect(`r bit flip #${t}`, verify(hash, flip(sig, t % 32), k.cmp), 0);
  expect(`s bit flip #${t}`, verify(hash, flip(sig, 32 + (t % 32), 2), k.cmp), 0);
  expect(`wrong key #${t}`, verify(hash, sig, other.cmp), 0);
  expect(`wrong y parity #${t}`, verify(hash, sig, flip(k.cmp, 0)), 0);
  expect(`bad y #${t}`, verify(hash, sig, flip(k.unc, 64)), 0);

  // high-S: valid plain ECDSA (OpenSSL accepts it), rejected like stacks-common
  const highS = Buffer.concat([sig.subarray(0, 32), be(N - big(sig.subarray(32)))]);
  const pubKey = crypto.createPublicKey({ key: { kty: "EC", crv: "secp256k1",
    x: k.unc.subarray(1, 33).toString("base64url"), y: k.unc.subarray(33).toString("base64url") }, format: "jwk" });
  expect(`openssl accepts high-S #${t}`, crypto.verify("sha256", msg, { key: pubKey, dsaEncoding: "ieee-p1363" }, highS), true);
  expect(`high-S rejected #${t}`, verify(hash, highS, k.cmp), 0);
}

// Hash >= n (exercises the z mod n reduction), via the reference signer
for (let t = 0; t < 5; t++) {
  const k = keys();
  const hash = be(N + big(crypto.randomBytes(16)));
  expect(`hash >= n #${t}`, verify(hash, refSign(k.d, hash), k.unc), 1);
}

// Malformed inputs
{
  const k = keys();
  const hash = crypto.randomBytes(32);
  const sig = refSign(k.d, hash);
  expect("reference sig valid", verify(hash, sig, k.cmp), 1);
  const r = sig.subarray(0, 32), s = sig.subarray(32);
  expect("r = 0", verify(hash, Buffer.concat([be(0n), s]), k.cmp), 0);
  expect("s = 0", verify(hash, Buffer.concat([r, be(0n)]), k.cmp), 0);
  expect("r = n", verify(hash, Buffer.concat([be(N), s]), k.cmp), 0);
  expect("r = 2^256 - 1", verify(hash, Buffer.concat([be(2n ** 256n - 1n), s]), k.cmp), 0);
  expect("s = n/2 + 1", verify(hash, Buffer.concat([r, be(N / 2n + 1n)]), k.cmp), 0);
  expect("prefix 05", verify(hash, sig, Buffer.concat([Buffer.from([5]), k.cmp.subarray(1)])), 0);
  expect("33 bytes with 04", verify(hash, sig, Buffer.concat([Buffer.from([4]), k.cmp.subarray(1)])), 0);
  expect("65 bytes with 02", verify(hash, sig, Buffer.concat([Buffer.from([2]), k.unc.subarray(1)])), 0);
  expect("x >= p", verify(hash, sig, Buffer.concat([Buffer.from([2]), be(P + 1n)])), 0);
  const pow = (b, e, m) => { let r = 1n; for (b %= m; e; e >>= 1n, b = b * b % m) if (e & 1n) r = r * b % m; return r; };
  let x = 1n; while (pow(x ** 3n + 7n, (P - 1n) / 2n, P) === 1n) x++;   // first x with no y
  expect("x not on curve", verify(hash, sig, Buffer.concat([Buffer.from([2]), be(x)])), 0);
}

// Timing
{
  const k = keys(); const msg = Buffer.from("bench");
  const hash = crypto.createHash("sha256").update(msg).digest(); const sig = opensslSign(k, msg);
  const n = 200, t0 = performance.now();
  for (let i = 0; i < n; i++) verify(hash, sig, k.cmp);
  console.log(`~${((performance.now() - t0) / n).toFixed(2)} ms per verify (compressed key)`);
}

console.log(fail ? `${fail}/${count} failures` : `all ${count} checks passed (${buffer.length} byte wasm)`);
process.exit(fail ? 1 : 0);
