// Test-only adapter; no Cap or WebAssembly code is shipped in the Go runtime.
// Oracle: Cap af624b9f15cb03f1f8194fb4c9f262ac34984923/core/src/hashwx.js.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

const modulePath = process.env.HASHWX_CAP_ORACLE;
if (!modulePath) throw new Error("HASHWX_CAP_ORACLE must name Cap core/src/hashwx.js");
const { hashwxReady, hashwxHash } = await import(pathToFileURL(modulePath).href);
const state = await hashwxReady();
let cases;
if (process.argv.includes("--fixtures")) {
  cases = [];
  for (let i = 0; i < 128; i++) {
    const seed = createHash("sha256").update(`hashwx-go-differential-seed-${i}`).digest();
    if (i === 0) seed.fill(0);
    if (i === 1) seed.fill(255);
    if (i === 2) for (let j = 0; j < 32; j++) seed[j] = j;
    const random = createHash("sha256").update(`hashwx-go-differential-nonce-${i}`).digest();
    const nonces = [0n, 1n, (1n << 32n) - 1n, 1n << 32n, 1n << 63n,
      (1n << 64n) - 1n, random.readBigUInt64LE(0), random.readBigUInt64LE(8)];
    for (const nonce of nonces) cases.push({ seed: seed.toString("hex"), nonce: nonce.toString() });
  }
} else {
  cases = JSON.parse(readFileSync(0, "utf8"));
}
for (const c of cases) {
  c.hash = hashwxHash(state, Buffer.from(c.seed, "hex"), BigInt(c.nonce)).toString(16).padStart(16, "0");
}
console.log(JSON.stringify(cases, null, 2));
