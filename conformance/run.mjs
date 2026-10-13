// Runs the registrar conformance tests against two registrars that name each
// other as peers (deploy/compose/two-registrars.yml starts a pair):
//
//   REGISTRAR_A=http://localhost:18081 REGISTRAR_B=http://localhost:18082 \
//   REGISTRAR_TEST_PEER=http://127.0.0.1:18089 node run.mjs [--only t07]
//
// REGISTRAR_A and REGISTRAR_B must be spelled exactly as each registrar's
// PAN_PEERS spells the other: the peer list is an exact match. A test whose
// registrars are not set reports env-skip, never a pass. Exit code 1 on any
// failure or error.
import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const only = process.argv.includes("--only") ? process.argv[process.argv.indexOf("--only") + 1] : null;
const env = {
  registrarA: process.env.REGISTRAR_A ?? null,
  registrarB: process.env.REGISTRAR_B ?? null,
  REGISTRAR: process.env.REGISTRAR_A ?? null,
  rehomeNonce: process.env.REHOME_NONCE,
};

const dir = join(here, "peering", "tests");
const files = readdirSync(dir).filter((f) => f.endsWith(".mjs")).sort();
let failed = 0;
const counts = {};
for (const f of files) {
  const t = (await import(pathToFileURL(join(dir, f)).href)).default;
  if (only && t.id !== only) continue;
  let r;
  try {
    r = await t.run(env);
  } catch (e) {
    r = { status: "error", detail: e?.message ?? String(e) };
  }
  counts[r.status] = (counts[r.status] ?? 0) + 1;
  const mark = r.status === "pass" ? "PASS" : r.status === "env-skip" ? "SKIP" : "FAIL";
  if (mark === "FAIL") failed++;
  console.log(`${mark}  ${t.id}  ${t.title}  [${t.spec}]`);
  if (r.detail && mark !== "PASS") console.log(`      ${typeof r.detail === "string" ? r.detail : JSON.stringify(r.detail)}`);
}
console.log(Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(", "));
process.exit(failed ? 1 : 0);
