// End to end against a running registrar and its Mailpit (deploy/compose):
// prove an email by the code Mailpit caught, claim a name, pair an agent key,
// resolve the signed card, and look it up over WebFinger.
//
//   node tools/smoke.mjs [registrar URL] [Mailpit URL]
//
// Defaults: http://localhost:8080 and http://localhost:8025. Exit code 1 on
// the first step that fails, with what the registrar said.
import nkeys from "nkeys.js";

const R = (process.argv[2] ?? "http://localhost:8080").replace(/\/$/, "");
const M = (process.argv[3] ?? "http://localhost:8025").replace(/\/$/, "");
const email = `smoke-${Date.now()}@example.com`;
const name = `smoke${Date.now().toString(36)}`;

async function call(method, path, body, token) {
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const r = await fetch(R + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => null);
  if (!r.ok || j?.ok === false) throw new Error(`${method} ${path}: HTTP ${r.status} ${JSON.stringify(j)}`);
  return j;
}

async function codeFromMailpit() {
  for (let i = 0; i < 30; i++) {
    const list = await fetch(`${M}/api/v1/search?query=${encodeURIComponent(`to:${email}`)}`).then((r) => r.json());
    const msg = list?.messages?.[0];
    if (msg) {
      const subject = msg.Subject ?? "";
      const code = subject.match(/^(\d{6}) /)?.[1];
      if (code) return code;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`no verification mail for ${email} reached Mailpit at ${M}`);
}

// RFC 8785 canonical JSON, enough for a card: sorted keys, compact.
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

const step = (s) => console.log(`ok  ${s}`);
try {
  const start = await call("POST", "/api/handles/start", { email });
  if (start.delivery !== "email") throw new Error(`the code went by "${start.delivery}", not by mail`);
  step("verification code sent by mail");
  const code = await codeFromMailpit();
  step("code read from the mail");
  const { token } = await call("POST", "/api/handles/verify", { email, code });
  step("email proved");
  const { handle } = await call("POST", "/api/handles/claim", { name, operator_name: "Smoke Test" }, token);
  step(`claimed ${handle}`);
  const pair = await call("POST", "/api/pair/start", { handle }, token);
  const kp = nkeys.createUser();
  const agentId = kp.getPublicKey();
  const sig = Buffer.from(kp.sign(new TextEncoder().encode(`pan-pair-v1:${pair.code}:${agentId}`))).toString("base64");
  await call("POST", "/api/pair/complete", { code: pair.code, agent_id: agentId, signature: sig });
  step("agent key paired");
  const resolved = await call("GET", `/api/resolve?handle=${encodeURIComponent(handle)}`);
  const card = resolved.card;
  if (!card || !JSON.stringify(card).includes(agentId)) throw new Error(`the card does not carry the paired key: ${JSON.stringify(resolved)}`);
  const signer = nkeys.fromPublic(resolved.registrar_key);
  const signed = new TextEncoder().encode(canonical(card));
  if (!signer.verify(signed, Buffer.from(resolved.registrar_sig ?? "", "base64"))) {
    throw new Error(`the card's signature does not verify against ${resolved.registrar_key}`);
  }
  const published = await fetch(`${R}/api/registrar-key`).then((r) => r.json());
  if (!JSON.stringify(published).includes(resolved.registrar_key)) {
    throw new Error("the key that signed the card is not the one the registrar publishes");
  }
  step("signed card resolves to the paired key, signed by the published key");
  const wf = await fetch(`${R}/.well-known/webfinger?resource=${encodeURIComponent(`acct:${handle}`)}`);
  if (!wf.ok) throw new Error(`WebFinger answered HTTP ${wf.status}`);
  step("WebFinger answers");
  const page = await fetch(`${R}/app`).then((r) => r.text());
  if (!page.includes("Get a name for your agent")) throw new Error("the claim page at /app is missing");
  step("claim page served at /app");
  console.log("smoke test passed");
} catch (e) {
  console.error(`FAIL ${e.message}`);
  process.exit(1);
}
