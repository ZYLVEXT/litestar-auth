#!/usr/bin/env node
/** Independently verify AuthWeave RFC 9421/RFC 9530 vectors with node:crypto. */

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

const data = JSON.parse(await readFile(new URL("./manifest.json", import.meta.url), "utf8"));
const rawPublicKey = Buffer.from(data.public_key_raw_b64, "base64");
const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
const publicKey = createPublicKey({ key: Buffer.concat([spkiPrefix, rawPublicKey]), format: "der", type: "spki" });
const baseComponents = ["@method", "@target-uri", "content-digest", "content-type", "idempotency-key"];

function headersFor(testCase) {
  const entries = testCase.headers_list ?? Object.entries(testCase.headers);
  const result = new Map();
  for (const [rawName, value] of entries) {
    const name = rawName.toLowerCase();
    if (result.has(name)) throw new Error("duplicate field");
    result.set(name, value);
  }
  return result;
}

function parseInput(value) {
  if (value.includes(",")) throw new Error("multiple signatures");
  const match = /^payment=\(([^)]*)\)((?:;[a-z]+=(?:"[^"]*"|-?\d+))+)$/.exec(value);
  if (!match) throw new Error("invalid Signature-Input");
  const components = [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]);
  if (components.map((item) => `"${item}"`).join(" ") !== match[1]) throw new Error("invalid component list");
  const parameters = new Map();
  for (const item of match[2].matchAll(/;([a-z]+)=(?:"([^"]*)"|(-?\d+))/g)) {
    if (parameters.has(item[1])) throw new Error("duplicate parameter");
    parameters.set(item[1], item[2] ?? Number(item[3]));
  }
  return { components, parameters, paramsText: `(${match[1]})${match[2]}` };
}

function signatureBase(testCase, headers, input) {
  const lines = input.components.map((component) => {
    let value;
    if (component === "@method") value = testCase.method.toUpperCase();
    else if (component === "@target-uri") value = testCase.target_uri;
    else value = headers.get(component);
    if (typeof value !== "string") throw new Error("missing covered component");
    return `"${component}": ${value}`;
  });
  lines.push(`"@signature-params": ${input.paramsText}`);
  return lines.join("\n");
}

function accepts(testCase) {
  try {
    const headers = headersFor(testCase);
    if (new URL(testCase.target_uri).search) throw new Error("query forbidden");
    if (headers.get("content-encoding") && headers.get("content-encoding").toLowerCase() !== "identity") {
      throw new Error("content encoding forbidden");
    }
    const body = Buffer.from(testCase.body_b64, "base64");
    const expectedDigest = `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
    if (headers.get("content-digest") !== expectedDigest) throw new Error("digest mismatch");
    const input = parseInput(headers.get("signature-input") ?? "");
    const expectedComponents = testCase.require_authorization_component
      ? [...baseComponents, "authorization"]
      : baseComponents;
    if (JSON.stringify(input.components) !== JSON.stringify(expectedComponents)) throw new Error("profile mismatch");
    if (
      input.parameters.get("keyid") !== data.key_id ||
      input.parameters.get("alg") !== "ed25519" ||
      input.parameters.get("tag") !== data.profile ||
      typeof input.parameters.get("nonce") !== "string"
    ) throw new Error("parameter mismatch");
    const signatureMatch = /^payment=:([A-Za-z0-9+/]+={0,2}):$/.exec(headers.get("signature") ?? "");
    if (!signatureMatch) throw new Error("invalid Signature field");
    if (!verify(null, Buffer.from(signatureBase(testCase, headers, input)), publicKey, Buffer.from(signatureMatch[1], "base64"))) {
      throw new Error("signature mismatch");
    }
    if (testCase.override_principal_subject && testCase.override_principal_subject !== data.binding.principal_subject) {
      throw new Error("identity binding mismatch");
    }
    return true;
  } catch {
    return false;
  }
}

let failures = 0;
for (const testCase of data.cases) {
  const actual = accepts(testCase);
  const expected = testCase.expect === "pass";
  if (actual !== expected) {
    console.error(`FAIL ${testCase.id}: expected ${expected ? "pass" : "fail"}`);
    failures += 1;
  } else {
    console.log(`ok  ${testCase.id}`);
  }
}
process.exitCode = failures === 0 ? 0 : 1;
