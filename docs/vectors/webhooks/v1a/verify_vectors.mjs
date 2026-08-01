#!/usr/bin/env node
// Dependency-free, non-Python verifier for the Standard Webhooks v1a vectors.

import { createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const manifestUrl = new URL("manifest.json", import.meta.url);
const manifest = JSON.parse(readFileSync(fileURLToPath(manifestUrl), "utf8"));
const requiredHeaders = ["webhook-id", "webhook-timestamp", "webhook-signature"];
const publicKeyPrefix = Buffer.from("302a300506032b6570032100", "hex");

function decodeBase64(value, expectedLength = undefined) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0) {
    throw new Error("invalid base64");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value || (expectedLength !== undefined && decoded.length !== expectedLength)) {
    throw new Error("invalid base64");
  }
  return decoded;
}

function collectHeaders(entries) {
  const headers = new Map();
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error("malformed_headers");
    }
    const [rawName, rawValue] = entry;
    const name = String(rawName).toLowerCase();
    if (!requiredHeaders.includes(name)) {
      continue;
    }
    const values = headers.get(name) ?? [];
    values.push(String(rawValue));
    headers.set(name, values);
  }
  for (const name of requiredHeaders) {
    const values = headers.get(name) ?? [];
    if (values.length > 1) {
      throw new Error("duplicate_header");
    }
    if (values.length !== 1) {
      throw new Error("malformed_headers");
    }
  }
  return Object.fromEntries(requiredHeaders.map((name) => [name, headers.get(name)[0]]));
}

function publicKey(rawBase64) {
  const raw = decodeBase64(rawBase64, 32);
  return createPublicKey({ key: Buffer.concat([publicKeyPrefix, raw]), format: "der", type: "spki" });
}

function verifyCase(testCase) {
  let headers;
  try {
    headers = collectHeaders(testCase.headers);
  } catch (error) {
    return String(error.message);
  }
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(headers["webhook-id"]) || headers["webhook-id"].includes(".")) {
    return "malformed_headers";
  }
  if (!/^[0-9]+$/.test(headers["webhook-timestamp"])) {
    return "timestamp_invalid";
  }

  const documentEnvironment = testCase.override_environment ?? manifest.key_document.environment;
  const documentOwner = testCase.override_owner ?? manifest.key_document.owner;
  const documentEndpoint = testCase.override_endpoint ?? manifest.key_document.endpoint;
  if (documentEnvironment !== manifest.key_document.environment) {
    return "environment_mismatch";
  }
  if (documentOwner !== manifest.key_document.owner) {
    return "owner_mismatch";
  }
  if (documentEndpoint !== manifest.key_document.endpoint) {
    return "endpoint_mismatch";
  }

  const timestamp = Number(headers["webhook-timestamp"]);
  if (!Number.isSafeInteger(timestamp) || Math.abs(testCase.now - timestamp) > 300) {
    return "timestamp_out_of_tolerance";
  }

  let body;
  try {
    body = decodeBase64(testCase.body_b64);
  } catch {
    return "malformed_headers";
  }
  const signingInput = Buffer.concat([
    Buffer.from(`${headers["webhook-id"]}.${headers["webhook-timestamp"]}.`, "ascii"),
    body,
  ]);
  if (signingInput.toString("base64") !== testCase.signing_input_b64) {
    return "vector_exact_bytes_mismatch";
  }

  const parts = headers["webhook-signature"].split(/\s+/u);
  if (parts.length < 1 || parts.length > 3) {
    return "signature_invalid";
  }
  const signatures = [];
  try {
    for (const part of parts) {
      const comma = part.indexOf(",");
      if (comma < 0 || part.slice(0, comma) !== "v1a") {
        return "signature_invalid";
      }
      signatures.push(decodeBase64(part.slice(comma + 1), 64));
    }
  } catch {
    return "signature_invalid";
  }

  const trustedRoles = testCase.trusted_key_roles ?? Object.keys(manifest.public_keys_raw_b64);
  const trustedKeys = trustedRoles.map((role) => publicKey(manifest.public_keys_raw_b64[role]));
  const verified = trustedKeys.some((key) =>
    signatures.some((signature) => verifySignature(null, signingInput, key, signature)),
  );
  return verified ? null : "signature_invalid";
}

let failures = 0;
for (const testCase of manifest.cases) {
  const code = verifyCase(testCase);
  const passed = code === null;
  const matches =
    testCase.expect === "pass" ? passed : !passed && (testCase.failure === undefined || testCase.failure === code);
  if (matches) {
    process.stdout.write(`ok  ${testCase.id}\n`);
  } else {
    process.stderr.write(`FAIL ${testCase.id}: passed=${passed} code=${code}\n`);
    failures += 1;
  }
}

process.exitCode = failures === 0 ? 0 : 1;
