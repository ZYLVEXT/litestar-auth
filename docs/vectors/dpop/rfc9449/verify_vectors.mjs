#!/usr/bin/env node
/** Dependency-free Node.js verification of the RFC 9449 resource-server vectors. */

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

const manifestUrl = new URL("./manifest.json", import.meta.url);
const data = JSON.parse(await readFile(manifestUrl, "utf8"));
const now = Date.parse(data.now) / 1000;

function decodePart(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

function decodeJwt(value) {
  const parts = value.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  return {
    header: decodePart(parts[0]),
    claims: decodePart(parts[1]),
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
    signature: Buffer.from(parts[2], "base64url"),
  };
}

function verifyEs256(jwt, jwk) {
  return verify(
    "sha256",
    jwt.signingInput,
    { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" },
    jwt.signature,
  );
}

function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash("sha256").update(canonical).digest("base64url");
}

function normalizeHtu(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("untrusted htu");
  url.search = "";
  url.hash = "";
  if (url.port === "443") url.port = "";
  return url.toString().replace(/\/$/, url.pathname === "/" ? "/" : "");
}

function classify(testCase) {
  if (testCase.authorization?.startsWith("Bearer ") && testCase.dpop) return "ambiguous";
  if (!testCase.authorization?.startsWith("DPoP ") || !testCase.dpop) return "malformed";
  try {
    const accessTokenValue = testCase.authorization.slice(5);
    const accessToken = decodeJwt(accessTokenValue);
    const proof = decodeJwt(testCase.dpop);
    const issuerJwk = data.jwks.keys.find((key) => key.kid === accessToken.header.kid);
    if (
      accessToken.header.typ !== "at+jwt" ||
      accessToken.header.alg !== "ES256" ||
      !issuerJwk ||
      !verifyEs256(accessToken, issuerJwk)
    ) return "invalid";
    if (
      accessToken.claims.iss !== data.issuer ||
      accessToken.claims.aud !== data.audience ||
      accessToken.claims.iat > now + 30 ||
      accessToken.claims.exp <= now - 30
    ) return "invalid";
    if (
      proof.header.typ !== "dpop+jwt" ||
      proof.header.alg !== "ES256" ||
      proof.header.jwk?.d ||
      !verifyEs256(proof, proof.header.jwk)
    ) return "invalid";
    if (
      proof.claims.htm.toUpperCase() !== testCase.method.toUpperCase() ||
      normalizeHtu(proof.claims.htu) !== normalizeHtu(testCase.target_uri) ||
      Math.abs(now - proof.claims.iat) > 90
    ) return "sender_constraint_mismatch";
    const ath = createHash("sha256").update(accessTokenValue, "ascii").digest("base64url");
    if (proof.claims.ath !== ath || accessToken.claims.cnf?.jkt !== thumbprint(proof.header.jwk)) {
      return "sender_constraint_mismatch";
    }
    return "pass";
  } catch {
    return "invalid";
  }
}

let failures = 0;
for (const testCase of data.cases) {
  const actual = classify(testCase);
  const expected = testCase.expect === "pass" ? "pass" : testCase.expect === "ambiguous" ? "ambiguous" : testCase.failure;
  if (actual !== expected) {
    console.error(`FAIL ${testCase.id}: expected ${expected}, got ${actual}`);
    failures += 1;
  } else {
    console.log(`ok  ${testCase.id}`);
  }
}
process.exitCode = failures === 0 ? 0 : 1;
