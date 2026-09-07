import { readFileSync, writeFileSync } from "node:fs";
const src = readFileSync("scopedGatewayActor.ts", "utf8");

// Cut out exactly the two functions the digest depends on, by their source text, so nothing is
// retyped by hand.
const startCanon = src.indexOf("export function canonicalJson");
const endDigest = src.indexOf("export function createScopedActorVerifier");
if (startCanon < 0 || endDigest < 0) throw new Error("markers not found");

let extracted = src.slice(startCanon, endDigest);

// TypeScript -> JavaScript: annotation removal only, no logic changes.
extracted = extracted
  .replace(/export /g, "")
  .replace(/\(value: unknown, depth = 0\): string/, "(value, depth = 0)")
  .replace(
    /function requestDigest\([\s\S]*?\): Promise<string> \{/,
    "function requestDigest(operation, body) {",
  )
  .replace(/const object = value as Record<string, unknown>;/, "const object = value;")
  .replace(/throw new ScopedGatewayError\(400, "invalid_request"\)/g, 'throw new Error("invalid_request")');

if (/: (unknown|string|Promise)|Record<|as Record|ScopedGatewayError/.test(extracted)) {
  throw new Error("type annotations survived the transform:\n" + extracted);
}

writeFileSync("canonical.mjs", extracted + "\nexport { canonicalJson, requestDigest };\n");
console.log(extracted);
