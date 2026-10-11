import { strict as assert } from "node:assert";
import { test } from "node:test";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

// Guards the package entry point: package.json used to declare only
// `main`/`types`, with no `exports` map, so how modern Node and
// bundlers resolve the package by name — and which subpaths exist —
// was uncontrolled. The `exports` map is now the controlled entry
// (`.` -> dist/src/, this repo's actual tsc emit layout), `main`/
// `types` are kept for older resolvers, and all three must agree and
// point at real build output. Mirrors the dataquest pilot (#184).

const repoRoot = path.dirname(
  path.dirname(path.dirname(fileURLToPath(import.meta.url))),
); // dist/test/*.test.js -> repo root

type PackageJson = {
  name: string;
  main?: string;
  types?: string;
  exports?: Record<string, Record<string, string> | string>;
};

function readPackageJson(): PackageJson {
  return JSON.parse(
    readFileSync(path.join(repoRoot, "package.json"), "utf8"),
  ) as PackageJson;
}

function stripDotSlash(p: string): string {
  return p.startsWith("./") ? p.slice(2) : p;
}

test("package.json declares an exports map for '.' with types/import/default", () => {
  const pkg = readPackageJson();
  assert.ok(pkg.exports, "package.json must declare an exports map");
  const dot = pkg.exports["."];
  assert.ok(dot && typeof dot === "object", "exports must define a '.' entry");
  assert.equal(dot.types, "./dist/src/index.d.ts");
  assert.equal(dot.import, "./dist/src/index.js");
  assert.equal(dot.default, "./dist/src/index.js");
});

test("exports, main and types agree on the same entry files", () => {
  const pkg = readPackageJson();
  const dot = pkg.exports?.["."] as Record<string, string>;
  assert.equal(stripDotSlash(dot.import), pkg.main);
  assert.equal(stripDotSlash(dot.default), pkg.main);
  assert.equal(stripDotSlash(dot.types), pkg.types);
});

test("every declared entry file exists after build", () => {
  const pkg = readPackageJson();
  const dot = pkg.exports?.["."] as Record<string, string>;
  for (const target of [pkg.main, pkg.types, dot.types, dot.import, dot.default]) {
    assert.ok(target, "entry target must be declared");
    const resolved = path.join(repoRoot, stripDotSlash(target));
    assert.ok(
      existsSync(resolved),
      `declared entry "${target}" does not exist after build`,
    );
  }
});

test("self-referencing import by package name exposes the core API", async () => {
  const pkg = readPackageJson();
  // Non-literal specifier: the package name is read from package.json
  // itself, so a rename or a broken exports map fails here, not a
  // hard-coded string that happens to match.
  const specifier: string = pkg.name;
  const mod = (await import(specifier)) as Record<string, unknown>;
  assert.equal(typeof mod.generateEd25519KeyPair, "function");
  assert.equal(typeof mod.signRequest, "function");
  assert.equal(typeof mod.verifyRequest, "function");

  const generateEd25519KeyPair = mod.generateEd25519KeyPair as () => {
    publicKey: unknown;
    privateKey: unknown;
  };
  const signRequest = mod.signRequest as (
    req: Record<string, unknown>,
    opts: Record<string, unknown>,
  ) => { headers: Record<string, string>; body: string };
  const verifyRequest = mod.verifyRequest as (
    req: unknown,
    opts: Record<string, unknown>,
  ) => { ok: boolean; keyId?: string };

  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ amount: 100 }),
    },
    { keyId: "exports-smoke-1", alg: "ed25519", key: privateKey, created: 1700000000 },
  );
  assert.ok(signed.headers["signature-input"].includes('keyid="exports-smoke-1"'));
  const result = verifyRequest(signed, { key: publicKey, now: 1700000060 });
  assert.equal(result.ok, true);
  assert.equal(result.keyId, "exports-smoke-1");
});

test("importing via the main entry resolves the same module as self-reference", async () => {
  const pkg = readPackageJson();
  assert.ok(pkg.main);
  const byMain = (await import(
    pathToFileURL(path.join(repoRoot, pkg.main)).href
  )) as Record<string, unknown>;
  const specifier: string = pkg.name;
  const byName = (await import(specifier)) as Record<string, unknown>;
  assert.equal(byName.signRequest, byMain.signRequest);
});
