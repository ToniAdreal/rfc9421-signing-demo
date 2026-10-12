# Contributing

Thanks for looking at the code. This repository is a learning/demo
implementation of a subset of RFC 9421 (HTTP Message Signatures) — see
`README.md` → "Limitations (honest)" for what is and is not supported,
and `SECURITY.md` for the security scope. Contributions are held to the
same honesty bar as the docs: if a claim is in here, it has been run.

## Prerequisites

- Node.js ≥ 20 (declared in `package.json` → `engines`). CI runs the
  test suite on Node 20 and 22 (`.github/workflows/ci.yml`).
- npm. There is nothing else to install: the implementation uses only
  Node built-ins (`node:crypto`), and the only dev dependencies are
  `typescript` and `@types/node`.

## Setup

```bash
npm install
npm test
```

`npm test` first builds the project (`npm run build`, i.e. `tsc`) and
then runs the compiled tests with `node --test dist/test/*.test.js`.
Tests therefore always exercise the build output in `dist/` (which is
git-ignored), never the TypeScript sources directly — after editing
`src/` or `test/`, just re-run `npm test`.

Two more entry points worth knowing:

```bash
npm run demo   # sign a fixed payment request, verify it, then show a tampered body being rejected
npm run bench  # measure local sign/verify throughput (builds first, then runs dist/bench/bench.js)
```

## Repository layout

- `src/` — the library (`sign`, `verify`, `keys`, `jwks`, `replay`,
  `nodeHttp`, …), plus `src/demo.ts` behind `npm run demo`.
- `test/` — `node:test` suites, one file per feature area.
- `bench/bench.ts` — the benchmark behind `npm run bench`.

## Hard rules

1. **Zero runtime dependencies.** `package.json` must not gain a
   `dependencies` section. New code uses Node built-ins only;
   TypeScript tooling stays in `devDependencies`.
2. **Strict TypeScript, ESM.** `tsconfig.json` builds with
   `strict: true` and `module`/`moduleResolution: NodeNext`. Keep
   import specifiers NodeNext-compatible (explicit `.js` extensions).
3. **Honest numbers and claims.** The test counts quoted in
   `README.md` (Install and Reproducibility) must equal what
   `npm test` actually prints — if you add or remove tests, update
   both places to the real output. Benchmark figures must come from
   a real `npm run bench` run on the stated machine, dated like the
   existing table in `README.md` → "Benchmarks"; never pre-fill,
   round into place, or copy numbers from another environment.
   Interoperability wording follows the same rule: only claim what a
   test in this repo demonstrates (see `README.md` →
   "Interoperability").
4. **Deterministic, offline tests.** Assertions must not depend on
   the wall clock, unseeded randomness, or the external network.
   Keys may be generated per test, but only round-trip properties are
   asserted on them; the JWKS tests serve their documents from a
   loopback-only server on an ephemeral port.

## Before submitting a change

- [ ] `npm test` — the full suite passes.
- [ ] `npx tsc --noEmit` — clean (no type errors). There is no lint
      or formatter step configured in this repo; the strict `tsc`
      build is the static gate, so don't add instructions that assume
      one.
- [ ] If tests were added or removed, the `README.md` test counts
      match the real `npm test` output.
- [ ] If the benchmark table was touched, its numbers come from a
      real `npm run bench` run, with the run date and environment
      noted.
- [ ] If signing or verification paths changed, `npm run demo` still
      runs end to end (verify OK, tamper rejected).

## Commit style

Commit messages are in English and follow Conventional Commits, as in
the existing history — one focused change per commit:

```
feat: add JwksKeyStore.stats() observability counters
fix: <what was wrong, in the subject>
test: add RFC 9421 B.2.6/B.2.4 official vectors, pin ECDSA encoding divergence
docs: add CHANGELOG.md summarizing the 0.1.0 commit history
bench: measure key-resolution hot paths (JwksKeyStore.resolve, memoizeKeyResolver hit/miss)
```

Use the prefix that matches the change (`feat:` / `fix:` / `test:` /
`docs:` / `bench:` / `ci:` / `chore:`) and describe what actually
changed — a subject that overstates the diff is treated like any
other unverified claim.

## Reporting a security issue

Follow `SECURITY.md` → "Reporting a security issue": open an issue on
this repository describing the problem. Never include private keys,
secrets, or any credentials in a report — a description of the
behavior is enough.
