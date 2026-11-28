import test from "node:test";
import assert from "node:assert/strict";
import { ReplayCache } from "../src/index.js";

// Backlog #1443: a clock that jumps backwards (NTP correction, a VM
// restore) must not reopen the replay window. The replay test is
// `now - seenAt < ttlSec`, so a rewound `now` still reports a seen
// nonce as a replay; `has()` / `size` / `exportSnapshot()` keep the
// entry live, and `prune()` never drops a future-dated entry as
// expired — the entry only expires once the clock has advanced
// `ttlSec` past its first-seen time.
const T0 = 1_700_000_000;
const TTL = 300;

test("rewound clock: seen nonce still replays via check and has", () => {
  let now = T0;
  const cache = new ReplayCache({ ttlSec: TTL, now: () => now });
  assert.equal(cache.check("n1"), false);
  assert.equal(cache.size, 1);

  // Rewind 100s: the entry's seenAt (T0) is now in the future.
  now = T0 - 100;
  assert.equal(cache.check("n1"), true);
  assert.equal(cache.has("n1"), true);
  assert.equal(cache.size, 1);
  assert.equal(cache.stats().hits, 1);
  assert.equal(cache.stats().misses, 1);
});

test("rewound clock: exportSnapshot still contains the entry", () => {
  let now = T0;
  const cache = new ReplayCache({ ttlSec: TTL, now: () => now });
  assert.equal(cache.check("n1"), false);
  assert.equal(cache.check("n2", T0, "kid-a"), false);

  now = T0 - 100;
  assert.deepEqual(cache.exportSnapshot(), {
    v: 2,
    entries: [
      ["", "n1", T0],
      ["kid-a", "n2", T0],
    ],
  });
});

test("rewound clock: expiry semantics unchanged once the clock advances past TTL", () => {
  let now = T0;
  const cache = new ReplayCache({ ttlSec: TTL, now: () => now });
  assert.equal(cache.check("n1"), false);

  // Rewind, then confirm the replay still holds.
  now = T0 - 100;
  assert.equal(cache.check("n1"), true);

  // Exactly at the TTL boundary the entry counts as expired.
  now = T0 + TTL;
  assert.equal(cache.has("n1"), false);
  assert.equal(cache.size, 0);

  // One second past the boundary the nonce is unseen again and
  // re-records with a fresh first-seen time.
  now = T0 + TTL + 1;
  assert.equal(cache.check("n1"), false);
  assert.equal(cache.has("n1"), true);
  assert.equal(cache.size, 1);
  assert.deepEqual(cache.exportSnapshot(), {
    v: 2,
    entries: [["", "n1", T0 + TTL + 1]],
  });
});

test("rewound clock: prune never drops future-dated entries as expired", () => {
  let now = T0;
  const cache = new ReplayCache({
    maxEntries: 3,
    ttlSec: TTL,
    now: () => now,
  });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("b"), false);
  assert.equal(cache.check("c"), false);
  assert.equal(cache.size, 3);

  // Rewind, then add a fourth nonce: prune runs at capacity, but no
  // entry is expired against the rewound clock (all three seenAt are
  // in the future), so only the LRU eviction of the oldest entry
  // ("a") may make room — "b" and "c" must survive.
  now = T0 - 100;
  assert.equal(cache.check("d"), false);
  assert.equal(cache.size, 3);
  assert.equal(cache.stats().evictions, 1);
  assert.equal(cache.has("a"), false);
  assert.equal(cache.has("b"), true);
  assert.equal(cache.has("c"), true);
  assert.equal(cache.has("d"), true);
});

test("rewound clock: scoped entries replay independently", () => {
  let now = T0;
  const cache = new ReplayCache({ ttlSec: TTL, now: () => now });
  assert.equal(cache.check("n1", T0, "kid-a"), false);

  now = T0 - 100;
  assert.equal(cache.check("n1", T0 - 100, "kid-a"), true);
  // The same nonce under another keyid is a different entry and is
  // still first-seen, even at the rewound time.
  assert.equal(cache.check("n1", T0 - 100, "kid-b"), false);
  assert.equal(cache.has("n1", T0 - 100, "kid-a"), true);
  assert.equal(cache.has("n1", T0 - 100, "kid-b"), true);
});

test("rewound clock: release still forgets exactly the rewound entry", () => {
  let now = T0;
  const cache = new ReplayCache({ ttlSec: TTL, now: () => now });
  assert.equal(cache.check("n1"), false);
  assert.equal(cache.check("n2"), false);

  now = T0 - 100;
  assert.equal(cache.release("n1"), true);
  assert.equal(cache.has("n1"), false);
  // The sibling entry is untouched by the release.
  assert.equal(cache.has("n2"), true);
  assert.equal(cache.size, 1);
  // A released nonce records as first-seen again.
  assert.equal(cache.check("n1"), false);
  assert.equal(cache.size, 2);
});
