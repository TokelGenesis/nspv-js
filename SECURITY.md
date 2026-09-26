# Security notes

## Fuzzing

`npm run fuzz -- <iterations> <seed>` mutates valid transactions/blocks and random
bytes through every parser that handles data from peers (transactions, blocks,
all P2P message codecs, nSPV responses, headers, tx proofs). A run fails on a
hang (>250 ms per input), unbounded memory, or a thrown non-`Error`.
Last run: 1,000,000 inputs, seed 987654, no findings.

## Known advisories without an upstream fix

| Package | Via | Why it is not exploitable here |
|---|---|---|
| `ip` (GHSA-2p57-rm9w-gvfp) | `bitcoin-protocol` | The advisory is in `isPublic`/`isPrivate`. `bitcoin-protocol` only calls `isV4Format`/`isV6Format` to serialise peer addresses. |
| `elliptic` (low) | `secp256k1@3` | Only used as the pure-JS fallback when the native binding is unavailable. New clients should use `@noble/secp256k1`. |
