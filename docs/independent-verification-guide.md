# Independent verification guide

Drop your Filosign proof packet ZIP on the static verifier (coming in Phase B) or use the `@filosign/verify` library.

## Quick start (Phase B)

1. Download the full proof packet ZIP from Filosign after signing completes
2. Open `verify.filosign.xyz` (static page from `apps/verify-web`)
3. Drop the ZIP; review the checklist
4. Optionally paste an RPC URL for on-chain checks

## Checks

- **Tier A (offline):** bundle schema, hash, placement, Merkle self-consistency
- **Tier B (RPC):** live registry reads, transaction receipts
- **Tier C (optional):** original document bytes vs Merkle root

## Private implementation spec

See `project/proof/independent-verification-guide.md` in the private monorepo (when written).

## Compatibility

See [compatibility-matrix.md](./compatibility-matrix.md).
