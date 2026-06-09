# Compatibility matrix

Symbols that must match private `@filosign/shared` byte-for-byte for verification parity.

| Private (`packages/shared`) | OSS (`@filosign/protocol`) | Parity required |
|-----------------------------|------------------------------|-----------------|
| `zComplianceBundle` | `compliance/bundle.ts` | Yes |
| `canonicalComplianceBundleJson` | `compliance/canonical.ts` | Yes |
| `computePlacementCommitment` | `placement/commitment.ts` | Yes |
| `hashNormalizedSignerEmail` | `commitments/email.ts` | Yes |
| `emailCommitRoot` | `commitments/email.ts` | Yes |
| `sortedCommitsForEmails` | `commitments/email.ts` | Yes |
| `buildRegistrationEmailCommitments` | `commitments/roster.ts` | Yes |
| `computeLeafHashV1` | `merkle/field-completion.ts` | Yes |
| `completionsMerkleRootV1` | `merkle/field-completion.ts` | Yes |
| `merkleRootFromLeafAndSiblings` | `merkle/tree.ts` | Yes |
| `verifyDocumentMerkleProofV1` | `merkle/document.ts` | Yes |
| `computeCidIdentifier` | `piece/cid-identifier.ts` | Yes |
| `jsonStringify` (stable) | `json/stable-stringify.ts` | Yes |
| — | `proof-packet/schema.ts` (`zVerifyManifestV1`, `PROOF_PACKET_V1_DEFAULT_PATHS`) | Private monorepo consumes via `@filosign/protocol` (`oss/packages/protocol` workspace) |

Update this table when adding symbols. Golden fixtures live in `packages/protocol/tests/fixtures/`.
