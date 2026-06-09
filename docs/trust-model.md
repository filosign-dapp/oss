# Trust model (OSS)

Filosign stores envelope registration and signatures on-chain. Export generation runs on Filosign infrastructure; **verification** runs independently with this OSS tooling.

## v1 envelopes (current)

- Roster slots use email commitments on-chain
- Server relay signs registrations and signatures (`onlyServer`)
- Wallet-to-slot binding is off-chain for v1; see wallet-identity plan for v2

## What independent verification proves

| Tier | Proves |
|------|--------|
| Local | Export JSON is well-formed and internally consistent |
| Chain | On-chain registry snapshot matches bundle + live RPC reads; per-signer slot binding (`hasSigned`, `boundSignerWallet`, `EnvelopeSigned` logs); settlement rules on `FSPaymentValidator`; conditional attachment rules on `FSAttachmentRelease` (including `packetContentHash`) |
| Documents | Decrypted envelope documents in ZIP match document Merkle root; exported attachment file SHA-256 hashes and packet plaintext hash (when bytes are present in the ZIP) |

## What it does not prove

- Filosign server relayed every valid signature (censorship is an availability risk, not on-chain forgery)
- Auth provider subject commitments (requires IdP data)
- Off-chain timeline fields (views, ack timestamps, IP) unless separately corroborated
- Review-mode attachment bytes when the exporter lacked decryption access (metadata only)
- Conditional attachment bytes while the packet remains locked on-chain
- Legal validity in your jurisdiction

See [independent-verification-guide.md](./independent-verification-guide.md).
