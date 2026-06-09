# Proof packet format (v1)

Canonical schema: [`packages/protocol/src/proof-packet/schema.ts`](../packages/protocol/src/proof-packet/schema.ts) in this OSS repo. `@filosign/verify` validates exports against that definition only.

## ZIP layout

```text
{DocumentName}-proof-{YYYY-MM-DD}-{pieceId}.zip
├── document-with-proof.pdf
└── proofs/
    ├── README.txt
    ├── verify-manifest.json
    ├── bundle/
    │   ├── bundle.json
    │   └── bundle.sha256
    ├── documents/
    │   ├── merkle-proofs.json
    │   └── original/
    └── reports/
        └── proof-report.pdf
```

| Path | Purpose |
|------|---------|
| `document-with-proof.pdf` | Merged share PDF (only file meant for everyday reading) |
| `proofs/README.txt` | Index and identifiers for counsel / IT |
| `proofs/verify-manifest.json` | Schema version and verification path index |
| `proofs/bundle/bundle.json` | Canonical compliance export |
| `proofs/bundle/bundle.sha256` | SHA-256 of canonical bundle JSON |
| `proofs/documents/merkle-proofs.json` | Per-document Merkle proofs |
| `proofs/documents/original/*` | Decrypted signed documents |
| `proofs/reports/proof-report.pdf` | Human-readable proof report |

Download filenames are chosen by the Filosign client: document name, `-proof-`, export date, and a short piece storage id.

## verify-manifest.json

Paths are relative to `proofs/` (the manifest directory).

```json
{
  "format": "filosign-verify-v1",
  "packetSchema": "filosign-proof-packet-v1",
  "consumerDocumentPath": "../document-with-proof.pdf",
  "bundlePath": "bundle/bundle.json",
  "bundleHashPath": "bundle/bundle.sha256",
  "bundleSha256": "0x…",
  "chainId": 84532,
  "pieceCid": "bafk…",
  "registryAddress": "0x…",
  "documentMerklePath": "documents/merkle-proofs.json",
  "originalDocumentsPrefix": "documents/original/"
}
```

Public link: [independent-verification-guide.md](./independent-verification-guide.md)
