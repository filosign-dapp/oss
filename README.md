# Filosign OSS

Open-source segment for Filosign trust primitives and proof verification.

**Source of truth:** this tree lives at `oss/` in the private Filosign monorepo. Develop here on `main`; publish to the public OSS remote when releasing.

Root workspaces include **`oss/packages/protocol`** only (avoids `@filosign/contracts` name clash with `apps/contracts`). Other OSS packages resolve under `cd oss` via this folder's own `package.json` workspaces.

## Packages

| Package | Role |
|---------|------|
| [`@filosign/protocol`](packages/protocol/) | Wire schemas, commitment math, proof packet schema |
| [`@filosign/contracts`](packages/contracts/) | Solidity, ABIs, public chain manifests |
| [`@filosign/verify`](packages/verify/) | Proof packet verification engine |
| [`verify-web`](apps/verify-web/) | Static browser verifier (drop ZIP) |

## Commands

From **`oss/`** (OSS nested workspaces):

```bash
bun install
bun test
bun run check
bun run build
```

From **filosign root**, `@filosign/protocol` is linked for `apps/client` (completion packet export).

## Publish to public OSS repo

Push only this folder to a separate GitHub remote (no duplicate dev checkout):

```bash
# From filosign repo root
git subtree split --prefix=oss -b oss-publish
git push git@github.com:filosign-dapp/oss.git oss-publish:main
```

To pull external OSS contributions back:

```bash
git subtree pull --prefix=oss git@github.com:filosign-dapp/oss.git main
```

Optional: automate with a GitHub Action on `oss/**` changes.

## Docs

See [`docs/`](docs/) for trust model, proof packet format, and verification guide.

## Phase roadmap

1. **Phase A (current):** skeleton, protocol, contracts ABI + chains manifest
2. **Phase B:** verify engine + static web UI
3. **Phase C:** CLI, full crypto, v2 bind checks
