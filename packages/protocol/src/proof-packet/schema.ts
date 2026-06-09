import { z } from "zod";
import { zEvmAddress, zHexString } from "../wire/zod";

/** ZIP folder layout version (canonical definition lives in this OSS package). */
export const PROOF_PACKET_SCHEMA_V1 = "filosign-proof-packet-v1" as const;
export type ProofPacketSchema = typeof PROOF_PACKET_SCHEMA_V1;

/** Verification manifest format version. */
export const VERIFY_MANIFEST_FORMAT_V1 = "filosign-verify-v1" as const;

/**
 * Default paths for proof packet v1.
 * Paths under `proofFolder` are relative to `proofs/`.
 * `consumerDocument` is at the ZIP root.
 */
export const PROOF_PACKET_V1_DEFAULT_PATHS = {
	proofFolder: "proofs",
	consumerDocument: "document-with-proof.pdf",
	consumerDocumentFromProofFolder: "../document-with-proof.pdf",
	readme: "README.txt",
	manifest: "verify-manifest.json",
	bundle: "bundle/bundle.json",
	bundleHash: "bundle/bundle.sha256",
	documentMerkle: "documents/merkle-proofs.json",
	originalPrefix: "documents/original/",
	proofReport: "reports/proof-report.pdf",
	attachedFilesPrefix: "Attached Files/",
	attachmentsManifest: "attachments/manifest.json",
	attachmentsOriginalPrefix: "attachments/original/",
} as const;

export const zVerifyManifestV1 = z.object({
	format: z.literal(VERIFY_MANIFEST_FORMAT_V1),
	packetSchema: z.literal(PROOF_PACKET_SCHEMA_V1),
	consumerDocumentPath: z.string(),
	bundlePath: z.string(),
	bundleHashPath: z.string(),
	bundleSha256: zHexString(),
	chainId: z.number().int(),
	pieceCid: z.string(),
	registryAddress: zEvmAddress(),
	documentMerklePath: z.string(),
	originalDocumentsPrefix: z.string(),
	attachmentsManifestPath: z.string().optional(),
	attachedFilesPrefix: z.string().optional(),
});

export type VerifyManifestV1 = z.infer<typeof zVerifyManifestV1>;

/** Alias — only one manifest shape is supported today. */
export const zVerifyManifest = zVerifyManifestV1;
export type VerifyManifest = VerifyManifestV1;
