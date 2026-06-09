import type {
	ComplianceBundle,
	DocumentMerkleLeafProofV1,
	VerifyManifestV1,
} from "@filosign/protocol";

export type CheckStatus = "pass" | "fail" | "skip" | "warn";

export type CheckTier = "local" | "chain" | "documents";

export type CheckResult = {
	id: string;
	tier: CheckTier;
	status: CheckStatus;
	expected?: string;
	actual?: string;
	message?: string;
	explorerUrl?: string | null;
};

export type VerifySummary = {
	passed: number;
	failed: number;
	skipped: number;
	warned: number;
	total: number;
	results: CheckResult[];
};

export type AttachmentManifestPayload = {
	attachments: Array<{
		packetId: string;
		packetCid: string;
		label: string | null;
		releaseMode: "review" | "conditional";
		unlocked: boolean;
		packetContentHash: string | null;
		files: Array<{
			id: string;
			name: string;
			mimeType: string;
			sha256: string;
		}>;
	}>;
};

export type ParsedProofPacket = {
	bundle: ComplianceBundle;
	manifest: VerifyManifestV1;
	bundleSha256Sidecar: string | null;
	documentMerkleProofs: {
		registerDocumentMerkleRoot: string;
		proofs: DocumentMerkleLeafProofV1[];
	} | null;
	originalDocuments: Record<string, Uint8Array>;
	attachmentManifest: AttachmentManifestPayload | null;
	originalAttachments: Record<string, Uint8Array>;
};

export type VerifyChainOptions = {
	rpcUrl: string;
	registryAddress: `0x${string}`;
};

export type VerifyPacketOptions = {
	zipBytes: Uint8Array;
	rpcUrl?: string;
	tiers?: CheckTier[];
};
