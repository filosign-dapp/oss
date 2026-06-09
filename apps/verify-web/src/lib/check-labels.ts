import type { CheckTier } from "@filosign/verify";

export const TIER_LABELS: Record<CheckTier, string> = {
	local: "Export integrity",
	chain: "Blockchain",
	documents: "Document bytes",
};

export const CHECK_LABELS: Record<string, string> = {
	"local.bundle.schema": "Bundle schema",
	"local.bundle.sha256.sidecar": "Bundle SHA-256 sidecar",
	"local.manifest.bundleSha256": "Manifest bundle hash",
	"local.manifest.sidecarMatch": "Manifest vs sidecar hash",
	"local.placement.commitment": "Placement commitment",
	"local.snapshot.placementCommitment": "Snapshot placement commitment",
	"local.snapshot.documentSha256": "Snapshot document hash",
	"chain.rpc.chainId": "RPC chain ID",
	"chain.rpc.connect": "RPC connectivity",
	"chain.registration.read": "Registry read",
	"chain.registration.exists": "Registration exists on-chain",
	"chain.registration.cidIdentifier": "Content ID on-chain",
	"chain.registration.sender": "Sender on-chain",
	"chain.registration.placementCommitment": "Placement on-chain",
	"chain.registration.documentSha256": "Document root on-chain",
	"chain.registration.senderEmailCommitment":
		"Sender email commitment on-chain",
	"chain.registration.signersCommitment": "Signers commitment on-chain",
	"chain.registration.viewersCommitment": "Viewers commitment on-chain",
	"chain.registration.requiredSignersCount": "Required signers count on-chain",
	"chain.registration.signaturesCount": "Signatures count on-chain",
	"chain.registration.timestamp": "Registration timestamp on-chain",
	"documents.merkle.root": "Document Merkle root",
	"documents.merkleProofs": "Merkle proofs present",
	"documents.original.present": "Original documents present",
	"documents.attachments.manifest": "Attachment manifest present",
};

export function labelForCheck(id: string): string {
	if (CHECK_LABELS[id]) return CHECK_LABELS[id];
	if (id.startsWith("local.parties[") && id.includes("emailCommitment")) {
		return "Party email commitment";
	}
	if (id.startsWith("local.parties[") && id.includes("authSubjectCommitment")) {
		return "Party auth subject commitment";
	}
	if (id.startsWith("local.signers[") && id.includes("merkleProof")) {
		return "Signer field Merkle proof";
	}
	if (id.startsWith("local.signers[") && id.includes("leafHash")) {
		return "Signer field leaf hash";
	}
	if (id.startsWith("chain.tx.")) {
		return "Transaction receipt";
	}
	if (id.startsWith("chain.signers[") && id.endsWith(".hasSigned")) {
		return "Signer slot signed on-chain";
	}
	if (id.startsWith("chain.signers[") && id.endsWith(".boundWallet")) {
		return "Signer wallet bound to email slot";
	}
	if (id.startsWith("chain.signers[") && id.includes(".envelopeSignedEvent")) {
		return "EnvelopeSigned log matches bundle";
	}
	if (id.startsWith("chain.signers[") && id.endsWith(".emailCommitment")) {
		return "Signer email commitment resolved";
	}
	if (id.startsWith("documents.original.")) {
		return "Original document in packet";
	}
	if (id.startsWith("documents.proof.")) {
		return "Document Merkle inclusion";
	}
	if (id.startsWith("chain.settlement.")) {
		return "Settlement rule on-chain";
	}
	if (id.startsWith("chain.attachment.")) {
		return "Attachment rule on-chain";
	}
	if (id.startsWith("documents.attachments.")) {
		return "Attachment file hash";
	}
	return id;
}
