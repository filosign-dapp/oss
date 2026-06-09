import {
	type ComplianceBundle,
	computePlacementCommitment,
} from "@filosign/protocol";

export const placementManifest = {
	version: 1 as const,
	documents: [
		{
			id: "d1",
			name: "a.pdf",
			sha256Plaintext: `0x${"aa".repeat(32)}`,
			pageCount: 1,
		},
	],
	fields: [
		{
			id: "f1",
			documentId: "d1",
			pageIndex: 0,
			rect: { x: 0, y: 0, width: 0.1, height: 0.1 },
			assignedRecipientEmail: "a@example.com",
			required: true,
			type: "signature" as const,
		},
	],
};

export const minimalBundle = {
	version: 1,
	pieceCid: "bafyTEST",
	chainId: 84532,
	exportedAtIso: "2026-01-01T00:00:00.000Z",
	executionStatus: "fully_executed",
	placementCommitment: computePlacementCommitment(placementManifest),
	placementManifest,
	registration: {
		sender: "0x0000000000000000000000000000000000000001",
		registrationTxHash: `0x${"bb".repeat(32)}`,
		createdAtIso: "2026-01-01T00:00:00.000Z",
		registerDocumentSha256: `0x${"cc".repeat(32)}`,
	},
	parties: [],
	onchainRegistration: null,
	transactions: [],
	signers: [],
	settlements: [],
	attachments: [],
	offChainEvidence: {
		acknowledgements: [],
		documentViews: [],
		coldInviteClaims: [],
		payoutRecipientAcknowledgements: [],
	},
} satisfies ComplianceBundle;

export const merkleProofsPayload = {
	registerDocumentMerkleRoot: minimalBundle.registration.registerDocumentSha256,
	proofs: [],
};
