import { describe, expect, it } from "bun:test";
import {
	type ComplianceBundle,
	complianceBundleSha256Hex,
	computePlacementCommitment,
} from "@filosign/protocol";
import { verifyLocal } from "../src/index";

const placementManifest = {
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

const minimalBundle = {
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

describe("@filosign/verify local checks", () => {
	it("verifyLocal passes schema and placement checks on minimal bundle", async () => {
		const summary = await verifyLocal({ bundle: minimalBundle });
		expect(summary.failed).toBe(0);
		expect(summary.passed).toBeGreaterThan(0);
		expect(
			summary.results.some((result) => result.id === "local.bundle.schema"),
		).toBe(true);
	});

	it("verifyLocal compares bundle.sha256 sidecar when provided", async () => {
		const bundleHash = await complianceBundleSha256Hex(minimalBundle);
		const summary = await verifyLocal({
			bundle: minimalBundle,
			bundleSha256Sidecar: bundleHash,
		});
		expect(summary.failed).toBe(0);
		expect(
			summary.results.find(
				(result) => result.id === "local.bundle.sha256.sidecar",
			)?.status,
		).toBe("pass");
	});

	it("verifyLocal fails when bundle.sha256 sidecar mismatches", async () => {
		const summary = await verifyLocal({
			bundle: minimalBundle,
			bundleSha256Sidecar: `0x${"ff".repeat(32)}`,
		});
		expect(summary.failed).toBeGreaterThan(0);
		expect(
			summary.results.find(
				(result) => result.id === "local.bundle.sha256.sidecar",
			)?.status,
		).toBe("fail");
	});
});
