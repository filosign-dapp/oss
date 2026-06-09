import { describe, expect, it } from "bun:test";
import type {
	CheckResult,
	ParsedProofPacket,
	VerifySummary,
} from "@filosign/verify";
import { buildVerificationReport } from "../src/lib/build-verification-report";

const bundleHash = `0x${"dd".repeat(32)}` as `0x${string}`;
const documentRoot = `0x${"cc".repeat(32)}` as `0x${string}`;

const bundle = {
	version: 1 as const,
	pieceCid: "bafyTEST",
	chainId: 31337,
	exportedAtIso: "2026-01-01T00:00:00.000Z",
	executionStatus: "fully_executed" as const,
	placementCommitment: `0x${"ee".repeat(32)}` as `0x${string}`,
	placementManifest: {
		version: 1 as const,
		documents: [
			{
				id: "doc1",
				name: "contract.pdf",
				sha256Plaintext: `0x${"ab".repeat(32)}` as `0x${string}`,
				pageCount: 1,
			},
		],
		fields: [],
	},
	registration: {
		sender: "0x0000000000000000000000000000000000000001" as `0x${string}`,
		registrationTxHash: `0x${"bb".repeat(32)}` as `0x${string}`,
		createdAtIso: "2026-01-01T00:00:00.000Z",
		registerDocumentSha256: documentRoot,
	},
	parties: [
		{
			role: "sender" as const,
			wallet: "0x0000000000000000000000000000000000000001" as `0x${string}`,
			email: "sender@example.com",
			displayName: "Sender",
			emailCommitment: `0x${"01".repeat(32)}` as `0x${string}`,
			authSubjectCommitment: `0x${"02".repeat(32)}` as `0x${string}`,
		},
	],
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
} satisfies ParsedProofPacket["bundle"];

const testManifest = {
	format: "filosign-verify-v1" as const,
	packetSchema: "filosign-proof-packet-v1" as const,
	consumerDocumentPath: "../document-with-proof.pdf",
	bundlePath: "bundle/bundle.json",
	bundleHashPath: "bundle/bundle.sha256",
	bundleSha256: bundleHash,
	chainId: 31337,
	pieceCid: "bafyTEST",
	registryAddress:
		"0x00000000000000000000000000000000000000aa" as `0x${string}`,
	documentMerklePath: "documents/merkle-proofs.json",
	originalDocumentsPrefix: "documents/original/",
} satisfies ParsedProofPacket["manifest"];

function summaryFromChecks(results: CheckResult[]): VerifySummary {
	let passed = 0;
	let failed = 0;
	let skipped = 0;
	let warned = 0;
	for (const result of results) {
		switch (result.status) {
			case "pass":
				passed++;
				break;
			case "fail":
				failed++;
				break;
			case "skip":
				skipped++;
				break;
			case "warn":
				warned++;
				break;
		}
	}
	return { passed, failed, skipped, warned, total: results.length, results };
}

describe("buildVerificationReport", () => {
	it("marks verified when no failures, even with warn checks", () => {
		const results: CheckResult[] = [
			{
				id: "local.bundle.schema",
				tier: "local",
				status: "pass",
			},
			{
				id: "local.parties[0].authSubjectCommitment",
				tier: "local",
				status: "warn",
				message: "authSubjectCommitment present",
			},
		];
		const report = buildVerificationReport({
			fileName: "test.zip",
			chainId: 31337,
			chainName: "Hardhat",
			packet: {
				bundle,
				manifest: testManifest,
				bundleSha256Sidecar: bundleHash,
				documentMerkleProofs: null,
				originalDocuments: {},
				attachmentManifest: null,
				originalAttachments: {},
			},
			summary: summaryFromChecks(results),
		});

		expect(report.verdict).toBe("verified");
		expect(report.counts.passed).toBe(1);
		expect(report.counts.info).toBe(1);
		expect(report.counts.failed).toBe(0);
		expect(report.sections.some((section) => section.title === "Notes")).toBe(
			true,
		);
		const notes = report.sections.find((section) => section.title === "Notes");
		expect(notes?.intro).toContain("Filosign");
		expect(notes?.rows).toHaveLength(1);
		expect(notes?.rows[0]?.exportValue).toContain("sender:");
	});

	it("lists each party once in Notes for auth subject warnings", () => {
		const report = buildVerificationReport({
			fileName: "test.zip",
			chainId: 31337,
			chainName: "Hardhat",
			packet: {
				bundle: {
					...bundle,
					parties: [
						bundle.parties[0]!,
						{
							role: "signer" as const,
							wallet:
								"0x0000000000000000000000000000000000000002" as `0x${string}`,
							email: "signer@example.com",
							displayName: "Signer",
							emailCommitment: `0x${"03".repeat(32)}` as `0x${string}`,
							authSubjectCommitment: `0x${"04".repeat(32)}` as `0x${string}`,
						},
					],
				},
				manifest: testManifest,
				bundleSha256Sidecar: bundleHash,
				documentMerkleProofs: null,
				originalDocuments: {},
				attachmentManifest: null,
				originalAttachments: {},
			},
			summary: summaryFromChecks([
				{
					id: "local.parties[0].authSubjectCommitment",
					tier: "local",
					status: "warn",
				},
				{
					id: "local.parties[1].authSubjectCommitment",
					tier: "local",
					status: "warn",
				},
			]),
		});

		const notes = report.sections.find((section) => section.title === "Notes");
		expect(notes?.rows).toHaveLength(2);
		expect(notes?.rows[0]?.exportValue).toBe("sender: Sender");
		expect(notes?.rows[1]?.exportValue).toBe("signer: Signer");
	});

	it("marks failed when any check fails", () => {
		const report = buildVerificationReport({
			fileName: "test.zip",
			chainId: 31337,
			chainName: "Hardhat",
			packet: {
				bundle,
				manifest: testManifest,
				bundleSha256Sidecar: null,
				documentMerkleProofs: null,
				originalDocuments: {},
				attachmentManifest: null,
				originalAttachments: {},
			},
			summary: summaryFromChecks([
				{
					id: "chain.registration.exists",
					tier: "chain",
					status: "fail",
					message: "No registration",
				},
			]),
		});

		expect(report.verdict).toBe("failed");
		expect(report.counts.failed).toBe(1);
	});

	it("includes workflow and document summary sections", () => {
		const report = buildVerificationReport({
			fileName: "proof.zip",
			chainId: 31337,
			chainName: "Hardhat",
			packet: {
				bundle,
				manifest: testManifest,
				bundleSha256Sidecar: bundleHash,
				documentMerkleProofs: null,
				originalDocuments: { "contract.pdf": new Uint8Array([1, 2, 3]) },
				attachmentManifest: null,
				originalAttachments: {},
			},
			summary: summaryFromChecks([
				{
					id: "documents.merkle.root",
					tier: "documents",
					status: "pass",
					expected: documentRoot,
					actual: documentRoot,
				},
			]),
		});

		expect(report.sections[0]?.title).toBe("About this workflow");
		const documents = report.sections.find(
			(section) => section.title === "Documents",
		);
		expect(documents?.rows.some((row) => row.claim === "Document files")).toBe(
			true,
		);
	});

	it("includes attachment byte checks in Attached files section", () => {
		const packetContentHash = `0x${"aa".repeat(32)}` as `0x${string}`;
		const fileHash = `0x${"bb".repeat(32)}` as `0x${string}`;
		const report = buildVerificationReport({
			fileName: "proof.zip",
			chainId: 31337,
			chainName: "Hardhat",
			packet: {
				bundle: {
					...bundle,
					attachments: [
						{
							packetId: "pkt-1",
							packetCid: "bafyPACKET",
							label: "Exhibit",
							releaseMode: "conditional",
							releaseType: "all_signed",
							releaseParams: { releaseType: "all_signed" },
							recipientsCommitment: `0x${"cc".repeat(32)}` as `0x${string}`,
							onChainRuleId: "1",
							releaseContractAddress:
								"0x0000000000000000000000000000000000000002" as `0x${string}`,
							registerRuleTxHash: `0x${"dd".repeat(32)}` as `0x${string}`,
							packetContentHash,
							releaseTxHash: `0x${"ee".repeat(32)}` as `0x${string}`,
							recipientCount: 1,
							unlocked: true,
							cancelled: false,
						},
					],
				},
				manifest: testManifest,
				bundleSha256Sidecar: bundleHash,
				documentMerkleProofs: null,
				originalDocuments: {},
				attachmentManifest: null,
				originalAttachments: {},
			},
			summary: summaryFromChecks([
				{
					id: "chain.attachment.pkt-1.exists",
					tier: "chain",
					status: "pass",
				},
				{
					id: "documents.attachments.pkt-1.exhibit.txt.sha256",
					tier: "documents",
					status: "pass",
					expected: fileHash,
					actual: fileHash,
				},
				{
					id: "documents.attachments.pkt-1.packetContentHash",
					tier: "documents",
					status: "pass",
					expected: packetContentHash,
					actual: packetContentHash,
				},
			]),
		});

		const attached = report.sections.find(
			(section) => section.title === "Attached files",
		);
		expect(attached).toBeDefined();
		expect(
			attached?.rows.some(
				(row) => row.claim === "Attachment file: exhibit.txt",
			),
		).toBe(true);
		expect(
			attached?.rows.some(
				(row) => row.claim === "Attachment pkt-1 file bundle hash",
			),
		).toBe(true);
	});
});
