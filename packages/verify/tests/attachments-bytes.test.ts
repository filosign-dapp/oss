import { describe, expect, it } from "bun:test";
import { sha256PlaintextHex, stableJsonStringify } from "@filosign/protocol";
import { runAttachmentByteChecks } from "../src/checks/attachments-bytes";

describe("attachment byte checks", () => {
	it("passes per-file and packet content hash checks", async () => {
		const bytes = new TextEncoder().encode("attachment payload");
		const fileHash = await sha256PlaintextHex(bytes);
		const plaintextObj = {
			version: 1 as const,
			packetId: "pkt-1",
			label: "Exhibit",
			files: [
				{
					id: "f1",
					name: "exhibit.txt",
					mimeType: "text/plain",
					sha256Plaintext: fileHash,
					bytesB64: btoa(String.fromCharCode(...bytes)),
				},
			],
		};
		const packetContentHash = await sha256PlaintextHex(
			new TextEncoder().encode(stableJsonStringify(plaintextObj)),
		);

		const results = await runAttachmentByteChecks({
			bundle: {
				version: 1,
				pieceCid: "bafyTEST",
				chainId: 84532,
				exportedAtIso: "2026-01-01T00:00:00.000Z",
				executionStatus: "fully_executed",
				placementCommitment: `0x${"11".repeat(32)}`,
				placementManifest: {
					version: 1,
					documents: [],
					fields: [],
				},
				registration: {
					sender: "0x0000000000000000000000000000000000000001",
					registrationTxHash: `0x${"22".repeat(32)}`,
					createdAtIso: "2026-01-01T00:00:00.000Z",
					registerDocumentSha256: `0x${"33".repeat(32)}`,
				},
				parties: [],
				onchainRegistration: null,
				transactions: [],
				signers: [],
				settlements: [],
				attachments: [
					{
						packetId: "pkt-1",
						packetCid: "bafyPACKET",
						label: "Exhibit",
						releaseMode: "conditional",
						releaseType: "all_signed",
						releaseParams: { releaseType: "all_signed" },
						recipientsCommitment: `0x${"44".repeat(32)}`,
						onChainRuleId: "1",
						releaseContractAddress:
							"0x0000000000000000000000000000000000000002",
						registerRuleTxHash: `0x${"55".repeat(32)}`,
						packetContentHash,
						releaseTxHash: `0x${"66".repeat(32)}`,
						recipientCount: 1,
						unlocked: true,
						cancelled: false,
					},
				],
				offChainEvidence: {
					acknowledgements: [],
					documentViews: [],
					coldInviteClaims: [],
					payoutRecipientAcknowledgements: [],
				},
			},
			manifestEntries: [
				{
					packetId: "pkt-1",
					packetCid: "bafyPACKET",
					label: "Exhibit",
					releaseMode: "conditional",
					unlocked: true,
					packetContentHash,
					files: [
						{
							id: "f1",
							name: "exhibit.txt",
							mimeType: "text/plain",
							sha256: fileHash,
						},
					],
				},
			],
			originalAttachments: {
				"pkt-1/exhibit.txt": bytes,
			},
		});

		const fileHashCheck = results.find(
			(result) => result.id === "documents.attachments.pkt-1.exhibit.txt.sha256",
		);
		const packetHashCheck = results.find(
			(result) =>
				result.id === "documents.attachments.pkt-1.packetContentHash",
		);
		expect(fileHashCheck?.status).toBe("pass");
		expect(packetHashCheck?.status).toBe("pass");
	});
});
