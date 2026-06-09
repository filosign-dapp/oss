import { describe, expect, it } from "bun:test";
import { envelopeRegistryAbi } from "@filosign/contracts/abis";
import {
	type ComplianceBundle,
	computePlacementCommitment,
	hashNormalizedSignerEmail,
} from "@filosign/protocol";
import {
	type Address,
	encodeAbiParameters,
	encodeEventTopics,
	getAddress,
	type Hex,
	parseAbiParameters,
	type TransactionReceipt,
} from "viem";
import { runSignerBindingChecks } from "../src/checks/chain-signer-binding";
import {
	parseEnvelopeSignedEvents,
	resolveSignerEmailCommitment,
} from "../src/utils/signer-chain";

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
			assignedRecipientEmail: "signer@example.com",
			required: true,
			type: "signature" as const,
		},
	],
};

const sender = "0x0000000000000000000000000000000000000001" as Address;
const signerWallet = "0x0000000000000000000000000000000000000002" as Address;
const registryAddress = "0x0000000000000000000000000000000000000abc" as Address;
const cidIdentifier = `0x${"11".repeat(32)}` as Hex;
const signTxHash = `0x${"55".repeat(32)}` as Hex;
const emailCommitment = hashNormalizedSignerEmail("signer@example.com");

function signedBundle(overrides?: {
	signerWallet?: Address;
	onchainTxHash?: Hex | null;
}): ComplianceBundle {
	return {
		version: 1,
		pieceCid: "bafyTEST",
		chainId: 84532,
		exportedAtIso: "2026-01-01T00:00:00.000Z",
		executionStatus: "fully_executed",
		placementCommitment: computePlacementCommitment(placementManifest),
		placementManifest,
		registration: {
			sender,
			registrationTxHash: `0x${"bb".repeat(32)}`,
			createdAtIso: "2026-01-01T00:00:00.000Z",
			registerDocumentSha256: `0x${"cc".repeat(32)}`,
		},
		parties: [
			{
				role: "signer",
				wallet: overrides?.signerWallet ?? signerWallet,
				email: "signer@example.com",
				displayName: "Signer",
				emailCommitment,
				authSubjectCommitment: null,
			},
		],
		onchainRegistration: null,
		transactions: [],
		signers: [
			{
				wallet: overrides?.signerWallet ?? signerWallet,
				displayName: "Signer",
				email: "signer@example.com",
				signed: true,
				assignedFieldIds: ["f1"],
				requiredFieldIds: ["f1"],
				optionalFieldIds: [],
				onchainTxHash: overrides?.onchainTxHash ?? signTxHash,
				signedAtIso: "2026-01-01T00:00:00.000Z",
				messageTimestampIso: "2026-01-01T00:00:00.000Z",
				blockTimestampFromTx: null,
				completedFieldIds: ["f1"],
				completionsRoot: `0x${"66".repeat(32)}`,
				leafSchemaVersion: 1,
				merkleProofs: [],
				draftCompletedFieldIds: [],
				acknowledgedAtIso: null,
				firstViewedAtIso: null,
			},
		],
		settlements: [],
		attachments: [],
		offChainEvidence: {
			acknowledgements: [],
			documentViews: [],
			coldInviteClaims: [],
			payoutRecipientAcknowledgements: [],
		},
	};
}

function envelopeSignedReceipt(args: {
	signerWallet: Address;
	sender?: Address;
}): TransactionReceipt {
	const eventSender = args.sender ?? sender;
	const topics = encodeEventTopics({
		abi: envelopeRegistryAbi,
		eventName: "EnvelopeSigned",
		args: {
			cidIdentifier,
			sender: eventSender,
			signerWallet: args.signerWallet,
		},
	});
	const data = encodeAbiParameters(
		parseAbiParameters("uint48 timestamp"),
		[1_700_000_000],
	);
	return {
		blockHash: `0x${"aa".repeat(32)}`,
		blockNumber: 1n,
		contractAddress: registryAddress,
		cumulativeGasUsed: 1n,
		effectiveGasPrice: 1n,
		from: sender,
		gasUsed: 1n,
		logs: [
			{
				address: registryAddress,
				blockHash: `0x${"aa".repeat(32)}`,
				blockNumber: 1n,
				data,
				logIndex: 0,
				transactionHash: signTxHash,
				transactionIndex: 0,
				removed: false,
				topics: topics as [`0x${string}`, ...`0x${string}`[]],
			},
		],
		logsBloom: `0x${"00".repeat(256)}`,
		status: "success",
		to: registryAddress,
		transactionHash: signTxHash,
		transactionIndex: 0,
		type: "eip1559",
	} satisfies TransactionReceipt;
}

describe("resolveSignerEmailCommitment", () => {
	it("prefers matching signer party row", () => {
		const bundle = signedBundle();
		const signer = bundle.signers[0];
		expect(signer).toBeDefined();
		const resolved = resolveSignerEmailCommitment({
			bundle,
			signer: signer as NonNullable<typeof signer>,
		});
		expect(resolved.ok).toBe(true);
		if (resolved.ok) {
			expect(resolved.emailCommitment).toBe(emailCommitment);
			expect(resolved.source).toBe("party");
		}
	});

	it("falls back to signer email when party row is missing", () => {
		const bundle = signedBundle();
		const signer = bundle.signers[0];
		expect(signer).toBeDefined();
		const resolved = resolveSignerEmailCommitment({
			bundle: { ...bundle, parties: [] },
			signer: signer as NonNullable<typeof signer>,
		});
		expect(resolved.ok).toBe(true);
		if (resolved.ok) {
			expect(resolved.emailCommitment).toBe(emailCommitment);
			expect(resolved.source).toBe("signerEmail");
		}
	});
});

describe("parseEnvelopeSignedEvents", () => {
	it("extracts EnvelopeSigned wallet for this envelope", () => {
		const events = parseEnvelopeSignedEvents({
			receipt: envelopeSignedReceipt({ signerWallet }),
			registryAddress,
			cidIdentifier,
		});
		expect(events).toHaveLength(1);
		const event = events[0];
		if (!event) throw new Error("expected EnvelopeSigned event");
		expect(getAddress(event.signerWallet)).toBe(getAddress(signerWallet));
	});
});

describe("runSignerBindingChecks", () => {
	it("passes when hasSigned, bound wallet, and EnvelopeSigned log align", async () => {
		const bundle = signedBundle();
		const receipt = envelopeSignedReceipt({ signerWallet });
		const client = {
			readContract: async ({ functionName }: { functionName: string }) => {
				if (functionName === "hasSigned") return true;
				if (functionName === "boundSignerWallet") return signerWallet;
				throw new Error(`unexpected read ${functionName}`);
			},
			getTransactionReceipt: async () => receipt,
		};

		const results = await runSignerBindingChecks({
			bundle,
			client: client as unknown as Parameters<
				typeof runSignerBindingChecks
			>[0]["client"],
			registryAddress,
			cidIdentifier,
			getReceipt: async () => receipt,
		});

		expect(results.find((r) => r.id.endsWith(".hasSigned"))?.status).toBe(
			"pass",
		);
		expect(results.find((r) => r.id.endsWith(".boundWallet"))?.status).toBe(
			"pass",
		);
		expect(
			results.find((r) => r.id.endsWith(".envelopeSignedEvent"))?.status,
		).toBe("pass");
	});

	it("fails when bundle wallet does not match EnvelopeSigned log", async () => {
		const wrongWallet = "0x0000000000000000000000000000000000000099" as Address;
		const bundle = signedBundle({ signerWallet: wrongWallet });
		const receipt = envelopeSignedReceipt({ signerWallet });
		const client = {
			readContract: async ({ functionName }: { functionName: string }) => {
				if (functionName === "hasSigned") return true;
				if (functionName === "boundSignerWallet") return wrongWallet;
				throw new Error(`unexpected read ${functionName}`);
			},
			getTransactionReceipt: async () => receipt,
		};

		const results = await runSignerBindingChecks({
			bundle,
			client: client as unknown as Parameters<
				typeof runSignerBindingChecks
			>[0]["client"],
			registryAddress,
			cidIdentifier,
			getReceipt: async () => receipt,
		});

		expect(
			results.find((r) => r.id.endsWith(".envelopeSignedEvent"))?.status,
		).toBe("fail");
	});
});
