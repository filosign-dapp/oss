import { envelopeRegistryAbi } from "@filosign/contracts/abis";
import {
	chainDisplayName,
	chainForViem,
	defaultRpcUrlForChain,
	explorerTxUrl,
} from "@filosign/contracts/chains";
import type { ComplianceBundle } from "@filosign/protocol";
import { computeCidIdentifier } from "@filosign/protocol";
import {
	type Address,
	BaseError,
	ContractFunctionExecutionError,
	createPublicClient,
	getAddress,
	type Hex,
	http,
} from "viem";
import type { CheckResult } from "../types";
import {
	bytes20Hex,
	compareCheck,
	statusCheck,
	summarizeChecks,
} from "../utils/check";
import type { EnvelopeRegistrationView } from "../utils/registry";
import {
	attachmentTxHashes,
	runAttachmentChainChecks,
} from "./chain-attachments";
import { runSignerBindingChecks } from "./chain-signer-binding";
import {
	runSettlementChainChecks,
	settlementTxHashes,
} from "./chain-settlements";

function chainRpcMismatchMessage(args: {
	bundleChainId: number;
	rpcChainId: number;
	rpcUrl: string;
}): string {
	const suggested = defaultRpcUrlForChain(args.bundleChainId);
	const packetChain = chainDisplayName(args.bundleChainId);
	const rpcChain = chainDisplayName(args.rpcChainId);
	return [
		`RPC chain is ${rpcChain} (${args.rpcChainId}) but the packet is ${packetChain} (${args.bundleChainId}).`,
		suggested
			? `Use ${suggested} for this packet (currently ${args.rpcUrl}).`
			: `Point RPC URL at ${packetChain} and try again.`,
	].join(" ");
}

function contractReadFailureMessage(
	error: unknown,
	registryAddress: Address,
): string {
	if (error instanceof ContractFunctionExecutionError) {
		return [
			`Could not read envelopeRegistrations at ${registryAddress}.`,
			"Wrong RPC URL for this packet, registry not deployed, or Hardhat node was reset.",
		].join(" ");
	}
	if (error instanceof BaseError) {
		return error.shortMessage;
	}
	if (error instanceof Error) {
		return error.message;
	}
	return "On-chain read failed";
}

export async function runChainChecks(args: {
	bundle: ComplianceBundle;
	rpcUrl: string;
	registryAddress: Address;
}): Promise<CheckResult[]> {
	const { bundle, rpcUrl, registryAddress } = args;
	const results: CheckResult[] = [];
	const client = createPublicClient({
		chain: chainForViem(bundle.chainId),
		transport: http(rpcUrl),
	});

	try {
		const rpcChainId = await client.getChainId();
		if (rpcChainId !== bundle.chainId) {
			return [
				statusCheck({
					id: "chain.rpc.chainId",
					tier: "chain",
					status: "fail",
					message: chainRpcMismatchMessage({
						bundleChainId: bundle.chainId,
						rpcChainId,
						rpcUrl,
					}),
				}),
			];
		}
	} catch (error) {
		return [
			statusCheck({
				id: "chain.rpc.connect",
				tier: "chain",
				status: "fail",
				message:
					error instanceof Error
						? `Could not reach RPC ${rpcUrl}: ${error.message}`
						: `Could not reach RPC ${rpcUrl}`,
			}),
		];
	}

	const cidIdentifier = computeCidIdentifier(bundle.pieceCid);
	const snapshot = bundle.onchainRegistration;

	let reg: EnvelopeRegistrationView;
	try {
		reg = (await client.readContract({
			address: registryAddress,
			abi: envelopeRegistryAbi,
			functionName: "envelopeRegistrations",
			args: [cidIdentifier as Hex],
		})) as EnvelopeRegistrationView;
	} catch (error) {
		return [
			statusCheck({
				id: "chain.registration.read",
				tier: "chain",
				status: "fail",
				message: contractReadFailureMessage(error, registryAddress),
			}),
		];
	}

	if (Number(reg.timestamp) === 0) {
		return [
			statusCheck({
				id: "chain.registration.exists",
				tier: "chain",
				status: "fail",
				message: "No envelope registration on-chain for this pieceCid",
			}),
		];
	}

	results.push(
		statusCheck({
			id: "chain.registration.exists",
			tier: "chain",
			status: "pass",
		}),
	);

	const rows: Array<{
		id: string;
		expected: string;
		actual: string;
		bytes20?: boolean;
	}> = [
		{
			id: "chain.registration.cidIdentifier",
			expected: snapshot?.cidIdentifier ?? cidIdentifier,
			actual: reg.cidIdentifier,
		},
		{
			id: "chain.registration.sender",
			expected: snapshot?.sender ?? bundle.registration.sender,
			actual: getAddress(reg.sender),
		},
		{
			id: "chain.registration.placementCommitment",
			expected: snapshot?.placementCommitment ?? bundle.placementCommitment,
			actual: reg.placementCommitment,
		},
		{
			id: "chain.registration.documentSha256",
			expected:
				snapshot?.documentSha256 ?? bundle.registration.registerDocumentSha256,
			actual: reg.documentSha256,
		},
	];

	if (snapshot?.senderEmailCommitment) {
		rows.push({
			id: "chain.registration.senderEmailCommitment",
			expected: snapshot.senderEmailCommitment,
			actual: reg.senderEmailCommitment,
		});
	}

	if (snapshot?.signersCommitment) {
		rows.push({
			id: "chain.registration.signersCommitment",
			expected: snapshot.signersCommitment,
			actual: String(reg.signersCommitment),
			bytes20: true,
		});
	}

	if (snapshot?.viewersCommitment) {
		rows.push({
			id: "chain.registration.viewersCommitment",
			expected: snapshot.viewersCommitment,
			actual: String(reg.viewersCommitment),
			bytes20: true,
		});
	}

	for (const row of rows) {
		results.push(
			compareCheck({
				id: row.id,
				tier: "chain",
				expected: row.bytes20 ? bytes20Hex(row.expected) : row.expected,
				actual: row.bytes20 ? bytes20Hex(row.actual) : row.actual,
			}),
		);
	}

	if (snapshot) {
		results.push(
			compareCheck({
				id: "chain.registration.requiredSignersCount",
				tier: "chain",
				expected: String(snapshot.requiredSignersCount),
				actual: String(reg.requiredSignersCount),
			}),
			compareCheck({
				id: "chain.registration.signaturesCount",
				tier: "chain",
				expected: String(snapshot.signaturesCount),
				actual: String(reg.signaturesCount),
			}),
			compareCheck({
				id: "chain.registration.timestamp",
				tier: "chain",
				expected: snapshot.timestamp,
				actual: reg.timestamp.toString(),
			}),
		);
	}

	results.push(
		...(await runSettlementChainChecks({ bundle, client })),
		...(await runAttachmentChainChecks({ bundle, client })),
	);

	const txHashes = new Set<Hex>();
	txHashes.add(bundle.registration.registrationTxHash);
	for (const signer of bundle.signers) {
		if (signer.onchainTxHash) txHashes.add(signer.onchainTxHash);
	}
	for (const hash of settlementTxHashes(bundle)) {
		txHashes.add(hash);
	}
	for (const hash of attachmentTxHashes(bundle)) {
		txHashes.add(hash);
	}

	const receiptCache = new Map<
		Hex,
		Awaited<ReturnType<typeof client.getTransactionReceipt>>
	>();
	const getReceipt = async (txHash: Hex) => {
		const cached = receiptCache.get(txHash);
		if (cached) return cached;
		const receipt = await client.getTransactionReceipt({ hash: txHash });
		receiptCache.set(txHash, receipt);
		return receipt;
	};

	for (const txHash of txHashes) {
		try {
			const receipt = await getReceipt(txHash);
			results.push({
				id: `chain.tx.${txHash.slice(2, 10)}`,
				tier: "chain",
				status: receipt.status === "success" ? "pass" : "fail",
				message: `Receipt ${receipt.status} at block ${receipt.blockNumber}`,
				explorerUrl: explorerTxUrl(bundle.chainId, txHash),
			});
		} catch (error) {
			results.push(
				statusCheck({
					id: `chain.tx.${txHash.slice(2, 10)}`,
					tier: "chain",
					status: "fail",
					message:
						error instanceof Error
							? `Could not fetch receipt for ${txHash}: ${error.message}`
							: `Could not fetch receipt for ${txHash}`,
				}),
			);
		}
	}

	results.push(
		...(await runSignerBindingChecks({
			bundle,
			client,
			registryAddress,
			cidIdentifier: cidIdentifier as Hex,
			getReceipt,
		})),
	);

	return results;
}

export async function verifyChain(args: {
	bundle: ComplianceBundle;
	rpcUrl: string;
	registryAddress: Address;
}) {
	return summarizeChecks(await runChainChecks(args));
}
