import { envelopeRegistryAbi } from "@filosign/contracts/abis";
import type { ComplianceBundle } from "@filosign/protocol";
import {
	type Address,
	getAddress,
	type Hex,
	type PublicClient,
	type TransactionReceipt,
} from "viem";
import type { CheckResult } from "../types";
import { compareCheck, statusCheck } from "../utils/check";
import {
	parseEnvelopeSignedEvents,
	resolveSignerEmailCommitment,
} from "../utils/signer-chain";

type SignerBindingClient = Pick<
	PublicClient,
	"readContract" | "getTransactionReceipt"
>;

export async function runSignerBindingChecks(args: {
	bundle: ComplianceBundle;
	client: SignerBindingClient;
	registryAddress: Address;
	cidIdentifier: Hex;
	getReceipt: (txHash: Hex) => Promise<TransactionReceipt>;
}): Promise<CheckResult[]> {
	const { bundle, client, registryAddress, cidIdentifier, getReceipt } = args;
	const results: CheckResult[] = [];

	for (const [index, signer] of bundle.signers.entries()) {
		const baseId = `chain.signers[${index}]`;
		const resolved = resolveSignerEmailCommitment({ bundle, signer });

		if (!resolved.ok) {
			if (signer.signed) {
				results.push(
					statusCheck({
						id: `${baseId}.emailCommitment`,
						tier: "chain",
						status: "fail",
						message: resolved.reason,
					}),
				);
			} else {
				results.push(
					statusCheck({
						id: `${baseId}.emailCommitment`,
						tier: "chain",
						status: "skip",
						message: resolved.reason,
					}),
				);
			}
			continue;
		}

		const emailCommitment = resolved.emailCommitment;
		let hasSigned = false;
		let boundWallet: Address = "0x0000000000000000000000000000000000000000";

		try {
			hasSigned = (await client.readContract({
				address: registryAddress,
				abi: envelopeRegistryAbi,
				functionName: "hasSigned",
				args: [cidIdentifier, emailCommitment],
			})) as boolean;
		} catch (error) {
			results.push(
				statusCheck({
					id: `${baseId}.hasSigned`,
					tier: "chain",
					status: "fail",
					message:
						error instanceof Error
							? `Could not read hasSigned: ${error.message}`
							: "Could not read hasSigned",
				}),
			);
			continue;
		}

		results.push(
			compareCheck({
				id: `${baseId}.hasSigned`,
				tier: "chain",
				expected: String(signer.signed),
				actual: String(hasSigned),
				message: signer.signed
					? "Email slot is marked signed on-chain"
					: "Email slot is not signed on-chain",
			}),
		);

		if (!signer.signed) {
			continue;
		}

		try {
			boundWallet = (await client.readContract({
				address: registryAddress,
				abi: envelopeRegistryAbi,
				functionName: "boundSignerWallet",
				args: [cidIdentifier, emailCommitment],
			})) as Address;
		} catch (error) {
			results.push(
				statusCheck({
					id: `${baseId}.boundWallet`,
					tier: "chain",
					status: "fail",
					message:
						error instanceof Error
							? `Could not read boundSignerWallet: ${error.message}`
							: "Could not read boundSignerWallet",
				}),
			);
			continue;
		}

		results.push(
			compareCheck({
				id: `${baseId}.boundWallet`,
				tier: "chain",
				expected: getAddress(signer.wallet),
				actual: getAddress(boundWallet),
				message: "Bound wallet for email slot matches bundle signer",
			}),
		);

		if (!signer.onchainTxHash) {
			results.push(
				statusCheck({
					id: `${baseId}.envelopeSignedEvent`,
					tier: "chain",
					status: "warn",
					message:
						"Signer marked signed but bundle has no onchainTxHash; skipped EnvelopeSigned log check",
				}),
			);
			continue;
		}

		let receipt: TransactionReceipt;
		try {
			receipt = await getReceipt(signer.onchainTxHash as Hex);
		} catch (error) {
			results.push(
				statusCheck({
					id: `${baseId}.envelopeSignedEvent`,
					tier: "chain",
					status: "fail",
					message:
						error instanceof Error
							? `Could not fetch sign tx receipt: ${error.message}`
							: "Could not fetch sign tx receipt",
				}),
			);
			continue;
		}

		const signedEvents = parseEnvelopeSignedEvents({
			receipt,
			registryAddress,
			cidIdentifier,
		});
		const matchingEvent = signedEvents.find(
			(event) =>
				getAddress(event.signerWallet).toLowerCase() ===
				getAddress(signer.wallet).toLowerCase(),
		);

		if (!matchingEvent) {
			results.push(
				statusCheck({
					id: `${baseId}.envelopeSignedEvent`,
					tier: "chain",
					status: "fail",
					message:
						signedEvents.length === 0
							? "Sign transaction has no EnvelopeSigned log for this envelope"
							: "Sign transaction EnvelopeSigned wallet does not match bundle signer",
				}),
			);
			continue;
		}

		results.push(
			compareCheck({
				id: `${baseId}.envelopeSignedEvent.sender`,
				tier: "chain",
				expected: getAddress(bundle.registration.sender),
				actual: getAddress(matchingEvent.sender),
				message: "EnvelopeSigned sender matches bundle registration sender",
			}),
		);

		results.push(
			statusCheck({
				id: `${baseId}.envelopeSignedEvent`,
				tier: "chain",
				status: "pass",
				message: "EnvelopeSigned log matches bundle signer wallet",
			}),
		);
	}

	return results;
}
