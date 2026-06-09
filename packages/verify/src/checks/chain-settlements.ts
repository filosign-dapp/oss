import { paymentValidatorAbi } from "@filosign/contracts/abis";
import type { ComplianceBundle } from "@filosign/protocol";
import { computeCidIdentifier } from "@filosign/protocol";
import { getAddress, type Hex, type PublicClient } from "viem";
import type { CheckResult } from "../types";
import { compareCheck, statusCheck } from "../utils/check";

export async function runSettlementChainChecks(args: {
	bundle: ComplianceBundle;
	client: PublicClient;
}): Promise<CheckResult[]> {
	const { bundle, client } = args;
	const results: CheckResult[] = [];
	const cidIdentifier = computeCidIdentifier(bundle.pieceCid);

	for (const pay of bundle.settlements) {
		const ruleId = BigInt(pay.onChainRuleId);
		try {
			const rule = (await client.readContract({
				address: pay.validatorAddress,
				abi: paymentValidatorAbi,
				functionName: "rules",
				args: [ruleId],
			})) as [
				string,
				string,
				string,
				number,
				string,
				number,
				bigint,
				boolean,
				boolean,
			];

			const [
				_payer,
				token,
				onchainCidId,
				_releaseType,
				_specificSignerCommitment,
				_thresholdN,
				_expiresAt,
				executed,
				_cancelled,
			] = rule;

			results.push(
				statusCheck({
					id: `chain.settlement.${pay.onChainRuleId}.exists`,
					tier: "chain",
					status: "pass",
					message: `Settlement rule ${pay.onChainRuleId} exists on-chain`,
				}),
				compareCheck({
					id: `chain.settlement.${pay.onChainRuleId}.token`,
					tier: "chain",
					expected: getAddress(pay.tokenAddress),
					actual: getAddress(token),
				}),
				compareCheck({
					id: `chain.settlement.${pay.onChainRuleId}.cidId`,
					tier: "chain",
					expected: cidIdentifier,
					actual: onchainCidId,
				}),
				compareCheck({
					id: `chain.settlement.${pay.onChainRuleId}.status`,
					tier: "chain",
					expected: pay.status === "executed" ? "true" : "false",
					actual: String(executed),
				}),
			);
		} catch (error) {
			results.push(
				statusCheck({
					id: `chain.settlement.${pay.onChainRuleId}.read`,
					tier: "chain",
					status: "fail",
					message: `Could not read settlement rule ${pay.onChainRuleId} from validator: ${error instanceof Error ? error.message : String(error)}`,
				}),
			);
		}
	}

	return results;
}

export function settlementTxHashes(bundle: ComplianceBundle): Hex[] {
	const hashes: Hex[] = [];
	for (const pay of bundle.settlements) {
		if (pay.registerRuleTxHash) hashes.push(pay.registerRuleTxHash);
		if (pay.approveTxHash) hashes.push(pay.approveTxHash);
		if (pay.payoutTxHash) hashes.push(pay.payoutTxHash);
	}
	return hashes;
}
