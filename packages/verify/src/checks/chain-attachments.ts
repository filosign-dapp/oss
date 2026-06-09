import { attachmentReleaseAbi } from "@filosign/contracts/abis";
import type { ComplianceBundle } from "@filosign/protocol";
import { computeCidIdentifier } from "@filosign/protocol";
import { type Hex, type PublicClient } from "viem";
import type { CheckResult } from "../types";
import { compareCheck, statusCheck } from "../utils/check";

export async function runAttachmentChainChecks(args: {
	bundle: ComplianceBundle;
	client: PublicClient;
}): Promise<CheckResult[]> {
	const { bundle, client } = args;
	const results: CheckResult[] = [];
	const cidIdentifier = computeCidIdentifier(bundle.pieceCid);

	for (const att of bundle.attachments) {
		if (!att.onChainRuleId || !att.releaseContractAddress) {
			continue;
		}

		const ruleId = BigInt(att.onChainRuleId);
		try {
			const rule = (await client.readContract({
				address: att.releaseContractAddress,
				abi: attachmentReleaseAbi,
				functionName: "rules",
				args: [ruleId],
			})) as [
				string,
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
				onchainCidId,
				_sender,
				packetContentHash,
				_recipientsCommitment,
				_releaseType,
				_specificSignerCommitment,
				_thresholdN,
				_expiresAt,
				released,
				_cancelled,
			] = rule;

			results.push(
				statusCheck({
					id: `chain.attachment.${att.packetId}.exists`,
					tier: "chain",
					status: "pass",
					message: `Attachment rule for ${att.packetId} exists on-chain`,
				}),
				compareCheck({
					id: `chain.attachment.${att.packetId}.packetContentHash`,
					tier: "chain",
					expected: att.packetContentHash ?? "0x",
					actual: packetContentHash,
				}),
				compareCheck({
					id: `chain.attachment.${att.packetId}.cidId`,
					tier: "chain",
					expected: cidIdentifier,
					actual: onchainCidId,
				}),
				compareCheck({
					id: `chain.attachment.${att.packetId}.released`,
					tier: "chain",
					expected: att.unlocked ? "true" : "false",
					actual: String(released),
				}),
			);
		} catch (error) {
			results.push(
				statusCheck({
					id: `chain.attachment.${att.packetId}.read`,
					tier: "chain",
					status: "fail",
					message: `Could not read attachment rule for ${att.packetId} from release contract: ${error instanceof Error ? error.message : String(error)}`,
				}),
			);
		}
	}

	return results;
}

export function attachmentTxHashes(bundle: ComplianceBundle): Hex[] {
	const hashes: Hex[] = [];
	for (const att of bundle.attachments) {
		if (att.registerRuleTxHash) hashes.push(att.registerRuleTxHash);
		if (att.releaseTxHash) hashes.push(att.releaseTxHash);
	}
	return hashes;
}
