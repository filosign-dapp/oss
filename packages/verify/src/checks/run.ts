import { defaultRpcUrlForChain } from "@filosign/contracts/chains";
import type { Address } from "viem";
import { parsePacket } from "../parse/packet";
import type { CheckTier, VerifyPacketOptions, VerifySummary } from "../types";
import { summarizeChecks } from "../utils/check";
import { registryAddressFromBundle } from "../utils/registry";
import { runChainChecks } from "./chain";
import { runAttachmentByteChecks } from "./attachments-bytes";
import { runDocumentChecks } from "./documents";
import { runLocalChecks } from "./local";

export { verifyChain } from "./chain";
export { verifyDocuments } from "./documents";
export { verifyLocal } from "./local";

const DEFAULT_TIERS: CheckTier[] = ["local", "chain", "documents"];

export async function verifyPacket(
	options: VerifyPacketOptions,
): Promise<VerifySummary> {
	const parsed = parsePacket(options.zipBytes);
	const tiers = options.tiers ?? DEFAULT_TIERS;
	const results = [];

	if (tiers.includes("local")) {
		results.push(
			...(await runLocalChecks({
				bundle: parsed.bundle,
				bundleSha256Sidecar: parsed.bundleSha256Sidecar,
				manifest: parsed.manifest,
			})),
		);
	}

	if (tiers.includes("chain")) {
		const registryAddress =
			parsed.manifest.registryAddress ??
			registryAddressFromBundle(parsed.bundle);
		const rpcUrl =
			options.rpcUrl?.trim() ||
			defaultRpcUrlForChain(parsed.bundle.chainId) ||
			null;

		if (!rpcUrl) {
			results.push({
				id: "chain.rpc",
				tier: "chain" as const,
				status: "skip" as const,
				message: "Provide an RPC URL to run on-chain checks",
			});
		} else if (!registryAddress) {
			results.push({
				id: "chain.registryAddress",
				tier: "chain" as const,
				status: "skip" as const,
				message: "No registry address in manifest or bundle transactions",
			});
		} else {
			results.push(
				...(await runChainChecks({
					bundle: parsed.bundle,
					rpcUrl,
					registryAddress: registryAddress as Address,
				})),
			);
		}
	}

	if (tiers.includes("documents")) {
		if (!parsed.documentMerkleProofs) {
			results.push({
				id: "documents.merkleProofs",
				tier: "documents" as const,
				status: "skip" as const,
				message: "No document Merkle proofs file in packet",
			});
		} else {
			results.push(
				...(await runDocumentChecks({
					bundle: parsed.bundle,
					documentMerkleProofs: parsed.documentMerkleProofs,
					originalDocuments: parsed.originalDocuments,
				})),
			);
			if (parsed.bundle.attachments.length > 0) {
				results.push(
					...(await runAttachmentByteChecks({
						bundle: parsed.bundle,
						manifestEntries: parsed.attachmentManifest?.attachments ?? [],
						originalAttachments: parsed.originalAttachments,
					})),
				);
			}
		}
	}

	return summarizeChecks(results);
}
