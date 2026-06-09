import type { ComplianceBundle } from "@filosign/protocol";
import type { Address, Hex } from "viem";

export type EnvelopeRegistrationView = {
	cidIdentifier: Hex;
	sender: Address;
	signersCommitment: Hex;
	viewersCommitment: Hex;
	placementCommitment: Hex;
	documentSha256: Hex;
	senderEmailCommitment: Hex;
	senderAuthSubjectCommitment: Hex;
	requiredSignersCount: number;
	requiredSignaturesCount: number;
	signaturesCount: number;
	quorumN: number;
	routingMode: number;
	routingOrderHash: Hex;
	quorumSetHash: Hex;
	timestamp: bigint;
	orgIdCommitment: Hex;
	completedAt: number;
	revokedBeforeCompletedAt: number;
	revokedBy: Address;
};

export function registryAddressFromBundle(
	bundle: ComplianceBundle,
): Address | null {
	const registrationTx = bundle.transactions.find(
		(transaction) => transaction.kind === "file_registered",
	);
	return registrationTx?.contractAddress ?? null;
}
