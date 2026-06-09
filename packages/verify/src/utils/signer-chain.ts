import { envelopeRegistryAbi } from "@filosign/contracts/abis";
import type { ComplianceBundle, SignerComplianceRow } from "@filosign/protocol";
import { hashNormalizedSignerEmail } from "@filosign/protocol";
import {
	type Address,
	getAddress,
	type Hex,
	parseEventLogs,
	type TransactionReceipt,
} from "viem";

export type ResolvedSignerEmailCommitment =
	| { ok: true; emailCommitment: Hex; source: "party" | "signerEmail" }
	| { ok: false; reason: string };

export function resolveSignerEmailCommitment(args: {
	bundle: ComplianceBundle;
	signer: SignerComplianceRow;
}): ResolvedSignerEmailCommitment {
	const walletKey = getAddress(args.signer.wallet).toLowerCase();
	const party = args.bundle.parties.find(
		(row) =>
			row.role === "signer" &&
			getAddress(row.wallet).toLowerCase() === walletKey,
	);
	if (party) {
		return {
			ok: true,
			emailCommitment: party.emailCommitment as Hex,
			source: "party",
		};
	}
	if (args.signer.email?.trim()) {
		return {
			ok: true,
			emailCommitment: hashNormalizedSignerEmail(args.signer.email),
			source: "signerEmail",
		};
	}
	return {
		ok: false,
		reason: "No signer party row or email to derive emailCommitment",
	};
}

export type EnvelopeSignedEvent = {
	signerWallet: Address;
	sender: Address;
	cidIdentifier: Hex;
};

export function parseEnvelopeSignedEvents(args: {
	receipt: TransactionReceipt;
	registryAddress: Address;
	cidIdentifier: Hex;
}): EnvelopeSignedEvent[] {
	const logs = args.receipt.logs.filter(
		(log) =>
			getAddress(log.address).toLowerCase() ===
			getAddress(args.registryAddress).toLowerCase(),
	);
	const parsed = parseEventLogs({
		abi: envelopeRegistryAbi,
		logs,
	});
	const cidKey = args.cidIdentifier.toLowerCase();
	const events: EnvelopeSignedEvent[] = [];
	for (const entry of parsed) {
		if (entry.eventName !== "EnvelopeSigned") continue;
		const eventArgs = entry.args as {
			cidIdentifier?: Hex;
			sender?: Address;
			signerWallet?: Address;
		};
		if (
			!eventArgs.cidIdentifier ||
			!eventArgs.sender ||
			!eventArgs.signerWallet
		) {
			continue;
		}
		if (eventArgs.cidIdentifier.toLowerCase() !== cidKey) continue;
		events.push({
			cidIdentifier: eventArgs.cidIdentifier,
			sender: getAddress(eventArgs.sender),
			signerWallet: getAddress(eventArgs.signerWallet),
		});
	}
	return events;
}
