import type { Hex } from "viem";
import { concatHex, keccak256, ripemd160, stringToBytes } from "viem";
import { normalizePlacementRecipientEmail } from "../placement/manifest";

export function hashNormalizedSignerEmail(email: string): Hex {
	const normalized = normalizePlacementRecipientEmail(email);
	return keccak256(stringToBytes(`filosign:signer-email:v1:${normalized}`));
}

function sortBytes32Asc(values: Hex[]): Hex[] {
	return [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

export function emailCommitRoot(sorted: Hex[]): Hex {
	if (!sorted.length) {
		return "0x0000000000000000000000000000000000000000";
	}
	return ripemd160(concatHex(sorted));
}

export function sortedCommitsForEmails(emails: Iterable<string>): Hex[] {
	const seen = new Set<string>();
	const list: string[] = [];
	for (const email of emails) {
		const normalized = normalizePlacementRecipientEmail(email);
		if (!seen.has(normalized)) {
			seen.add(normalized);
			list.push(normalized);
		}
	}
	return sortBytes32Asc(list.map(hashNormalizedSignerEmail));
}

export function commitsForEmails(emails: Iterable<string>): Hex[] {
	const seen = new Set<string>();
	const list: string[] = [];
	for (const email of emails) {
		const normalized = normalizePlacementRecipientEmail(email);
		if (!seen.has(normalized)) {
			seen.add(normalized);
			list.push(normalized);
		}
	}
	return list.map(hashNormalizedSignerEmail);
}
