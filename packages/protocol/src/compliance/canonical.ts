import type { ComplianceBundle } from "./bundle";

function sortKeysDeep(value: unknown): unknown {
	if (value === null || typeof value !== "object") {
		return value;
	}
	if (Array.isArray(value)) {
		return value.map(sortKeysDeep);
	}
	const obj = value as Record<string, unknown>;
	const sorted: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) {
		sorted[key] = sortKeysDeep(obj[key]);
	}
	return sorted;
}

export function canonicalComplianceBundleJson(
	bundle: ComplianceBundle,
): string {
	const sorted = sortKeysDeep(bundle) as ComplianceBundle;
	return JSON.stringify(sorted);
}

/** SHA-256 of canonical bundle JSON as 0x-prefixed hex (matches private export hash). */
export async function complianceBundleSha256Hex(
	bundle: ComplianceBundle,
): Promise<`0x${string}`> {
	const canonical = canonicalComplianceBundleJson(bundle);
	const bytes = new TextEncoder().encode(canonical);
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	const hex = [...new Uint8Array(digest)]
		.map((byte) => byte.toString(16).padStart(2, "0"))
		.join("");
	return `0x${hex}`;
}
