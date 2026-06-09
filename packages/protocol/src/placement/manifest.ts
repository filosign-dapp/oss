import type { Hex } from "viem";
import { keccak256, stringToBytes } from "viem";
import { z } from "zod";
import { stableJsonStringify } from "../json/stable-stringify";

export const zRectNormalized = z.object({
	x: z.number().min(0).max(1),
	y: z.number().min(0).max(1),
	width: z.number().min(0).max(1),
	height: z.number().min(0).max(1),
});

export function normalizePlacementRecipientEmail(email: string): string {
	return email.trim().toLowerCase();
}

export const zPlacementFieldBase = z.object({
	id: z.string().min(1),
	pageIndex: z.number().int().min(0),
	rect: zRectNormalized,
	assignedRecipientEmail: z
		.email()
		.transform((e) => normalizePlacementRecipientEmail(e)),
	required: z.boolean(),
	type: z.enum([
		"signature",
		"initial",
		"date",
		"name",
		"email",
		"text",
		"checkbox",
	]),
});

export const zPlacementField = zPlacementFieldBase.extend({
	documentId: z.string().min(1),
});

export const zPlacementDocument = z.object({
	id: z.string().min(1),
	name: z.string().min(1),
	sha256Plaintext: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
	pageCount: z.number().int().min(1),
});

export const zPlacementManifest = z.object({
	version: z.literal(1),
	documents: z.array(zPlacementDocument).min(1),
	fields: z.array(zPlacementField).min(1),
});

export type PlacementManifest = z.infer<typeof zPlacementManifest>;
export type PlacementField = z.infer<typeof zPlacementField>;
export type PlacementDocument = z.infer<typeof zPlacementDocument>;

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

export function canonicalPlacementManifestJson(
	manifest: PlacementManifest,
): string {
	const parsed = zPlacementManifest.parse(manifest);
	return stableJsonStringify(sortKeysDeep(parsed));
}

export function computePlacementCommitment(manifest: PlacementManifest): Hex {
	return keccak256(stringToBytes(canonicalPlacementManifestJson(manifest)));
}

export function uniqueSignerEmailsFromManifest(
	manifest: PlacementManifest,
): string[] {
	const seen = new Set<string>();
	for (const field of manifest.fields) {
		seen.add(field.assignedRecipientEmail);
	}
	return [...seen];
}
