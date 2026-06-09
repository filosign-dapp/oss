import type { ComplianceBundle } from "@filosign/protocol";
import { sha256PlaintextHex, stableJsonStringify } from "@filosign/protocol";
import type { CheckResult } from "../types";
import { compareCheck, statusCheck } from "../utils/check";

function sanitizeZipSegment(name: string): string {
	return name.replace(/[/\\]/g, "_").slice(0, 200) || "document";
}

function uint8ToBase64(bytes: Uint8Array): string {
	let binary = "";
	for (const v of bytes) {
		binary += String.fromCharCode(v);
	}
	return btoa(binary);
}

export type AttachmentManifestEntry = {
	packetId: string;
	packetCid: string;
	label: string | null;
	releaseMode: "review" | "conditional";
	unlocked: boolean;
	packetContentHash: string | null;
	files: Array<{
		id: string;
		name: string;
		mimeType: string;
		sha256: string;
	}>;
};

export async function runAttachmentByteChecks(args: {
	bundle: ComplianceBundle;
	manifestEntries: AttachmentManifestEntry[];
	originalAttachments: Record<string, Uint8Array>;
}): Promise<CheckResult[]> {
	const { bundle, manifestEntries, originalAttachments } = args;
	const results: CheckResult[] = [];

	if (bundle.attachments.length === 0) {
		return results;
	}

	if (manifestEntries.length === 0) {
		results.push(
			statusCheck({
				id: "documents.attachments.manifest",
				tier: "documents",
				status: "skip",
				message: "No attachment manifest entries in packet",
			}),
		);
		return results;
	}

	for (const entry of manifestEntries) {
		const bundleRow = bundle.attachments.find(
			(row) => row.packetId === entry.packetId,
		);
		if (!bundleRow) {
			results.push(
				statusCheck({
					id: `documents.attachments.${entry.packetId}.bundleRow`,
					tier: "documents",
					status: "fail",
					message: `Attachment ${entry.packetId} missing from bundle.json`,
				}),
			);
			continue;
		}

		if (entry.files.length === 0) {
			results.push(
				statusCheck({
					id: `documents.attachments.${entry.packetId}.files`,
					tier: "documents",
					status: "skip",
					message: `No decrypted files exported for packet ${entry.packetId}`,
				}),
			);
			continue;
		}

		const fileRows: Array<{
			id: string;
			name: string;
			mimeType: string;
			sha256Plaintext: string;
			bytesB64: string;
		}> = [];

		for (const fileMeta of entry.files) {
			const safeName = sanitizeZipSegment(fileMeta.name);
			const zipPath = `${entry.packetId}/${safeName}`;
			const bytes =
				originalAttachments[zipPath] ??
				originalAttachments[`${entry.packetId}/${fileMeta.name}`] ??
				null;

			if (!bytes) {
				results.push(
					statusCheck({
						id: `documents.attachments.${entry.packetId}.${safeName}`,
						tier: "documents",
						status: "fail",
						message: `Missing attachment file ${zipPath} in packet`,
					}),
				);
				continue;
			}

			const actualHash = await sha256PlaintextHex(bytes);
			results.push(
				compareCheck({
					id: `documents.attachments.${entry.packetId}.${safeName}.sha256`,
					tier: "documents",
					expected: fileMeta.sha256,
					actual: actualHash,
					message: `${fileMeta.name} file hash`,
				}),
			);

			fileRows.push({
				id: fileMeta.id,
				name: fileMeta.name,
				mimeType: fileMeta.mimeType,
				sha256Plaintext: fileMeta.sha256,
				bytesB64: uint8ToBase64(bytes),
			});
		}

		const expectedContentHash =
			entry.packetContentHash ?? bundleRow.packetContentHash;
		if (expectedContentHash && fileRows.length === entry.files.length) {
			const plaintextObj = {
				version: 1 as const,
				packetId: entry.packetId,
				...(entry.label ? { label: entry.label } : {}),
				files: fileRows,
			};
			const plaintextBytes = new TextEncoder().encode(
				stableJsonStringify(plaintextObj),
			);
			const recomputed = await sha256PlaintextHex(plaintextBytes);
			results.push(
				compareCheck({
					id: `documents.attachments.${entry.packetId}.packetContentHash`,
					tier: "documents",
					expected: expectedContentHash,
					actual: recomputed,
					message: "Attachment packet plaintext hash",
				}),
			);
		}
	}

	return results;
}
