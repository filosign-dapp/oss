import {
	type ComplianceBundle,
	zComplianceBundle,
	zVerifyManifestV1,
} from "@filosign/protocol";
import { unzipSync } from "fflate";
import type { AttachmentManifestPayload, ParsedProofPacket } from "../types";
import {
	EXPECTED_MANIFEST_PATH,
	resolvePathsFromManifest,
	validatePacketLayout,
} from "./schemas";

function decodeEntry(
	entries: Record<string, Uint8Array>,
	path: string,
): string {
	const bytes = entries[path];
	if (!bytes) {
		throw new Error(`Missing ${path} in proof packet`);
	}
	return new TextDecoder().decode(bytes);
}

function findManifestPath(entries: Record<string, Uint8Array>): string {
	if (entries[EXPECTED_MANIFEST_PATH]) {
		return EXPECTED_MANIFEST_PATH;
	}
	const fallback = Object.keys(entries).find((path) =>
		path.endsWith("verify-manifest.json"),
	);
	if (!fallback) {
		throw new Error(
			`Missing verify-manifest.json (expected ${EXPECTED_MANIFEST_PATH})`,
		);
	}
	return fallback;
}

export function parsePacket(zipBytes: Uint8Array): ParsedProofPacket {
	const entries = unzipSync(zipBytes);
	const manifestPath = findManifestPath(entries);

	const manifestRaw = JSON.parse(decodeEntry(entries, manifestPath)) as unknown;
	const manifest = zVerifyManifestV1.parse(manifestRaw);

	const paths = resolvePathsFromManifest(manifestPath, manifest);
	validatePacketLayout(entries, paths);

	const bundleRaw = JSON.parse(
		decodeEntry(entries, paths.bundlePath),
	) as unknown;
	const bundle = zComplianceBundle.parse(bundleRaw) satisfies ComplianceBundle;

	const bundleSha256Sidecar = new TextDecoder()
		.decode(entries[paths.bundleHashPath])
		.trim();

	let documentMerkleProofs: ParsedProofPacket["documentMerkleProofs"] = null;
	if (entries[paths.merklePath]) {
		documentMerkleProofs = JSON.parse(
			decodeEntry(entries, paths.merklePath),
		) as ParsedProofPacket["documentMerkleProofs"];
	}

	const originalPrefix = paths.originalPrefix.endsWith("/")
		? paths.originalPrefix
		: `${paths.originalPrefix}/`;

	const originalDocuments: Record<string, Uint8Array> = {};
	for (const [entryPath, bytes] of Object.entries(entries)) {
		if (entryPath.startsWith(originalPrefix) && !entryPath.endsWith("/")) {
			const name = entryPath.slice(originalPrefix.length);
			originalDocuments[name] = bytes;
		}
	}

	let attachmentManifest: AttachmentManifestPayload | null = null;
	if (paths.attachmentsManifestPath && entries[paths.attachmentsManifestPath]) {
		attachmentManifest = JSON.parse(
			decodeEntry(entries, paths.attachmentsManifestPath),
		) as AttachmentManifestPayload;
	}

	const originalAttachments: Record<string, Uint8Array> = {};
	if (paths.attachmentsOriginalPrefix) {
		const attachmentPrefix = paths.attachmentsOriginalPrefix.endsWith("/")
			? paths.attachmentsOriginalPrefix
			: `${paths.attachmentsOriginalPrefix}/`;
		for (const [entryPath, bytes] of Object.entries(entries)) {
			if (entryPath.startsWith(attachmentPrefix) && !entryPath.endsWith("/")) {
				const name = entryPath.slice(attachmentPrefix.length);
				originalAttachments[name] = bytes;
			}
		}
	}

	return {
		bundle,
		manifest,
		bundleSha256Sidecar,
		documentMerkleProofs,
		originalDocuments,
		attachmentManifest,
		originalAttachments,
	};
}
