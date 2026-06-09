import {
	PROOF_PACKET_SCHEMA_V1,
	PROOF_PACKET_V1_DEFAULT_PATHS,
	type VerifyManifestV1,
} from "@filosign/protocol";

export type ResolvedPacketPaths = {
	packetSchema: typeof PROOF_PACKET_SCHEMA_V1;
	manifestPath: string;
	bundlePath: string;
	bundleHashPath: string;
	merklePath: string;
	originalPrefix: string;
	attachmentsManifestPath: string | null;
	attachmentsOriginalPrefix: string | null;
};

const paths = PROOF_PACKET_V1_DEFAULT_PATHS;
const proofRoot = `${paths.proofFolder}/`;

export const EXPECTED_MANIFEST_PATH = `${proofRoot}${paths.manifest}`;

function joinZipPath(base: string, relative: string): string {
	const normalizedBase = base.endsWith("/") ? base.slice(0, -1) : base;
	const normalizedRelative = relative.replace(/^\.\//, "");
	if (normalizedRelative.startsWith("../")) {
		const parent = normalizedBase.includes("/")
			? normalizedBase.slice(0, normalizedBase.lastIndexOf("/"))
			: "";
		const rest = normalizedRelative.slice(3);
		return parent ? `${parent}/${rest}` : rest;
	}
	return `${normalizedBase}/${normalizedRelative}`;
}

function manifestDirectory(manifestPath: string): string {
	const slash = manifestPath.lastIndexOf("/");
	return slash === -1 ? "" : manifestPath.slice(0, slash + 1);
}

export function resolvePathsFromManifest(
	manifestPath: string,
	manifest: VerifyManifestV1,
): ResolvedPacketPaths {
	if (manifest.packetSchema !== PROOF_PACKET_SCHEMA_V1) {
		throw new Error(
			`Unsupported proof packet schema: ${manifest.packetSchema}`,
		);
	}

	const manifestDir = manifestDirectory(manifestPath);
	return {
		packetSchema: PROOF_PACKET_SCHEMA_V1,
		manifestPath,
		bundlePath: joinZipPath(manifestDir, manifest.bundlePath),
		bundleHashPath: joinZipPath(manifestDir, manifest.bundleHashPath),
		merklePath: joinZipPath(manifestDir, manifest.documentMerklePath),
		originalPrefix: joinZipPath(manifestDir, manifest.originalDocumentsPrefix),
		attachmentsManifestPath: manifest.attachmentsManifestPath
			? joinZipPath(manifestDir, manifest.attachmentsManifestPath)
			: null,
		attachmentsOriginalPrefix: manifest.attachmentsManifestPath
			? joinZipPath(manifestDir, paths.attachmentsOriginalPrefix)
			: null,
	};
}

export function requiredLayoutPaths(resolved: ResolvedPacketPaths): string[] {
	const manifestDir = manifestDirectory(resolved.manifestPath);
	return [
		resolved.manifestPath,
		joinZipPath(manifestDir, paths.readme),
		resolved.bundlePath,
		resolved.bundleHashPath,
		resolved.merklePath,
		joinZipPath(manifestDir, paths.proofReport),
		paths.consumerDocument,
	];
}

export function validatePacketLayout(
	entries: Record<string, Uint8Array>,
	resolved: ResolvedPacketPaths,
): void {
	for (const path of requiredLayoutPaths(resolved)) {
		if (!entries[path]) {
			throw new Error(`Missing required proof packet file: ${path}`);
		}
	}
}
