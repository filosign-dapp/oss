import { describe, expect, it } from "bun:test";
import {
	PROOF_PACKET_V1_DEFAULT_PATHS,
	type VerifyManifestV1,
} from "@filosign/protocol";
import { zipSync } from "fflate";
import { parsePacket } from "../src/parse/packet";
import { merkleProofsPayload, minimalBundle } from "./fixtures/minimal-bundle";

const bundleHash = `0x${"dd".repeat(32)}` as `0x${string}`;
const paths = PROOF_PACKET_V1_DEFAULT_PATHS;
const proofRoot = `${paths.proofFolder}/`;

function buildManifest(): VerifyManifestV1 {
	return {
		format: "filosign-verify-v1",
		packetSchema: "filosign-proof-packet-v1",
		consumerDocumentPath: paths.consumerDocumentFromProofFolder,
		bundlePath: paths.bundle,
		bundleHashPath: paths.bundleHash,
		bundleSha256: bundleHash,
		chainId: minimalBundle.chainId,
		pieceCid: minimalBundle.pieceCid,
		registryAddress: "0x00000000000000000000000000000000000000aa",
		documentMerklePath: paths.documentMerkle,
		originalDocumentsPrefix: paths.originalPrefix,
	};
}

function encode(text: string): Uint8Array {
	return new TextEncoder().encode(text);
}

function buildProofPacketZip(
	extra: Record<string, Uint8Array> = {},
): Uint8Array {
	return zipSync({
		[paths.consumerDocument]: new Uint8Array([1, 2, 3]),
		[`${proofRoot}${paths.readme}`]: encode("readme"),
		[`${proofRoot}${paths.manifest}`]: encode(JSON.stringify(buildManifest())),
		[`${proofRoot}${paths.bundle}`]: encode(JSON.stringify(minimalBundle)),
		[`${proofRoot}${paths.bundleHash}`]: encode(`${bundleHash}\n`),
		[`${proofRoot}${paths.documentMerkle}`]: encode(
			JSON.stringify(merkleProofsPayload),
		),
		[`${proofRoot}${paths.proofReport}`]: new Uint8Array([4, 5, 6]),
		[`${proofRoot}${paths.originalPrefix}a.pdf`]: new Uint8Array([7, 8, 9]),
		...extra,
	});
}

describe("parsePacket v1 proof packet", () => {
	it("parses proofs hierarchy", () => {
		const parsed = parsePacket(buildProofPacketZip());
		expect(parsed.manifest.format).toBe("filosign-verify-v1");
		expect(parsed.manifest.packetSchema).toBe("filosign-proof-packet-v1");
		expect(parsed.bundleSha256Sidecar).toBe(bundleHash);
		expect(parsed.originalDocuments["a.pdf"]).toEqual(
			new Uint8Array([7, 8, 9]),
		);
	});

	it("throws when verify-manifest.json is missing", () => {
		const zip = zipSync({
			[paths.consumerDocument]: new Uint8Array([1]),
			[`${proofRoot}${paths.bundle}`]: encode(JSON.stringify(minimalBundle)),
		});
		expect(() => parsePacket(zip)).toThrow("Missing verify-manifest.json");
	});

	it("throws when required bundle file is missing", () => {
		const entries: Record<string, Uint8Array> = {
			[paths.consumerDocument]: new Uint8Array([1, 2, 3]),
			[`${proofRoot}${paths.readme}`]: encode("readme"),
			[`${proofRoot}${paths.manifest}`]: encode(
				JSON.stringify(buildManifest()),
			),
			[`${proofRoot}${paths.bundleHash}`]: encode(`${bundleHash}\n`),
			[`${proofRoot}${paths.documentMerkle}`]: encode(
				JSON.stringify(merkleProofsPayload),
			),
			[`${proofRoot}${paths.proofReport}`]: new Uint8Array([4, 5, 6]),
		};
		expect(() => parsePacket(zipSync(entries))).toThrow(
			"Missing required proof packet file: proofs/bundle/bundle.json",
		);
	});

	it("rejects legacy flat layout at ZIP root", () => {
		const zip = zipSync({
			"bundle.json": encode(JSON.stringify(minimalBundle)),
			"verify-manifest.json": encode(
				JSON.stringify({
					format: "filosign-verify-v1",
					bundlePath: "bundle.json",
					bundleSha256: bundleHash,
					chainId: minimalBundle.chainId,
					pieceCid: minimalBundle.pieceCid,
					registryAddress: "0x00000000000000000000000000000000000000aa",
					documentMerklePath: "document-merkle-proofs.json",
					originalDocumentsPrefix: "original/",
				}),
			),
			"document-merkle-proofs.json": encode(
				JSON.stringify(merkleProofsPayload),
			),
		});
		expect(() => parsePacket(zip)).toThrow();
	});
});
