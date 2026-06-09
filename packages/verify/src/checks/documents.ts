import type { ComplianceBundle } from "@filosign/protocol";
import {
	documentsMerkleRootV1,
	verifyDocumentMerkleProofV1,
} from "@filosign/protocol";
import type { Hex } from "viem";
import type { CheckResult, ParsedProofPacket } from "../types";
import { compareCheck, statusCheck, summarizeChecks } from "../utils/check";

function sanitizeZipSegment(name: string): string {
	return name.replace(/[/\\]/g, "_").slice(0, 200) || "document";
}

export async function runDocumentChecks(args: {
	bundle: ComplianceBundle;
	documentMerkleProofs: NonNullable<ParsedProofPacket["documentMerkleProofs"]>;
	originalDocuments: Record<string, Uint8Array>;
}): Promise<CheckResult[]> {
	const { bundle, documentMerkleProofs, originalDocuments } = args;
	const results: CheckResult[] = [];
	const expectedRoot =
		documentMerkleProofs.registerDocumentMerkleRoot ??
		bundle.registration.registerDocumentSha256;

	const docInputs: Array<{ id: string; bytes: Uint8Array; name: string }> = [];

	for (const document of bundle.placementManifest.documents) {
		const zipName = sanitizeZipSegment(document.name);
		const bytes =
			originalDocuments[zipName] ?? originalDocuments[document.name] ?? null;
		if (!bytes) {
			results.push(
				statusCheck({
					id: `documents.original.${document.id}`,
					tier: "documents",
					status: "fail",
					message: `Missing original/${zipName} in packet`,
				}),
			);
			continue;
		}
		docInputs.push({ id: document.id, bytes, name: document.name });
	}

	if (docInputs.length === 0) {
		results.push(
			statusCheck({
				id: "documents.original.present",
				tier: "documents",
				status: "skip",
				message: "No original documents found in packet",
			}),
		);
		return results;
	}

	const recomputedRoot = await documentsMerkleRootV1({
		documents: docInputs.map((document) => ({
			id: document.id,
			bytes: document.bytes,
		})),
	});

	results.push(
		compareCheck({
			id: "documents.merkle.root",
			tier: "documents",
			expected: expectedRoot,
			actual: recomputedRoot,
			message: "Document bytes recomputed Merkle root",
		}),
	);

	for (const document of docInputs) {
		const proof = documentMerkleProofs.proofs.find(
			(entry) => entry.id === document.id,
		);
		if (!proof) {
			results.push(
				statusCheck({
					id: `documents.proof.${document.id}`,
					tier: "documents",
					status: "fail",
					message: `No Merkle proof for document ${document.name}`,
				}),
			);
			continue;
		}

		const ok = await verifyDocumentMerkleProofV1({
			leafBytes: document.bytes,
			siblings: proof.siblings as Hex[],
			expectedRoot: expectedRoot as Hex,
		});
		results.push(
			statusCheck({
				id: `documents.proof.${document.id}`,
				tier: "documents",
				status: ok ? "pass" : "fail",
				message: `${document.name} Merkle inclusion proof`,
			}),
		);
	}

	return results;
}

export async function verifyDocuments(args: {
	bundle: ComplianceBundle;
	documentMerkleProofs: NonNullable<ParsedProofPacket["documentMerkleProofs"]>;
	originalDocuments: Record<string, Uint8Array>;
}) {
	return summarizeChecks(await runDocumentChecks(args));
}
