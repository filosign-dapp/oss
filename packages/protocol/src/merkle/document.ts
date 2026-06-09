import type { Hex } from "viem";
import { sha256PlaintextHex } from "../hash/sha256";
import {
	merkleInclusionSiblings,
	merkleLevelsFromLeaves,
	merkleRootFromLeafAndSiblings,
	merkleRootFromLeaves,
} from "./tree";

export type DocumentMerkleInput = {
	id: string;
	bytes: Uint8Array;
};

export type DocumentMerkleLeafProofV1 = {
	id: string;
	leafHash: Hex;
	leafIndex: number;
	siblings: Hex[];
};

export async function documentLeafHashV1(bytes: Uint8Array): Promise<Hex> {
	return sha256PlaintextHex(bytes);
}

export async function documentsMerkleRootV1(args: {
	documents: DocumentMerkleInput[];
}): Promise<Hex> {
	if (args.documents.length === 0) {
		throw new Error("documentsMerkleRootV1: at least one document required");
	}
	const sorted = [...args.documents].sort((a, b) => a.id.localeCompare(b.id));
	const leaves = await Promise.all(
		sorted.map((document) => documentLeafHashV1(document.bytes)),
	);
	return merkleRootFromLeaves(leaves);
}

export async function documentsMerkleProofsV1(args: {
	documents: DocumentMerkleInput[];
}): Promise<DocumentMerkleLeafProofV1[]> {
	if (args.documents.length === 0) {
		throw new Error("documentsMerkleProofsV1: at least one document required");
	}
	const sorted = [...args.documents].sort((a, b) => a.id.localeCompare(b.id));
	const leaves = await Promise.all(
		sorted.map((document) => documentLeafHashV1(document.bytes)),
	);
	const levels = merkleLevelsFromLeaves(leaves);
	return sorted.map((document, leafIndex) => ({
		id: document.id,
		leafHash: leaves[leafIndex] as Hex,
		leafIndex,
		siblings: merkleInclusionSiblings(levels, leafIndex),
	}));
}

export async function verifyDocumentMerkleProofV1(args: {
	leafBytes: Uint8Array;
	siblings: Hex[];
	expectedRoot: Hex;
}): Promise<boolean> {
	const leafHash = await documentLeafHashV1(args.leafBytes);
	const computed = merkleRootFromLeafAndSiblings(leafHash, args.siblings);
	return computed.toLowerCase() === args.expectedRoot.toLowerCase();
}
