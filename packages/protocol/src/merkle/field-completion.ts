import type { Address, Hex } from "viem";
import { encodeAbiParameters, keccak256, stringToBytes } from "viem";
import {
	merkleInclusionSiblings,
	merkleLevelsFromLeaves,
	merkleRootFromLeaves,
} from "./tree";

export const LEAF_SCHEMA_VERSION_V1 = 1 as const;

export function fieldIdToBytes32(fieldId: string): Hex {
	return keccak256(stringToBytes(fieldId));
}

export function computeLeafHashV1(params: {
	fieldId: string;
	placementCommitment: Hex;
	pieceCid: string;
	signer: Address;
}): Hex {
	const pieceCidDigest = keccak256(stringToBytes(params.pieceCid));
	const fieldKey = fieldIdToBytes32(params.fieldId);
	const encoded = encodeAbiParameters(
		[
			{ type: "uint8", name: "leafSchemaVersion" },
			{ type: "bytes32", name: "fieldId" },
			{ type: "bytes32", name: "placementCommitment" },
			{ type: "bytes32", name: "pieceCidDigest" },
			{ type: "address", name: "signer" },
		],
		[
			LEAF_SCHEMA_VERSION_V1,
			fieldKey,
			params.placementCommitment,
			pieceCidDigest,
			params.signer,
		],
	);
	return keccak256(encoded);
}

export function completionsMerkleRootV1(params: {
	fieldIds: string[];
	placementCommitment: Hex;
	pieceCid: string;
	signer: Address;
}): Hex {
	const uniqueSorted = [...new Set(params.fieldIds)].sort((a, b) =>
		a.localeCompare(b),
	);
	const leaves = uniqueSorted.map((fieldId) =>
		computeLeafHashV1({
			fieldId,
			placementCommitment: params.placementCommitment,
			pieceCid: params.pieceCid,
			signer: params.signer,
		}),
	);
	return merkleRootFromLeaves(leaves);
}

export type CompletionMerkleLeafProofV1 = {
	fieldId: string;
	leafHash: Hex;
	leafIndex: number;
	siblings: Hex[];
};

export function completionsMerkleProofsV1(params: {
	fieldIds: string[];
	placementCommitment: Hex;
	pieceCid: string;
	signer: Address;
}): CompletionMerkleLeafProofV1[] {
	const uniqueSorted = [...new Set(params.fieldIds)].sort((a, b) =>
		a.localeCompare(b),
	);
	const leaves = uniqueSorted.map((fieldId) =>
		computeLeafHashV1({
			fieldId,
			placementCommitment: params.placementCommitment,
			pieceCid: params.pieceCid,
			signer: params.signer,
		}),
	);
	const levels = merkleLevelsFromLeaves(leaves);
	return uniqueSorted.map((fieldId, leafIndex) => ({
		fieldId,
		leafHash: leaves[leafIndex] as Hex,
		leafIndex,
		siblings: merkleInclusionSiblings(levels, leafIndex),
	}));
}
