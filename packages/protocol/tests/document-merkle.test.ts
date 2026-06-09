import { describe, expect, it } from "bun:test";
import type { Hex } from "viem";
import { concat, hexToBigInt, keccak256 } from "viem";
import {
	documentLeafHashV1,
	documentsMerkleProofsV1,
	documentsMerkleRootV1,
	merkleRootFromLeafAndSiblings,
	verifyDocumentMerkleProofV1,
} from "../src/index";

function pairHash(a: Hex, b: Hex): Hex {
	const [left, right] = hexToBigInt(a) <= hexToBigInt(b) ? [a, b] : [b, a];
	return keccak256(concat([left, right]));
}

describe("document Merkle v1", () => {
	it("rejects empty document list", async () => {
		await expect(documentsMerkleRootV1({ documents: [] })).rejects.toThrow(
			/at least one document/,
		);
	});

	it("single document: root equals leaf hash", async () => {
		const bytes = new Uint8Array([1, 2, 3]);
		const root = await documentsMerkleRootV1({
			documents: [{ id: "a", bytes }],
		});
		const leaf = await documentLeafHashV1(bytes);
		expect(root).toBe(leaf);
	});

	it("multi-document: stable root for sorted ids", async () => {
		const docA = new Uint8Array([10]);
		const docB = new Uint8Array([20]);
		const root1 = await documentsMerkleRootV1({
			documents: [
				{ id: "b", bytes: docB },
				{ id: "a", bytes: docA },
			],
		});
		const root2 = await documentsMerkleRootV1({
			documents: [
				{ id: "a", bytes: docA },
				{ id: "b", bytes: docB },
			],
		});
		expect(root1).toBe(root2);
	});

	it("each proof verifies to the root", async () => {
		const documents = [
			{ id: "doc-1", bytes: new Uint8Array([1]) },
			{ id: "doc-2", bytes: new Uint8Array([2, 3]) },
		];
		const root = await documentsMerkleRootV1({ documents });
		const proofs = await documentsMerkleProofsV1({ documents });
		for (const proof of proofs) {
			const doc = documents.find((d) => d.id === proof.id);
			if (!doc) throw new Error(`proof id ${proof.id} not in documents`);
			const recomputed = merkleRootFromLeafAndSiblings(
				proof.leafHash,
				proof.siblings,
			);
			expect(recomputed).toBe(root);
			const ok = await verifyDocumentMerkleProofV1({
				leafBytes: doc.bytes,
				siblings: proof.siblings,
				expectedRoot: root,
			});
			expect(ok).toBe(true);
		}
	});

	it("verifyDocumentMerkleProofV1 rejects wrong root", async () => {
		const bytes = new Uint8Array([9]);
		const proofs = await documentsMerkleProofsV1({
			documents: [{ id: "x", bytes }],
		});
		const proof = proofs[0];
		if (!proof) throw new Error("expected proof");
		const ok = await verifyDocumentMerkleProofV1({
			leafBytes: bytes,
			siblings: proof.siblings,
			expectedRoot: `0x${"ff".repeat(32)}`,
		});
		expect(ok).toBe(false);
	});

	it("odd document count duplicates last leaf at this level", async () => {
		const docA = new Uint8Array([1]);
		const docB = new Uint8Array([2]);
		const docC = new Uint8Array([3]);
		const leafA = await documentLeafHashV1(docA);
		const leafB = await documentLeafHashV1(docB);
		const leafC = await documentLeafHashV1(docC);
		const ab = pairHash(leafA, leafB);
		const cc = pairHash(leafC, leafC);
		const expected = pairHash(ab, cc);
		const root = await documentsMerkleRootV1({
			documents: [
				{ id: "c", bytes: docC },
				{ id: "a", bytes: docA },
				{ id: "b", bytes: docB },
			],
		});
		expect(root).toBe(expected);
	});
});
