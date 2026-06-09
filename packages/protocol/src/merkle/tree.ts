import type { Hex } from "viem";
import { concat, hexToBigInt, keccak256 } from "viem";

function hashPair(a: Hex, b: Hex): Hex {
	const [left, right] = hexToBigInt(a) <= hexToBigInt(b) ? [a, b] : [b, a];
	return keccak256(concat([left, right]));
}

export function merkleRootFromLeaves(leafHashes: Hex[]): Hex {
	if (leafHashes.length === 0) {
		throw new Error("merkleRootFromLeaves: empty leaves");
	}
	let level = [...leafHashes];
	while (level.length > 1) {
		const next: Hex[] = [];
		for (let i = 0; i < level.length; i += 2) {
			const left = level[i];
			const right = level[i + 1] ?? left;
			if (!left || !right) break;
			next.push(hashPair(left, right));
		}
		level = next;
	}
	const root = level[0];
	if (!root) throw new Error("merkleRootFromLeaves: no root");
	return root;
}

export function merkleLevelsFromLeaves(leafHashes: Hex[]): Hex[][] {
	if (leafHashes.length === 0) {
		throw new Error("merkleLevelsFromLeaves: empty leaves");
	}
	const levels: Hex[][] = [];
	let level = [...leafHashes];
	levels.push(level);
	while (level.length > 1) {
		const next: Hex[] = [];
		for (let i = 0; i < level.length; i += 2) {
			const left = level[i];
			const right = level[i + 1] ?? left;
			if (!left || !right) break;
			next.push(hashPair(left, right));
		}
		level = next;
		levels.push(level);
	}
	return levels;
}

export function merkleInclusionSiblings(
	levels: Hex[][],
	leafIndex: number,
): Hex[] {
	const siblings: Hex[] = [];
	let index = leafIndex;
	for (let depth = 0; depth < levels.length - 1; depth++) {
		const row = levels[depth];
		if (!row) break;
		const pairBase = Math.floor(index / 2) * 2;
		const left = row[pairBase];
		const right = row[pairBase + 1] ?? left;
		const sibling = index === pairBase ? right : left;
		if (sibling !== undefined) siblings.push(sibling);
		index = Math.floor(index / 2);
	}
	return siblings;
}

export function merkleRootFromLeafAndSiblings(
	leafHash: Hex,
	siblings: Hex[],
): Hex {
	let current = leafHash;
	for (const sibling of siblings) {
		current = hashPair(current, sibling);
	}
	return current;
}
