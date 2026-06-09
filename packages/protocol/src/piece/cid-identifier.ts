import { encodePacked, keccak256 } from "viem";

export function computeCidIdentifier(pieceCid: string): `0x${string}` {
	return keccak256(encodePacked(["string"], [pieceCid]));
}
