import type { Hex } from "viem";
import { getAddress, isAddress, isHex } from "viem";
import z from "zod";

export const zHexString = () =>
	z
		.string()
		.refine((val) => isHex(val), { error: "Invalid hex string" })
		.transform((val) => val.toLowerCase() as Hex);

export const zEvmAddress = () =>
	z
		.string()
		.refine((val) => isAddress(val), { error: "Invalid Ethereum address" })
		.transform((val) => getAddress(val));
