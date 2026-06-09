import z from "zod";
import { zHexString } from "../wire/zod";

export const settlementReleaseTypes = [
	"all_signed",
	"specific_signer",
	"at_least_n",
	"all_required_signed",
	"all_signed_complete",
	"quorum_required",
	"quorum_set",
	"quorum_all",
	"all_of_set",
] as const;

export const settlementRuleStatuses = [
	"pending",
	"ready",
	"partial",
	"executed",
	"cancelled",
	"failed_insufficient",
	"failed_relay",
	"failed_conditions",
] as const;

export type SettlementReleaseType = (typeof settlementReleaseTypes)[number];
export type SettlementRuleStatus = (typeof settlementRuleStatuses)[number];

export const zSettlementReleaseParams = z.discriminatedUnion("releaseType", [
	z.object({ releaseType: z.literal("all_signed") }),
	z.object({ releaseType: z.literal("all_required_signed") }),
	z.object({ releaseType: z.literal("all_signed_complete") }),
	z.object({
		releaseType: z.literal("specific_signer"),
		signerEmailCommitment: zHexString(),
	}),
	z.object({
		releaseType: z.literal("at_least_n"),
		thresholdN: z.number().int().min(1),
		signerEmailCommitments: z.array(zHexString()).min(1),
	}),
	z.object({
		releaseType: z.literal("quorum_required"),
		thresholdN: z.number().int().min(1),
	}),
	z.object({
		releaseType: z.literal("quorum_set"),
		thresholdN: z.number().int().min(1),
		signerEmailCommitments: z.array(zHexString()).min(1),
	}),
	z.object({
		releaseType: z.literal("quorum_all"),
		thresholdN: z.number().int().min(1),
	}),
	z.object({
		releaseType: z.literal("all_of_set"),
		signerEmailCommitments: z.array(zHexString()).min(1),
	}),
]);

export type SettlementReleaseParams = z.infer<typeof zSettlementReleaseParams>;
