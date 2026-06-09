import z from "zod";
import { zFieldCompletionWireRow } from "../field-completion/wire";
import { zPlacementManifest } from "../placement/manifest";
import { zEvmAddress, zHexString } from "../wire/zod";
import {
	settlementReleaseTypes,
	settlementRuleStatuses,
	zSettlementReleaseParams,
} from "./settlement-wire";

export const zMerkleLeafProof = z.object({
	fieldId: z.string(),
	leafHash: zHexString(),
	leafIndex: z.number().int().min(0),
	siblings: z.array(zHexString()),
});

export const zSignerComplianceRow = z.object({
	wallet: zEvmAddress(),
	displayName: z.string().nullable(),
	email: z.string().nullable(),
	signed: z.boolean(),
	assignedFieldIds: z.array(z.string()),
	requiredFieldIds: z.array(z.string()),
	optionalFieldIds: z.array(z.string()),
	onchainTxHash: zHexString().nullable(),
	signedAtIso: z.string().nullable(),
	completedFieldIds: z.array(z.string()),
	completionsRoot: zHexString().nullable(),
	leafSchemaVersion: z.number().int().nullable(),
	merkleProofs: z.array(zMerkleLeafProof),
	draftCompletedFieldIds: z.array(z.string()),
	messageTimestampIso: z.string().nullable(),
	blockTimestampFromTx: z.number().int().nonnegative().nullable(),
	acknowledgedAtIso: z.string().nullable(),
	firstViewedAtIso: z.string().nullable(),
	requestIp: z.string().nullable().optional(),
	requestUserAgent: z.string().nullable().optional(),
});

export const zPartyRole = z.enum(["sender", "signer", "viewer"]);

export const zPartyRow = z.object({
	role: zPartyRole,
	wallet: zEvmAddress(),
	email: z.string(),
	displayName: z.string().nullable(),
	emailCommitment: zHexString(),
	authSubjectCommitment: zHexString().nullable(),
});

export const zOnchainRegistrationSnapshot = z.object({
	cidIdentifier: zHexString(),
	sender: zEvmAddress(),
	signersCommitment: zHexString(),
	viewersCommitment: zHexString(),
	placementCommitment: zHexString(),
	documentSha256: zHexString(),
	senderEmailCommitment: zHexString(),
	senderAuthSubjectCommitment: zHexString(),
	requiredSignersCount: z.number().int().min(0).max(255),
	requiredSignaturesCount: z.number().int().min(0).max(255),
	signaturesCount: z.number().int().min(0).max(255),
	quorumN: z.number().int().min(0).max(255),
	routingMode: z.number().int().min(0).max(255),
	completedAt: z.string().nullable().optional(),
	revokedBeforeCompletedAt: z.string().nullable().optional(),
	revokedBy: zEvmAddress().nullable().optional(),
	rosterSignedCount: z.number().int().min(0).max(255),
	timestamp: z.string(),
	orgIdCommitment: zHexString().nullable().optional(),
});

export const zChainTxKind = z.enum([
	"file_registered",
	"file_signed",
	"signer_amended",
	"envelope_revoked_before_complete",
	"payout_executed",
	"settlement_rule_registered",
	"settlement_approved",
	"attachment_rule_registered",
	"attachment_released",
]);

export const zSettlementComplianceRow = z.object({
	onChainRuleId: z.string(),
	legs: z.array(
		z.object({
			recipientWallet: zEvmAddress(),
			amount: z.string(),
		}),
	),
	tokenAddress: zEvmAddress(),
	validatorAddress: zEvmAddress(),
	releaseType: z.enum(settlementReleaseTypes),
	status: z.enum(settlementRuleStatuses),
	registerRuleTxHash: zHexString(),
	approveTxHash: zHexString(),
	payoutTxHash: zHexString().nullable(),
	executedAtIso: z.string().nullable(),
	lastError: z.string().nullable(),
});

export const COMPLIANCE_CHAIN_TX_KINDS = zChainTxKind.options;

export const zChainTxRef = z.object({
	kind: zChainTxKind,
	txHash: zHexString(),
	chainId: z.number().int(),
	contractAddress: zEvmAddress(),
	summary: z.string(),
	relatedAddresses: z.array(zEvmAddress()),
	blockNumber: z.number().int().nonnegative().nullable(),
	timestamp: z.number().int().nonnegative().nullable(),
	fetchedAtIso: z.string().nullable(),
});

export const zAckEvidenceRow = z.object({
	wallet: zEvmAddress(),
	createdAtIso: z.string(),
	acknowledgedAtIso: z.string(),
	intentVersion: z.string(),
	emailCommitment: zHexString(),
	authSubjectCommitment: zHexString().nullable(),
	ackSha256: zHexString().nullable(),
});

export const zDocumentViewRow = z.object({
	wallet: zEvmAddress(),
	firstViewedAtIso: z.string(),
	source: z.enum(["sign_page", "file_viewer", "inbox"]),
});

export const zColdInviteClaimRow = z.object({
	email: z.string(),
	wallet: zEvmAddress(),
	claimedAtIso: z.string(),
	isSigner: z.boolean(),
});

export const zSettlementRecipientAckRow = z.object({
	signerWallet: zEvmAddress(),
	termsVersion: z.string(),
	acknowledgedAtIso: z.string(),
});

export const zOffChainEvidence = z.object({
	acknowledgements: z.array(zAckEvidenceRow),
	documentViews: z.array(zDocumentViewRow),
	coldInviteClaims: z.array(zColdInviteClaimRow),
	payoutRecipientAcknowledgements: z.array(zSettlementRecipientAckRow),
});

export const zAttachmentComplianceRow = z.object({
	packetId: z.string(),
	packetCid: z.string(),
	label: z.string().nullable(),
	releaseMode: z.enum(["review", "conditional"]),
	releaseType: z.enum(settlementReleaseTypes).nullable(),
	releaseParams: zSettlementReleaseParams.nullable(),
	recipientsCommitment: zHexString().nullable(),
	onChainRuleId: z.string().nullable(),
	releaseContractAddress: zEvmAddress().nullable(),
	registerRuleTxHash: zHexString().nullable(),
	packetContentHash: zHexString().nullable(),
	releaseTxHash: zHexString().nullable(),
	recipientCount: z.number().int().nonnegative(),
	unlocked: z.boolean(),
	cancelled: z.boolean(),
});

export const zComplianceExportKind = z.enum(["zip", "pdf", "json"]);
export type ComplianceExportKind = z.infer<typeof zComplianceExportKind>;

export const zComplianceBundle = z.object({
	version: z.literal(1),
	pieceCid: z.string(),
	chainId: z.number().int(),
	exportedAtIso: z.string(),
	executionStatus: z.enum(["fully_executed", "partially_executed"]),
	placementCommitment: zHexString(),
	placementManifest: zPlacementManifest,
	registration: z.object({
		sender: zEvmAddress(),
		registrationTxHash: zHexString(),
		createdAtIso: z.string(),
		registerDocumentSha256: zHexString(),
	}),
	parties: z.array(zPartyRow),
	onchainRegistration: zOnchainRegistrationSnapshot.nullable(),
	transactions: z.array(zChainTxRef),
	signers: z.array(zSignerComplianceRow),
	settlements: z.array(zSettlementComplianceRow),
	attachments: z.array(zAttachmentComplianceRow),
	offChainEvidence: zOffChainEvidence,
	fieldCompletions: z.array(zFieldCompletionWireRow).optional(),
});

export type ComplianceBundle = z.infer<typeof zComplianceBundle>;
export type SettlementComplianceRow = z.infer<typeof zSettlementComplianceRow>;
export type AttachmentComplianceRow = z.infer<typeof zAttachmentComplianceRow>;
export type SignerComplianceRow = z.infer<typeof zSignerComplianceRow>;
export type MerkleLeafProof = z.infer<typeof zMerkleLeafProof>;
export type PartyRow = z.infer<typeof zPartyRow>;
export type ChainTxRef = z.infer<typeof zChainTxRef>;
