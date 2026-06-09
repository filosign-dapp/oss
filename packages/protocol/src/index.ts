// Compliance bundle schema and canonical JSON

// Email and roster commitments
export {
	commitsForEmails,
	emailCommitRoot,
	hashNormalizedSignerEmail,
	sortedCommitsForEmails,
} from "./commitments/email";
export { buildRegistrationEmailCommitments } from "./commitments/roster";
export {
	type AttachmentComplianceRow,
	type ChainTxRef,
	COMPLIANCE_CHAIN_TX_KINDS,
	type ComplianceBundle,
	type ComplianceExportKind,
	type MerkleLeafProof,
	type PartyRow,
	type SettlementComplianceRow,
	type SignerComplianceRow,
	zAttachmentComplianceRow,
	zChainTxRef,
	zComplianceBundle,
	zComplianceExportKind,
} from "./compliance/bundle";
export {
	canonicalComplianceBundleJson,
	complianceBundleSha256Hex,
} from "./compliance/canonical";
export {
	type FieldCompletionWireRow,
	zFieldCompletionWireRow,
} from "./field-completion/wire";
export { sha256PlaintextHex } from "./hash/sha256";
export { stableJsonStringify } from "./json/stable-stringify";
// Document Merkle
export {
	type DocumentMerkleInput,
	type DocumentMerkleLeafProofV1,
	documentLeafHashV1,
	documentsMerkleProofsV1,
	documentsMerkleRootV1,
	verifyDocumentMerkleProofV1,
} from "./merkle/document";
// Field completion Merkle
export {
	type CompletionMerkleLeafProofV1,
	completionsMerkleProofsV1,
	completionsMerkleRootV1,
	computeLeafHashV1,
	LEAF_SCHEMA_VERSION_V1,
} from "./merkle/field-completion";
export {
	merkleInclusionSiblings,
	merkleLevelsFromLeaves,
	merkleRootFromLeafAndSiblings,
	merkleRootFromLeaves,
} from "./merkle/tree";
// Piece identifier
export { computeCidIdentifier } from "./piece/cid-identifier";
// Placement
export {
	canonicalPlacementManifestJson,
	computePlacementCommitment,
	normalizePlacementRecipientEmail,
	type PlacementDocument,
	type PlacementField,
	type PlacementManifest,
	uniqueSignerEmailsFromManifest,
	zPlacementDocument,
	zPlacementField,
	zPlacementManifest,
	zRectNormalized,
} from "./placement/manifest";
export {
	PROOF_PACKET_SCHEMA_V1,
	PROOF_PACKET_V1_DEFAULT_PATHS,
	type ProofPacketSchema,
	VERIFY_MANIFEST_FORMAT_V1,
	type VerifyManifest,
	type VerifyManifestV1,
	zVerifyManifest,
	zVerifyManifestV1,
} from "./proof-packet";
// Wire helpers
export { zEvmAddress, zHexString } from "./wire/zod";
