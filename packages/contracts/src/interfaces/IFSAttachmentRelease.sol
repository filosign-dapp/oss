// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// Auto-generated from src/FSAttachmentRelease.sol — DO NOT EDIT (regenerate with the script only)

import "./IFSEnvelopeRegistry.sol";

interface IFSAttachmentRelease {
    enum ReleaseType { AllSigned, SpecificSigner, AtLeastN, AllRequiredSigned, AllSignedComplete, QuorumRequired, QuorumSet, QuorumAll, AllOfSet }

    struct AttachmentRule {
        bytes32 cidId;
        address sender;
        bytes32 packetContentHash;
        bytes20 recipientsCommitment;
        ReleaseType releaseType;
        bytes32 specificSignerCommitment;
        uint8 thresholdN;
        uint64 expiresAt;
        bool released;
        bool cancelled;
    }

    function envelopeRegistry() external view returns (address);
    function deploymentChainId() external view returns (uint256);
    function nextRuleId() external view returns (uint256);
    function rules(uint256 key) external view returns (AttachmentRule memory);
    event AttachmentRuleRegistered();
    event AttachmentRuleCancelled();
    event AttachmentReleased();
    event AttachmentRuleUpdated();
    event SignerCommitmentRemapped();
    function registerAttachmentRule(bytes32 cidId_, bytes32 packetContentHash_, ReleaseType releaseType_, bytes32 specificSignerCommitment_, uint8 thresholdN_, uint64 expiresAt_, bytes32[] calldata signerCommitments_, bytes32[] calldata recipientEmailCommitments_) external returns (uint256 ruleId);
    function updateAttachmentRule(uint256 ruleId, bytes32 packetContentHash_, ReleaseType releaseType_, bytes32 specificSignerCommitment_, uint8 thresholdN_, uint64 expiresAt_, bytes32[] calldata signerCommitments_, bytes32[] calldata recipientEmailCommitments_) external;
    function remapSignerCommitment(bytes32 cidId_, bytes32 oldCommitment_, bytes32 newCommitment_) external;
    function cancelAttachmentRule(uint256 ruleId) external;
    function executeAttachmentRelease(uint256 ruleId) external;
    function canRelease(uint256 ruleId) external view returns (bool);
    function signerCommitments(uint256 ruleId) external view returns (bytes32[] memory);
    function ruleIdsForCid(bytes32 cidId_) external view returns (uint256[] memory);
}
