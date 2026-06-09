// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// Auto-generated from src/FSPaymentValidator.sol — DO NOT EDIT (regenerate with the script only)

import "./IFSEnvelopeRegistry.sol";

interface IFSPaymentValidator {
    enum ReleaseType { AllSigned, SpecificSigner, AtLeastN, AllRequiredSigned, AllSignedComplete, QuorumRequired, QuorumSet, QuorumAll, AllOfSet }

    struct PayoutLeg {
        address recipient;
        uint256 amount;
    }

    struct PaymentRule {
        address payer;
        address token;
        bytes32 cidId;
        ReleaseType releaseType;
        bytes32 specificSignerCommitment;
        uint8 thresholdN;
        uint64 expiresAt;
        bool executed;
        bool cancelled;
    }

    function envelopeRegistry() external view returns (address);
    function deploymentChainId() external view returns (uint256);
    function nextRuleId() external view returns (uint256);
    function rules(uint256 key) external view returns (PaymentRule memory);
    function legPaidBitmap(uint256 key) external view returns (uint256);
    event PaymentRuleRegistered();
    event PaymentRuleUpdated();
    event PaymentRuleCancelled();
    event PayoutExecuted();
    event PayoutLegExecuted();
    event SignerCommitmentRemapped();
    function registerRule(address payer_, address token_, bytes32 cidId_, ReleaseType releaseType_, bytes32 specificSignerCommitment_, uint8 thresholdN_, uint64 expiresAt_, bytes32[] calldata signerCommitments_, PayoutLeg[] calldata legs_) external returns (uint256 ruleId);
    function updatePayoutRule(uint256 ruleId, ReleaseType releaseType_, bytes32 specificSignerCommitment_, uint8 thresholdN_, uint64 expiresAt_, bytes32[] calldata signerCommitments_, PayoutLeg[] calldata legs_) external;
    function cancelPayoutRule(uint256 ruleId) external;
    function hasAnyPaidLegForCid(bytes32 cidId_) external view returns (bool);
    function remapSignerCommitment(bytes32 cidId_, bytes32 oldCommitment_, bytes32 newCommitment_) external;
    function executePayoutLeg(uint256 ruleId, uint256 legIndex) external;
    function executePayout(uint256 ruleId) external;
    function canExecute(uint256 ruleId) external view returns (bool);
    function isLegPaid(uint256 ruleId, uint256 legIndex) external view returns (bool);
    function unpaidLegCount(uint256 ruleId) external view returns (uint256 count);
    function ruleLegs(uint256 ruleId) external view returns (PayoutLeg[] memory);
    function signerCommitments(uint256 ruleId) external view returns (bytes32[] memory);
    function ruleIdsForCid(bytes32 cidId_) external view returns (uint256[] memory);
}
