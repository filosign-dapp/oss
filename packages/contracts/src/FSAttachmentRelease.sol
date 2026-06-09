// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "./errors/EFSPaymentValidator.sol";
import { EnvelopeRecalled } from "./errors/EFSEnvelopeRegistry.sol";
import "./interfaces/IFSEnvelopeRegistry.sol";

/// @notice Signature-conditional supplementary packet release (Teams Pro). Review-only packets stay off-chain.
contract FSAttachmentRelease is ReentrancyGuard {
    uint8 internal constant MAX_ATTACHMENT_RECIPIENTS = 32;
    uint8 internal constant MAX_RULE_COMMITMENTS = 128;
    uint8 internal constant MAX_RULES_PER_CID = 128;

    enum ReleaseType {
        AllSigned,
        SpecificSigner,
        AtLeastN,
        AllRequiredSigned,
        AllSignedComplete,
        QuorumRequired,
        QuorumSet,
        QuorumAll,
        AllOfSet
    }

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

    IFSEnvelopeRegistry public immutable envelopeRegistry;
    uint256 public immutable deploymentChainId;

    uint256 public nextRuleId;
    mapping(uint256 ruleId => AttachmentRule) public rules;
    mapping(uint256 ruleId => bytes32[]) private _ruleSignerCommitments;
    mapping(bytes32 cidId => uint256[]) private _ruleIdsByCid;

    event AttachmentRuleRegistered(
        uint256 indexed ruleId,
        bytes32 indexed cidId,
        address indexed sender,
        bytes20 recipientsCommitment,
        bytes32 packetContentHash,
        ReleaseType releaseType
    );

    event AttachmentRuleCancelled(uint256 indexed ruleId, bytes32 indexed cidId);

    event AttachmentReleased(
        uint256 indexed ruleId,
        bytes32 indexed cidId,
        bytes20 recipientsCommitment,
        bytes32 packetContentHash
    );

    event AttachmentRuleUpdated(uint256 indexed ruleId, bytes32 indexed cidId);

    event SignerCommitmentRemapped(
        uint256 indexed ruleId,
        bytes32 indexed cidId,
        bytes32 indexed oldCommitment,
        bytes32 newCommitment
    );

    constructor(address envelopeRegistry_, uint256 deploymentChainId_) {
        if (envelopeRegistry_ == address(0)) {
            revert InvalidReleaseConfig();
        }
        envelopeRegistry = IFSEnvelopeRegistry(envelopeRegistry_);
        deploymentChainId = deploymentChainId_;
        if (block.chainid != deploymentChainId_) {
            revert InvalidReleaseConfig();
        }
    }

    function registerAttachmentRule(
        bytes32 cidId_,
        bytes32 packetContentHash_,
        ReleaseType releaseType_,
        bytes32 specificSignerCommitment_,
        uint8 thresholdN_,
        uint64 expiresAt_,
        bytes32[] calldata signerCommitments_,
        bytes32[] calldata recipientEmailCommitments_
    ) external returns (uint256 ruleId) {
        IFSEnvelopeRegistry.EnvelopeRegistrationView memory reg = envelopeRegistry
            .envelopeRegistrations(cidId_);
        if (reg.timestamp == 0) revert FileNotRegistered();
        if (envelopeRegistry.isRevokedBeforeComplete(cidId_))
            revert EnvelopeRecalled();
        if (
            msg.sender != reg.sender &&
            !envelopeRegistry.isOrgController(
                reg.orgIdCommitment,
                msg.sender
            )
        ) revert UnauthorizedRuleRegistration();
        if (packetContentHash_ == bytes32(0)) revert InvalidReleaseConfig();
        if (
            recipientEmailCommitments_.length == 0 ||
            recipientEmailCommitments_.length > MAX_ATTACHMENT_RECIPIENTS
        ) revert InvalidReleaseConfig();

        _validateReleaseConfig(
            releaseType_,
            specificSignerCommitment_,
            thresholdN_,
            signerCommitments_
        );
        if (releaseType_ == ReleaseType.QuorumRequired) {
            _validateQuorumRequiredThreshold(cidId_, thresholdN_);
        }
        if (releaseType_ == ReleaseType.QuorumAll) {
            _validateQuorumAllThreshold(cidId_, thresholdN_);
        }
        _validateExpiresAt(expiresAt_);
        _validateRecipientCommitments(recipientEmailCommitments_);

        if (_ruleIdsByCid[cidId_].length >= MAX_RULES_PER_CID) {
            revert ExceedsMaxCommitments();
        }

        bytes20 recipientsCommitment = envelopeRegistry.computeEmailSignerCommitment(
            recipientEmailCommitments_
        );

        ruleId = nextRuleId++;
        AttachmentRule storage rule = rules[ruleId];
        rule.cidId = cidId_;
        rule.sender = reg.sender;
        rule.packetContentHash = packetContentHash_;
        rule.recipientsCommitment = recipientsCommitment;
        rule.releaseType = releaseType_;
        rule.specificSignerCommitment = specificSignerCommitment_;
        rule.thresholdN = thresholdN_;
        rule.expiresAt = expiresAt_;

        if (_needsCommitmentList(releaseType_)) {
            _storeSignerCommitments(ruleId, signerCommitments_);
        }

        _ruleIdsByCid[cidId_].push(ruleId);

        emit AttachmentRuleRegistered(
            ruleId,
            cidId_,
            reg.sender,
            recipientsCommitment,
            packetContentHash_,
            releaseType_
        );
    }

    function updateAttachmentRule(
        uint256 ruleId,
        bytes32 packetContentHash_,
        ReleaseType releaseType_,
        bytes32 specificSignerCommitment_,
        uint8 thresholdN_,
        uint64 expiresAt_,
        bytes32[] calldata signerCommitments_,
        bytes32[] calldata recipientEmailCommitments_
    ) external nonReentrant {
        AttachmentRule storage rule = rules[ruleId];
        if (rule.sender == address(0)) revert InvalidPayer();
        IFSEnvelopeRegistry.EnvelopeRegistrationView memory reg = envelopeRegistry
            .envelopeRegistrations(rule.cidId);
        if (
            msg.sender != rule.sender &&
            !envelopeRegistry.isOrgController(reg.orgIdCommitment, msg.sender)
        ) revert UnauthorizedRuleRegistration();
        if (rule.released) revert RuleAlreadyExecuted();
        if (rule.cancelled) revert RuleAlreadyCancelled();
        _assertRequiredSigningNotStarted(rule.cidId);
        if (envelopeRegistry.isRevokedBeforeComplete(rule.cidId))
            revert EnvelopeRecalled();
        if (packetContentHash_ == bytes32(0)) revert InvalidReleaseConfig();
        if (
            recipientEmailCommitments_.length == 0 ||
            recipientEmailCommitments_.length > MAX_ATTACHMENT_RECIPIENTS
        ) revert InvalidReleaseConfig();

        _validateReleaseConfig(
            releaseType_,
            specificSignerCommitment_,
            thresholdN_,
            signerCommitments_
        );
        if (releaseType_ == ReleaseType.QuorumRequired) {
            _validateQuorumRequiredThreshold(rule.cidId, thresholdN_);
        }
        if (releaseType_ == ReleaseType.QuorumAll) {
            _validateQuorumAllThreshold(rule.cidId, thresholdN_);
        }
        _validateExpiresAt(expiresAt_);
        _validateRecipientCommitments(recipientEmailCommitments_);

        bytes20 recipientsCommitment = envelopeRegistry.computeEmailSignerCommitment(
            recipientEmailCommitments_
        );

        rule.packetContentHash = packetContentHash_;
        rule.recipientsCommitment = recipientsCommitment;
        rule.releaseType = releaseType_;
        rule.specificSignerCommitment = specificSignerCommitment_;
        rule.thresholdN = thresholdN_;
        rule.expiresAt = expiresAt_;

        delete _ruleSignerCommitments[ruleId];
        if (_needsCommitmentList(releaseType_)) {
            _storeSignerCommitments(ruleId, signerCommitments_);
        }

        emit AttachmentRuleUpdated(ruleId, rule.cidId);
    }

    function remapSignerCommitment(
        bytes32 cidId_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_
    ) external {
        if (msg.sender != address(envelopeRegistry)) revert UnauthorizedRegistry();
        uint256[] storage ruleIds = _ruleIdsByCid[cidId_];
        uint256 len = ruleIds.length;
        for (uint256 i = 0; i < len; ) {
            uint256 ruleId = ruleIds[i];
            AttachmentRule storage rule = rules[ruleId];
            if (rule.sender == address(0) || rule.cancelled || rule.released) {
                unchecked {
                    ++i;
                }
                continue;
            }
            if (
                rule.releaseType == ReleaseType.SpecificSigner &&
                rule.specificSignerCommitment == oldCommitment_
            ) {
                rule.specificSignerCommitment = newCommitment_;
                emit SignerCommitmentRemapped(
                    ruleId,
                    cidId_,
                    oldCommitment_,
                    newCommitment_
                );
            }
            if (_needsCommitmentList(rule.releaseType)) {
                bytes32[] storage commitments = _ruleSignerCommitments[ruleId];
                for (uint256 j = 0; j < commitments.length; ) {
                    if (commitments[j] == oldCommitment_) {
                        commitments[j] = newCommitment_;
                        emit SignerCommitmentRemapped(
                            ruleId,
                            cidId_,
                            oldCommitment_,
                            newCommitment_
                        );
                    }
                    unchecked {
                        ++j;
                    }
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    function cancelAttachmentRule(uint256 ruleId) external nonReentrant {
        AttachmentRule storage rule = rules[ruleId];
        if (rule.sender == address(0)) revert InvalidPayer();
        IFSEnvelopeRegistry.EnvelopeRegistrationView memory reg = envelopeRegistry
            .envelopeRegistrations(rule.cidId);
        if (
            msg.sender != rule.sender &&
            !envelopeRegistry.isOrgController(reg.orgIdCommitment, msg.sender)
        ) revert UnauthorizedRuleCancellation();
        if (rule.released) revert RuleAlreadyExecuted();
        if (rule.cancelled) revert RuleAlreadyCancelled();
        if (envelopeRegistry.isRevokedBeforeComplete(rule.cidId))
            revert EnvelopeRecalled();
        _assertRequiredSigningNotStarted(rule.cidId);
        rule.cancelled = true;
        emit AttachmentRuleCancelled(ruleId, rule.cidId);
    }

    function executeAttachmentRelease(
        uint256 ruleId
    ) external nonReentrant {
        AttachmentRule storage rule = rules[ruleId];
        if (rule.released || rule.cancelled) revert RuleNotExecutable();
        if (envelopeRegistry.isRevokedBeforeComplete(rule.cidId))
            revert EnvelopeRecalled();
        if (!_releaseConditionsMet(ruleId, rule)) revert RuleNotExecutable();
        if (_isRuleExpired(rule)) {
            revert RuleNotExecutable();
        }
        rule.released = true;
        emit AttachmentReleased(
            ruleId,
            rule.cidId,
            rule.recipientsCommitment,
            rule.packetContentHash
        );
    }

    function canRelease(uint256 ruleId) external view returns (bool) {
        AttachmentRule storage rule = rules[ruleId];
        if (rule.released || rule.cancelled || rule.sender == address(0)) {
            return false;
        }
        if (_isRuleExpired(rule)) {
            return false;
        }
        if (envelopeRegistry.isRevokedBeforeComplete(rule.cidId)) return false;
        return _releaseConditionsMet(ruleId, rule);
    }

    function signerCommitments(
        uint256 ruleId
    ) external view returns (bytes32[] memory) {
        return _ruleSignerCommitments[ruleId];
    }

    function ruleIdsForCid(
        bytes32 cidId_
    ) external view returns (uint256[] memory) {
        return _ruleIdsByCid[cidId_];
    }

    function _validateRecipientCommitments(
        bytes32[] calldata commitments_
    ) private pure {
        for (uint256 i = 0; i < commitments_.length; i++) {
            if (commitments_[i] == bytes32(0)) revert InvalidReleaseConfig();
            for (uint256 j = 0; j < i; j++) {
                if (commitments_[j] >= commitments_[i]) {
                    revert InvalidReleaseConfig();
                }
            }
        }
    }

    function _validateExpiresAt(uint64 expiresAt_) private view {
        if (expiresAt_ != 0 && expiresAt_ <= block.timestamp) {
            revert InvalidReleaseConfig();
        }
    }

    function _usesCompletionGatedExpiry(
        ReleaseType rt,
        bytes32 cidId_
    ) private view returns (bool) {
        if (
            rt == ReleaseType.AllSigned ||
            rt == ReleaseType.AllRequiredSigned ||
            rt == ReleaseType.AllSignedComplete
        ) {
            return true;
        }
        if (rt == ReleaseType.QuorumRequired) {
            IFSEnvelopeRegistry.EnvelopeRegistrationView memory reg = envelopeRegistry
                .envelopeRegistrations(cidId_);
            return reg.quorumN > 0;
        }
        return false;
    }

    function _isRuleExpired(
        AttachmentRule storage rule
    ) private view returns (bool) {
        if (rule.expiresAt == 0) return false;
        if (_usesCompletionGatedExpiry(rule.releaseType, rule.cidId)) {
            if (!envelopeRegistry.isEnvelopeComplete(rule.cidId)) {
                return block.timestamp > rule.expiresAt;
            }
            uint48 completedAt = envelopeRegistry
                .envelopeRegistrations(rule.cidId)
                .completedAt;
            return completedAt > rule.expiresAt;
        }
        return block.timestamp > rule.expiresAt;
    }

    function _storeSignerCommitments(
        uint256 ruleId,
        bytes32[] calldata signerCommitments_
    ) private {
        if (signerCommitments_.length > MAX_RULE_COMMITMENTS) {
            revert ExceedsMaxCommitments();
        }
        bytes32[] storage stored = _ruleSignerCommitments[ruleId];
        for (uint256 i = 0; i < signerCommitments_.length; i++) {
            bytes32 commitment = signerCommitments_[i];
            if (commitment == bytes32(0)) revert InvalidReleaseConfig();
            for (uint256 j = 0; j < i; j++) {
                if (signerCommitments_[j] == commitment) {
                    revert InvalidReleaseConfig();
                }
            }
            stored.push(commitment);
        }
    }

    function _needsCommitmentList(
        ReleaseType releaseType_
    ) private pure returns (bool) {
        return releaseType_ == ReleaseType.AtLeastN ||
            releaseType_ == ReleaseType.QuorumSet ||
            releaseType_ == ReleaseType.AllOfSet;
    }

    function _validateReleaseConfig(
        ReleaseType releaseType_,
        bytes32 specificSignerCommitment_,
        uint8 thresholdN_,
        bytes32[] calldata signerCommitments_
    ) private pure {
        if (releaseType_ == ReleaseType.SpecificSigner) {
            if (specificSignerCommitment_ == bytes32(0)) {
                revert InvalidReleaseConfig();
            }
            return;
        }
        if (
            releaseType_ == ReleaseType.AtLeastN ||
            releaseType_ == ReleaseType.QuorumSet
        ) {
            if (
                thresholdN_ == 0 ||
                signerCommitments_.length == 0 ||
                thresholdN_ > signerCommitments_.length
            ) revert InvalidReleaseConfig();
            return;
        }
        if (releaseType_ == ReleaseType.AllOfSet) {
            if (signerCommitments_.length == 0) revert InvalidReleaseConfig();
            return;
        }
        if (releaseType_ == ReleaseType.QuorumAll) {
            if (thresholdN_ == 0) revert InvalidReleaseConfig();
            return;
        }
        if (releaseType_ == ReleaseType.QuorumRequired) {
            if (thresholdN_ == 0) revert InvalidReleaseConfig();
            return;
        }
    }

    function _assertRequiredSigningNotStarted(bytes32 cidId_) private view {
        if (
            envelopeRegistry.envelopeRegistrations(cidId_).requiredSignaturesCount > 0
        ) revert RequiredSigningStarted();
    }

    function _validateQuorumRequiredThreshold(
        bytes32 cidId_,
        uint8 thresholdN_
    ) private view {
        IFSEnvelopeRegistry.EnvelopeRegistrationView memory reg = envelopeRegistry
            .envelopeRegistrations(cidId_);
        if (reg.quorumN > 0) {
            if (thresholdN_ != reg.quorumN) revert InvalidReleaseConfig();
            return;
        }
        if (thresholdN_ == 0 || thresholdN_ > reg.requiredSignersCount) {
            revert InvalidReleaseConfig();
        }
    }

    function _validateQuorumAllThreshold(
        bytes32 cidId_,
        uint8 thresholdN_
    ) private view {
        IFSEnvelopeRegistry.EnvelopeRegistrationView memory reg = envelopeRegistry
            .envelopeRegistrations(cidId_);
        if (thresholdN_ == 0 || thresholdN_ > reg.requiredSignersCount) {
            revert InvalidReleaseConfig();
        }
    }

    function _releaseConditionsMet(
        uint256 ruleId,
        AttachmentRule storage rule
    ) private view returns (bool) {
        bytes32 cidId = rule.cidId;
        ReleaseType rt = rule.releaseType;

        if (
            rt == ReleaseType.AllSigned ||
            rt == ReleaseType.AllRequiredSigned ||
            rt == ReleaseType.AllSignedComplete
        ) {
            return envelopeRegistry.isEnvelopeComplete(cidId);
        }
        if (rt == ReleaseType.SpecificSigner) {
            return envelopeRegistry.hasSigned(cidId, rule.specificSignerCommitment);
        }
        if (rt == ReleaseType.QuorumRequired) {
            IFSEnvelopeRegistry.EnvelopeRegistrationView memory reg = envelopeRegistry
                .envelopeRegistrations(cidId);
            if (reg.quorumN > 0) {
                return envelopeRegistry.isEnvelopeComplete(cidId);
            }
            return reg.requiredSignaturesCount >= rule.thresholdN;
        }
        if (rt == ReleaseType.QuorumAll) {
            return envelopeRegistry.rosterSignedCount(cidId) >= rule.thresholdN;
        }

        bytes32[] storage commitments = _ruleSignerCommitments[ruleId];
        if (rt == ReleaseType.AllOfSet) {
            for (uint256 i = 0; i < commitments.length; i++) {
                if (!envelopeRegistry.hasSigned(cidId, commitments[i])) return false;
            }
            return commitments.length > 0;
        }

        uint8 signed;
        for (uint256 i = 0; i < commitments.length; i++) {
            if (envelopeRegistry.hasSigned(cidId, commitments[i])) {
                signed++;
                if (signed >= rule.thresholdN) return true;
            }
        }
        return false;
    }
}
