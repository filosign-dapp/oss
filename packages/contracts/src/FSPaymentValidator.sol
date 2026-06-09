// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "./errors/EFSPaymentValidator.sol";
import { EnvelopeRecalled } from "./errors/EFSEnvelopeRegistry.sol";
import "./interfaces/IFSEnvelopeRegistry.sol";

contract FSPaymentValidator is ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint8 internal constant MAX_PAYOUT_LEGS = 32;
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

    IFSEnvelopeRegistry public immutable envelopeRegistry;
    uint256 public immutable deploymentChainId;

    uint256 public nextRuleId;
    mapping(uint256 ruleId => PaymentRule) public rules;
    mapping(uint256 ruleId => PayoutLeg[]) private _ruleLegs;
    mapping(uint256 ruleId => bytes32[]) private _ruleSignerCommitments;
    mapping(bytes32 cidId => uint256[]) private _ruleIdsByCid;
    /// @dev Bit i set when leg i has been paid (supports up to 256 legs; product caps at 32).
    mapping(uint256 ruleId => uint256) public legPaidBitmap;

    event PaymentRuleRegistered(
        uint256 indexed ruleId,
        bytes32 indexed cidId,
        address indexed payer,
        address token,
        ReleaseType releaseType
    );

    event PaymentRuleUpdated(uint256 indexed ruleId, bytes32 indexed cidId);
    event PaymentRuleCancelled(uint256 indexed ruleId, bytes32 indexed cidId);
    event PayoutExecuted(
        uint256 indexed ruleId,
        bytes32 indexed cidId,
        address indexed recipient,
        uint256 amount
    );

    event PayoutLegExecuted(
        uint256 indexed ruleId,
        bytes32 indexed cidId,
        uint256 legIndex,
        address indexed recipient,
        uint256 amount
    );

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

    function registerRule(
        address payer_,
        address token_,
        bytes32 cidId_,
        ReleaseType releaseType_,
        bytes32 specificSignerCommitment_,
        uint8 thresholdN_,
        uint64 expiresAt_,
        bytes32[] calldata signerCommitments_,
        PayoutLeg[] calldata legs_
    ) external returns (uint256 ruleId) {
        if (msg.sender != payer_) revert UnauthorizedRuleRegistration();
        _assertFileRegistered(cidId_);
        _validateLegs(payer_, token_, legs_);
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

        if (_ruleIdsByCid[cidId_].length >= MAX_RULES_PER_CID) {
            revert ExceedsMaxRulesPerCid();
        }

        ruleId = nextRuleId++;
        PaymentRule storage rule = rules[ruleId];
        rule.payer = payer_;
        rule.token = token_;
        rule.cidId = cidId_;
        rule.releaseType = releaseType_;
        rule.specificSignerCommitment = specificSignerCommitment_;
        rule.thresholdN = thresholdN_;
        rule.expiresAt = expiresAt_;

        _storeLegs(ruleId, legs_);
        if (_needsCommitmentList(releaseType_)) {
            _storeSignerCommitments(ruleId, signerCommitments_);
        }

        _ruleIdsByCid[cidId_].push(ruleId);

        emit PaymentRuleRegistered(
            ruleId,
            cidId_,
            payer_,
            token_,
            releaseType_
        );
    }

    function updatePayoutRule(
        uint256 ruleId,
        ReleaseType releaseType_,
        bytes32 specificSignerCommitment_,
        uint8 thresholdN_,
        uint64 expiresAt_,
        bytes32[] calldata signerCommitments_,
        PayoutLeg[] calldata legs_
    ) external nonReentrant {
        PaymentRule storage rule = rules[ruleId];
        if (rule.payer == address(0)) revert InvalidPayer();
        if (msg.sender != rule.payer) revert UnauthorizedRuleRegistration();
        if (rule.executed || rule.cancelled) revert RuleAlreadyExecuted();
        if (legPaidBitmap[ruleId] != 0) revert RuleAlreadyExecuted();
        _assertRequiredSigningNotStarted(rule.cidId);
        _assertNotRevoked(rule.cidId);

        _validateLegs(rule.payer, rule.token, legs_);
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

        uint256 totalAmount;
        for (uint256 i = 0; i < legs_.length; ) {
            unchecked {
                totalAmount += legs_[i].amount;
                ++i;
            }
        }
        if (
            IERC20(rule.token).allowance(rule.payer, address(this)) < totalAmount
        ) {
            revert InsufficientAllowance();
        }

        rule.releaseType = releaseType_;
        rule.specificSignerCommitment = specificSignerCommitment_;
        rule.thresholdN = thresholdN_;
        rule.expiresAt = expiresAt_;

        delete _ruleLegs[ruleId];
        delete _ruleSignerCommitments[ruleId];
        legPaidBitmap[ruleId] = 0;
        _storeLegs(ruleId, legs_);
        if (_needsCommitmentList(releaseType_)) {
            _storeSignerCommitments(ruleId, signerCommitments_);
        }

        emit PaymentRuleUpdated(ruleId, rule.cidId);
    }

    function cancelPayoutRule(uint256 ruleId) external nonReentrant {
        PaymentRule storage rule = rules[ruleId];
        if (rule.payer == address(0)) revert InvalidPayer();
        if (msg.sender != rule.payer) revert UnauthorizedRuleRegistration();
        if (rule.executed) revert RuleAlreadyExecuted();
        if (rule.cancelled) revert RuleAlreadyCancelled();
        if (legPaidBitmap[ruleId] != 0) revert RuleAlreadyExecuted();
        _assertRequiredSigningNotStarted(rule.cidId);
        _assertNotRevoked(rule.cidId);
        rule.cancelled = true;
        emit PaymentRuleCancelled(ruleId, rule.cidId);
    }

    function hasAnyPaidLegForCid(
        bytes32 cidId_
    ) external view returns (bool) {
        uint256[] storage ruleIds = _ruleIdsByCid[cidId_];
        uint256 len = ruleIds.length;
        for (uint256 i = 0; i < len; ) {
            if (legPaidBitmap[ruleIds[i]] != 0) return true;
            unchecked {
                ++i;
            }
        }
        return false;
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
            PaymentRule storage rule = rules[ruleId];
            if (rule.payer == address(0) || rule.cancelled || rule.executed) {
                unchecked {
                    ++i;
                }
                continue;
            }
            if (legPaidBitmap[ruleId] != 0) {
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

    function executePayoutLeg(
        uint256 ruleId,
        uint256 legIndex
    ) external nonReentrant {
        _executePayoutLeg(ruleId, legIndex);
    }

    /// @dev Pays all unpaid legs in one transaction (atomic). Prefer `executePayoutLeg` for production.
    function executePayout(uint256 ruleId) external nonReentrant {
        _assertRuleExecutable(ruleId);
        PayoutLeg[] storage legs = _ruleLegs[ruleId];
        uint256 len = legs.length;
        for (uint256 i = 0; i < len; ) {
            if (!_isLegPaid(ruleId, i)) {
                _executePayoutLeg(ruleId, i);
            }
            unchecked {
                ++i;
            }
        }
    }

    function canExecute(uint256 ruleId) external view returns (bool) {
        return _canExecuteRule(ruleId);
    }

    function isLegPaid(
        uint256 ruleId,
        uint256 legIndex
    ) external view returns (bool) {
        if (legIndex >= _ruleLegs[ruleId].length) return false;
        return _isLegPaid(ruleId, legIndex);
    }

    function unpaidLegCount(
        uint256 ruleId
    ) external view returns (uint256 count) {
        PayoutLeg[] storage legs = _ruleLegs[ruleId];
        uint256 len = legs.length;
        for (uint256 i = 0; i < len; ) {
            if (!_isLegPaid(ruleId, i)) {
                unchecked {
                    ++count;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    function ruleLegs(uint256 ruleId) external view returns (PayoutLeg[] memory) {
        return _ruleLegs[ruleId];
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

    function _assertFileRegistered(bytes32 cidId_) private view {
        if (envelopeRegistry.envelopeRegistrations(cidId_).timestamp == 0) {
            revert FileNotRegistered();
        }
        if (envelopeRegistry.isRevokedBeforeComplete(cidId_))
            revert EnvelopeRecalled();
    }

    function _assertNotRevoked(bytes32 cidId_) private view {
        if (envelopeRegistry.isRevokedBeforeComplete(cidId_))
            revert EnvelopeRecalled();
    }

    function _validateLegs(
        address payer_,
        address token_,
        PayoutLeg[] calldata legs_
    ) private view {
        if (payer_ == address(0) || token_ == address(0)) revert InvalidPayer();
        if (legs_.length == 0 || legs_.length > MAX_PAYOUT_LEGS)
            revert ExceedsMaxLegs();
        address validator = address(this);
        for (uint256 i = 0; i < legs_.length; i++) {
            if (legs_[i].recipient == address(0)) revert InvalidPayer();
            if (legs_[i].amount == 0) revert InvalidAmount();
            if (legs_[i].recipient == payer_) revert PayerCannotBeRecipient();
            if (legs_[i].recipient == validator)
                revert RecipientCannotBeValidator();
            if (legs_[i].recipient == token_)
                revert RecipientCannotBeToken();
        }
    }

    function _assertRuleExecutable(uint256 ruleId) private view {
        PaymentRule storage rule = rules[ruleId];
        if (rule.executed || rule.cancelled || rule.payer == address(0))
            revert RuleNotExecutable();
        if (_isRuleExpired(rule)) revert RuleNotExecutable();
        if (envelopeRegistry.isRevokedBeforeComplete(rule.cidId))
            revert EnvelopeRecalled();
        if (!_releaseConditionsMet(ruleId, rule)) revert RuleNotExecutable();
    }

    function _canExecuteRule(uint256 ruleId) private view returns (bool) {
        PaymentRule storage rule = rules[ruleId];
        if (rule.executed || rule.cancelled || rule.payer == address(0))
            return false;
        if (_isRuleExpired(rule)) return false;
        if (envelopeRegistry.isRevokedBeforeComplete(rule.cidId)) return false;
        if (!_releaseConditionsMet(ruleId, rule)) return false;
        return _unpaidLegCount(ruleId) > 0;
    }

    function _unpaidLegCount(uint256 ruleId) private view returns (uint256 count) {
        PayoutLeg[] storage legs = _ruleLegs[ruleId];
        uint256 len = legs.length;
        for (uint256 i = 0; i < len; ) {
            if (!_isLegPaid(ruleId, i)) {
                unchecked {
                    ++count;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    function _isLegPaid(
        uint256 ruleId,
        uint256 legIndex
    ) private view returns (bool) {
        return (legPaidBitmap[ruleId] & (uint256(1) << legIndex)) != 0;
    }

    function _setLegPaid(uint256 ruleId, uint256 legIndex) private {
        legPaidBitmap[ruleId] |= uint256(1) << legIndex;
    }

    function _executePayoutLeg(uint256 ruleId, uint256 legIndex) private {
        _assertRuleExecutable(ruleId);
        PaymentRule storage rule = rules[ruleId];
        PayoutLeg[] storage legs = _ruleLegs[ruleId];
        if (legIndex >= legs.length) revert InvalidLegIndex();
        if (_isLegPaid(ruleId, legIndex)) revert LegAlreadyPaid();

        PayoutLeg storage leg = legs[legIndex];
        address token = rule.token;
        address payer = rule.payer;

        _setLegPaid(ruleId, legIndex);
        if (_unpaidLegCount(ruleId) == 0) {
            rule.executed = true;
        }

        uint256 beforeBal = IERC20(token).balanceOf(leg.recipient);
        IERC20(token).safeTransferFrom(payer, leg.recipient, leg.amount);
        uint256 afterBal = IERC20(token).balanceOf(leg.recipient);
        if (afterBal - beforeBal < leg.amount)
            revert InsufficientTransferReceived();

        emit PayoutLegExecuted(
            ruleId,
            rule.cidId,
            legIndex,
            leg.recipient,
            leg.amount
        );
        emit PayoutExecuted(ruleId, rule.cidId, leg.recipient, leg.amount);
    }

    function _validateExpiresAt(uint64 expiresAt_) private view {
        if (expiresAt_ != 0 && expiresAt_ <= block.timestamp)
            revert InvalidReleaseConfig();
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
        PaymentRule storage rule
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

    function _storeLegs(uint256 ruleId, PayoutLeg[] calldata legs_) private {
        PayoutLeg[] storage stored = _ruleLegs[ruleId];
        for (uint256 i = 0; i < legs_.length; i++) {
            stored.push(legs_[i]);
        }
    }

    function _needsCommitmentList(
        ReleaseType releaseType_
    ) private pure returns (bool) {
        return releaseType_ == ReleaseType.AtLeastN ||
            releaseType_ == ReleaseType.QuorumSet ||
            releaseType_ == ReleaseType.AllOfSet;
    }

    function _storeSignerCommitments(
        uint256 ruleId,
        bytes32[] calldata signerCommitments_
    ) private {
        if (signerCommitments_.length > MAX_RULE_COMMITMENTS)
            revert ExceedsMaxCommitments();
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

    function _validateReleaseConfig(
        ReleaseType releaseType_,
        bytes32 specificSignerCommitment_,
        uint8 thresholdN_,
        bytes32[] calldata signerCommitments_
    ) private pure {
        if (releaseType_ == ReleaseType.SpecificSigner) {
            if (specificSignerCommitment_ == bytes32(0))
                revert InvalidReleaseConfig();
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
        if (
            thresholdN_ == 0 || thresholdN_ > reg.requiredSignersCount
        ) revert InvalidReleaseConfig();
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
        PaymentRule storage rule
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
