// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import "./errors/EFSCommon.sol";
import "./errors/EFSEnvelopeRegistry.sol";
import "./interfaces/IFSPaymentValidatorRegistry.sol";
import "./interfaces/IFSAttachmentReleaseRegistry.sol";
import "./libraries/FSCommitmentLib.sol";
import "./libraries/FSEnvelopeRoutingLib.sol";
import "./libraries/FSSignatureValidation.sol";

contract FSEnvelopeRegistry is EIP712, Ownable2Step {
    uint256 internal constant SIGNATURE_VALIDITY_PERIOD = 24 hours;
    uint256 internal constant SIGNATURE_CLOCK_DRIFT_TOLERANCE = 5 minutes;

    uint8 internal constant MAX_SIGNERS_PER_ENVELOPE = 128;
    uint8 internal constant MAX_VIEWERS_PER_ENVELOPE = 128;
    uint8 internal constant MAX_ORG_CONTROLLERS = 64;

    enum RoutingMode {
        Parallel,
        Sequential
    }

    struct EnvelopeRegistration {
        bytes32 cidIdentifier;
        address sender;
        uint48 timestamp;
        uint8 requiredSignersCount;
        uint8 requiredSignaturesCount;
        uint8 signaturesCount;
        uint8 quorumN;
        RoutingMode routingMode;
        bytes20 signersCommitment;
        uint48 completedAt;
        bytes20 viewersCommitment;
        uint48 revokedBeforeCompletedAt;
        address revokedBy;
        bytes32 placementCommitment;
        bytes32 documentSha256;
        bytes32 senderEmailCommitment;
        bytes32 senderAuthSubjectCommitment;
        bytes32 orgIdCommitment;
        bytes32 routingOrderHash;
        bytes32 quorumSetHash;
        bytes32[] signerRoster;
        mapping(bytes32 => bool) viewerEmailRegistered;
        mapping(bytes32 => bool) isRequiredSigner;
        mapping(bytes32 => bytes) signatures;
    }

    struct EnvelopeRegistrationView {
        bytes32 cidIdentifier;
        address sender;
        bytes20 signersCommitment;
        bytes20 viewersCommitment;
        bytes32 placementCommitment;
        bytes32 documentSha256;
        bytes32 senderEmailCommitment;
        bytes32 senderAuthSubjectCommitment;
        uint8 requiredSignersCount;
        uint8 requiredSignaturesCount;
        uint8 signaturesCount;
        uint8 quorumN;
        uint8 routingMode;
        bytes32 routingOrderHash;
        bytes32 quorumSetHash;
        uint256 timestamp;
        bytes32 orgIdCommitment;
        uint48 completedAt;
        uint48 revokedBeforeCompletedAt;
        address revokedBy;
    }

    event EnvelopeRegistered(
        bytes32 indexed cidIdentifier,
        address indexed sender,
        uint48 timestamp
    );
    event EnvelopeSigned(
        bytes32 indexed cidIdentifier,
        address indexed sender,
        address indexed signerWallet,
        uint48 timestamp
    );
    event SignerReplacementProposed(
        bytes32 indexed cidIdentifier,
        address indexed recaller,
        bytes32 indexed oldCommitment,
        bytes32 newCommitment,
        bytes20 signersCommitmentAfter
    );
    event SignerReplacementExecuted(
        bytes32 indexed cidIdentifier,
        address indexed recaller,
        bytes32 indexed oldCommitment,
        bytes32 newCommitment,
        uint8 signaturesClearedCount
    );
    event SignerReplacementCancelled(
        bytes32 indexed cidIdentifier,
        address indexed recaller
    );
    event ServerUpdated(
        address indexed previousServer,
        address indexed newServer,
        address indexed changedBy
    );
    event EnvelopeRevokedBeforeComplete(
        bytes32 indexed cidIdentifier,
        address indexed revokedBy,
        uint48 revokedAt
    );
    event EnvelopeCompleted(bytes32 indexed cidIdentifier, uint48 completedAt);
    event OrgControllersSet(bytes32 indexed orgIdCommitment, address[] wallets);
    event SignerWalletBound(
        bytes32 indexed cidIdentifier,
        bytes32 indexed emailCommitment,
        address indexed wallet
    );
    event SatelliteContractsConfigured(
        address indexed paymentValidator,
        address indexed attachmentRelease
    );
    event EnvelopeSignaturesCleared(
        bytes32 indexed cidIdentifier,
        address indexed recaller,
        uint8 signaturesClearedCount
    );

    mapping(bytes32 => EnvelopeRegistration) private _envelopeRegistrations;
    mapping(bytes32 cidId => mapping(bytes32 emailCommitment => address))
        private _boundSignerWallet;
    mapping(bytes32 orgIdCommitment => mapping(address => bool))
        private _isOrgController;
    mapping(bytes32 orgIdCommitment => address[]) private _orgControllerList;

    struct PendingSignerReplacement {
        bytes32 oldCommitment;
        bytes32 newCommitment;
        address recaller;
        uint48 proposedAt;
        bool active;
        bytes32 routingOrderHashAfter;
        bytes32 quorumSetHashAfter;
        bytes20 signersCommitmentAfter;
    }

    mapping(bytes32 => PendingSignerReplacement) private _pendingReplacement;

    address public server;
    address public paymentValidator;
    address public attachmentRelease;

    modifier onlyServer() {
        if (msg.sender != server) revert OnlyServer();
        _;
    }

    constructor(
        address server_
    ) EIP712("FSEnvelopeRegistry", "2") Ownable(msg.sender) {
        if (server_ == address(0)) revert ZeroAddress();
        server = server_;
    }

    function setServer(address newServer_) external onlyOwner {
        if (newServer_ == address(0)) revert ZeroAddress();
        if (newServer_ == server) revert ServerUnchanged();

        address previousServer = server;
        server = newServer_;
        emit ServerUpdated(previousServer, newServer_, msg.sender);
    }

    function setSatelliteContracts(
        address paymentValidator_,
        address attachmentRelease_
    ) external onlyOwner {
        if (paymentValidator != address(0) || attachmentRelease != address(0)) {
            revert SatelliteAlreadyConfigured();
        }
        if (paymentValidator_ == address(0) || attachmentRelease_ == address(0)) {
            revert ZeroAddress();
        }
        paymentValidator = paymentValidator_;
        attachmentRelease = attachmentRelease_;
        emit SatelliteContractsConfigured(paymentValidator_, attachmentRelease_);
    }

    function isOrgController(
        bytes32 orgIdCommitment_,
        address wallet_
    ) external view returns (bool) {
        return _isOrgController[orgIdCommitment_][wallet_];
    }

    function getOrgControllers(
        bytes32 orgIdCommitment_
    ) external view returns (address[] memory) {
        return _orgControllerList[orgIdCommitment_];
    }

    function setOrgControllers(
        bytes32 orgIdCommitment_,
        address[] calldata wallets_
    ) external onlyServer {
        if (orgIdCommitment_ == bytes32(0)) revert ZeroOrgIdCommitment();
        if (wallets_.length > MAX_ORG_CONTROLLERS)
            revert ExceedsMaxOrgControllers();

        address[] storage previous = _orgControllerList[orgIdCommitment_];
        for (uint256 i = 0; i < previous.length; ) {
            _isOrgController[orgIdCommitment_][previous[i]] = false;
            unchecked {
                ++i;
            }
        }
        delete _orgControllerList[orgIdCommitment_];

        for (uint256 i = 0; i < wallets_.length; ) {
            address wallet = wallets_[i];
            if (wallet == address(0)) revert ZeroAddress();
            for (uint256 j = 0; j < i; ) {
                if (wallets_[j] == wallet) revert DuplicateOrgController(wallet);
                unchecked {
                    ++j;
                }
            }
            _isOrgController[orgIdCommitment_][wallet] = true;
            _orgControllerList[orgIdCommitment_].push(wallet);
            unchecked {
                ++i;
            }
        }

        emit OrgControllersSet(orgIdCommitment_, wallets_);
    }

    bytes32 private constant REGISTER_ENVELOPE_TYPEHASH =
        keccak256(
            "RegisterEnvelope(bytes32 cidIdentifier,address sender,bytes20 signersCommitment,bytes20 viewersCommitment,bytes32 placementCommitment,bytes32 documentSha256,bytes32 senderEmailCommitment,bytes32 senderAuthSubjectCommitment,bytes32 orgIdCommitment,bytes32 requiredCommitmentsHash,bytes32 optionalCommitmentsHash,uint8 routingMode,bytes32 routingOrderHash,uint8 quorumN,bytes32 quorumSetHash,uint256 timestamp)"
        );
    bytes32 private constant PROPOSE_SIGNER_REPLACEMENT_TYPEHASH =
        keccak256(
            "ProposeSignerReplacement(bytes32 cidIdentifier,address recaller,bytes32 oldCommitment,bytes32 newCommitment,bytes20 signersCommitmentAfter,uint256 timestamp)"
        );
    bytes32 private constant CANCEL_SIGNER_REPLACEMENT_TYPEHASH =
        keccak256(
            "CancelSignerReplacement(bytes32 cidIdentifier,address recaller,uint256 timestamp)"
        );
    bytes32 private constant RECALL_ENVELOPE_TYPEHASH =
        keccak256(
            "RecallEnvelope(bytes32 cidIdentifier,address recaller,bytes32 orgIdCommitment,uint256 timestamp)"
        );
    bytes32 private constant CLEAR_ENVELOPE_SIGNATURES_TYPEHASH =
        keccak256(
            "ClearEnvelopeSignatures(bytes32 cidIdentifier,address recaller,uint256 timestamp)"
        );
    bytes32 private constant ACK_ENVELOPE_TYPEHASH =
        keccak256(
            "AckEnvelope(bytes32 cidIdentifier,address sender,address viewerWallet,bytes32 viewerEmailCommitment,bytes32 authSubjectCommitment,bytes20 signersCommitment,uint256 timestamp)"
        );
    bytes32 private constant SIGN_ENVELOPE_TYPEHASH =
        keccak256(
            "SignEnvelope(bytes32 cidIdentifier,address sender,address signerWallet,bytes32 signerEmailCommitment,bytes32 authSubjectCommitment,bytes20 dl3SignatureCommitment,bytes32 completionsRoot,uint8 leafSchemaVersion,bytes20 signersCommitment,uint256 timestamp)"
        );

    function computeEmailSignerCommitment(
        bytes32[] calldata commitments_
    ) public pure returns (bytes20) {
        return FSCommitmentLib.computeEmailSignerCommitment(commitments_);
    }

    function hashCommitments(
        bytes32[] calldata commitments_
    ) public pure returns (bytes32) {
        return FSCommitmentLib.hashCommitments(commitments_);
    }

    function envelopeRegistrations(
        bytes32 cidId
    ) external view returns (EnvelopeRegistrationView memory) {
        EnvelopeRegistration storage file = _envelopeRegistrations[cidId];
        return
            EnvelopeRegistrationView({
                cidIdentifier: file.cidIdentifier,
                sender: file.sender,
                signersCommitment: file.signersCommitment,
                viewersCommitment: file.viewersCommitment,
                placementCommitment: file.placementCommitment,
                documentSha256: file.documentSha256,
                senderEmailCommitment: file.senderEmailCommitment,
                senderAuthSubjectCommitment: file.senderAuthSubjectCommitment,
                requiredSignersCount: file.requiredSignersCount,
                requiredSignaturesCount: file.requiredSignaturesCount,
                signaturesCount: file.signaturesCount,
                quorumN: file.quorumN,
                routingMode: uint8(file.routingMode),
                routingOrderHash: file.routingOrderHash,
                quorumSetHash: file.quorumSetHash,
                timestamp: file.timestamp,
                orgIdCommitment: file.orgIdCommitment,
                completedAt: file.completedAt,
                revokedBeforeCompletedAt: file.revokedBeforeCompletedAt,
                revokedBy: file.revokedBy
            });
    }

    function isRevokedBeforeComplete(
        bytes32 cidId
    ) external view returns (bool) {
        return _envelopeRegistrations[cidId].revokedBeforeCompletedAt != 0;
    }

    function isEnvelopeComplete(bytes32 cidId) external view returns (bool) {
        return _envelopeRegistrations[cidId].completedAt != 0;
    }

    struct RegisterEnvelopeSigInput {
        bytes32 cidId;
        address sender;
        bytes20 signersCommitment;
        bytes20 viewersCommitment;
        bytes32 placementCommitment;
        bytes32 documentSha256;
        bytes32 senderEmailCommitment;
        bytes32 senderAuthSubjectCommitment;
        bytes32 orgIdCommitment;
        bytes32 requiredHash;
        bytes32 optionalHash;
        uint8 routingMode;
        bytes32 routingOrderHash;
        uint8 quorumN;
        bytes32 quorumSetHash;
        uint256 timestamp;
    }

    struct RegisterEnvelopeWriteInput {
        bytes32 cidId;
        address sender;
        bytes20 signersCommitment;
        bytes20 viewersCommitment;
        bytes32 placementCommitment;
        bytes32 documentSha256;
        bytes32 senderEmailCommitment;
        bytes32 senderAuthSubjectCommitment;
        uint8 routingMode;
        uint8 quorumN;
        bytes32 routingOrderHash;
        bytes32 quorumSetHash;
        uint256 timestamp;
    }

    struct RegisterEnvelopeInput {
        string pieceCid;
        address sender;
        bytes32[] requiredCommitments;
        bytes32[] optionalCommitments;
        bytes32[] viewerEmailCommitments;
        bytes32 senderEmailCommitment;
        bytes32 senderAuthSubjectCommitment;
        bytes32 orgIdCommitment;
        uint8 routingMode;
        bytes32[] routingOrder;
        uint8 quorumN;
        bytes32[] quorumSet;
        uint256 timestamp;
        bytes signature;
        bytes32 placementCommitment;
        bytes32 documentSha256;
    }

    function registerEnvelope(
        RegisterEnvelopeInput calldata input
    ) external onlyServer {
        if (input.optionalCommitments.length > 0)
            revert OptionalSignersNotSupported();

        FSEnvelopeRoutingLib.validateRegisterRouting(
            input.requiredCommitments,
            input.routingMode,
            input.routingOrder,
            input.quorumN,
            input.quorumSet
        );

        if (input.requiredCommitments.length == 0) revert BadSignersLength();
        if (input.viewerEmailCommitments.length > MAX_VIEWERS_PER_ENVELOPE)
            revert ExceedsMaxViewers();
        if (input.documentSha256 == bytes32(0)) revert ZeroDocumentSha256();

        bytes32 cidId = FSCommitmentLib.cidIdentifier(input.pieceCid);

        RegisterEnvelopeSigInput memory sigInput = RegisterEnvelopeSigInput({
            cidId: cidId,
            sender: input.sender,
            signersCommitment: FSCommitmentLib.computeEmailSignerCommitment(
                input.requiredCommitments
            ),
            viewersCommitment: FSCommitmentLib.computeEmailSignerCommitment(
                input.viewerEmailCommitments
            ),
            placementCommitment: input.placementCommitment,
            documentSha256: input.documentSha256,
            senderEmailCommitment: input.senderEmailCommitment,
            senderAuthSubjectCommitment: input.senderAuthSubjectCommitment,
            orgIdCommitment: input.orgIdCommitment,
            requiredHash: hashCommitments(input.requiredCommitments),
            optionalHash: hashCommitments(input.optionalCommitments),
            routingMode: input.routingMode,
            routingOrderHash: hashCommitments(input.routingOrder),
            quorumN: input.quorumN,
            quorumSetHash: hashCommitments(input.quorumSet),
            timestamp: input.timestamp
        });

        if (!_verifyRegisterEnvelopeSignature(sigInput, input.signature))
            revert InvalidSignature();

        RegisterEnvelopeWriteInput
            memory writeInput = RegisterEnvelopeWriteInput({
                cidId: cidId,
                sender: input.sender,
                signersCommitment: sigInput.signersCommitment,
                viewersCommitment: sigInput.viewersCommitment,
                placementCommitment: input.placementCommitment,
                documentSha256: input.documentSha256,
                senderEmailCommitment: input.senderEmailCommitment,
                senderAuthSubjectCommitment: input.senderAuthSubjectCommitment,
                routingMode: input.routingMode,
                quorumN: input.quorumN,
                routingOrderHash: sigInput.routingOrderHash,
                quorumSetHash: sigInput.quorumSetHash,
                timestamp: input.timestamp
            });

        _writeEnvelopeRegistration(
            writeInput,
            input.orgIdCommitment,
            input.requiredCommitments,
            input.viewerEmailCommitments
        );
    }

    function _writeEnvelopeRegistration(
        RegisterEnvelopeWriteInput memory input,
        bytes32 orgIdCommitment_,
        bytes32[] calldata requiredCommitments_,
        bytes32[] calldata viewerEmailCommitments_
    ) private {
        EnvelopeRegistration storage file = _envelopeRegistrations[input.cidId];
        if (file.timestamp != 0) revert FileAlreadyRegistered();

        file.cidIdentifier = input.cidId;
        file.sender = input.sender;
        file.signersCommitment = input.signersCommitment;
        file.viewersCommitment = input.viewersCommitment;
        file.placementCommitment = input.placementCommitment;
        file.documentSha256 = input.documentSha256;
        file.senderEmailCommitment = input.senderEmailCommitment;
        file.senderAuthSubjectCommitment = input.senderAuthSubjectCommitment;
        file.requiredSignersCount = uint8(requiredCommitments_.length);
        file.quorumN = input.quorumN;
        file.routingMode = RoutingMode(input.routingMode);
        file.routingOrderHash = input.routingOrderHash;
        file.quorumSetHash = input.quorumSetHash;
        file.timestamp = uint48(input.timestamp);
        file.orgIdCommitment = orgIdCommitment_;
        file.completedAt = 0;
        file.revokedBeforeCompletedAt = 0;
        file.revokedBy = address(0);

        for (uint256 i = 0; i < requiredCommitments_.length; ) {
            bytes32 c = requiredCommitments_[i];
            file.isRequiredSigner[c] = true;
            file.signerRoster.push(c);
            unchecked {
                ++i;
            }
        }
        for (uint256 i = 0; i < viewerEmailCommitments_.length; ) {
            file.viewerEmailRegistered[viewerEmailCommitments_[i]] = true;
            unchecked {
                ++i;
            }
        }

        emit EnvelopeRegistered(
            input.cidId,
            input.sender,
            uint48(input.timestamp)
        );
    }

    function _verifyRegisterEnvelopeSignature(
        RegisterEnvelopeSigInput memory input,
        bytes calldata signature_
    ) private view returns (bool) {
        _assertSignatureTimestamp(input.timestamp);
        if (
            input.senderEmailCommitment == bytes32(0) ||
            input.senderAuthSubjectCommitment == bytes32(0)
        ) revert InvalidSignature();

        bytes32 structHash = keccak256(
            abi.encode(
                REGISTER_ENVELOPE_TYPEHASH,
                input.cidId,
                input.sender,
                input.signersCommitment,
                input.viewersCommitment,
                input.placementCommitment,
                input.documentSha256,
                input.senderEmailCommitment,
                input.senderAuthSubjectCommitment,
                input.orgIdCommitment,
                input.requiredHash,
                input.optionalHash,
                input.routingMode,
                input.routingOrderHash,
                input.quorumN,
                input.quorumSetHash,
                input.timestamp
            )
        );
        return
            FSSignatureValidation.isValid(
                input.sender,
                _hashTypedDataV4(structHash),
                signature_
            );
    }

    function getPendingSignerReplacement(
        bytes32 cidId
    )
        external
        view
        returns (
            bool active,
            bytes32 oldCommitment,
            bytes32 newCommitment,
            address recaller,
            bytes32 routingOrderHashAfter,
            bytes32 quorumSetHashAfter,
            bytes20 signersCommitmentAfter,
            uint48 proposedAt
        )
    {
        PendingSignerReplacement storage pending = _pendingReplacement[cidId];
        return (
            pending.active,
            pending.oldCommitment,
            pending.newCommitment,
            pending.recaller,
            pending.routingOrderHashAfter,
            pending.quorumSetHashAfter,
            pending.signersCommitmentAfter,
            pending.proposedAt
        );
    }

    function proposeSignerReplacement(
        string calldata pieceCid_,
        address recaller_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_,
        uint256 timestamp_,
        bytes calldata signature_,
        bytes32[] calldata routingOrderBefore_,
        bytes32[] calldata routingOrderAfter_,
        bytes32[] calldata quorumSetBefore_,
        bytes32[] calldata quorumSetAfter_
    ) external onlyServer {
        _proposeSignerReplacement(
            FSCommitmentLib.cidIdentifier(pieceCid_),
            recaller_,
            oldCommitment_,
            newCommitment_,
            timestamp_,
            signature_,
            routingOrderBefore_,
            routingOrderAfter_,
            quorumSetBefore_,
            quorumSetAfter_
        );
    }

    function _proposeSignerReplacement(
        bytes32 cidId,
        address recaller_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_,
        uint256 timestamp_,
        bytes calldata signature_,
        bytes32[] calldata routingOrderBefore_,
        bytes32[] calldata routingOrderAfter_,
        bytes32[] calldata quorumSetBefore_,
        bytes32[] calldata quorumSetAfter_
    ) private {
        EnvelopeRegistration storage file = _envelopeRegistrations[cidId];
        _validateSignerReplacementInputs(file, oldCommitment_, newCommitment_);
        if (_pendingReplacement[cidId].active) revert SignerReplacementPending();

        _assertRecallerAuthorized(file, recaller_);
        _assertSignatureTimestamp(timestamp_);
        _assertSignerReplacementRouting(
            file,
            routingOrderBefore_,
            routingOrderAfter_,
            quorumSetBefore_,
            quorumSetAfter_,
            oldCommitment_,
            newCommitment_
        );

        bytes20 signersCommitmentAfter = _previewSignersCommitmentAfter(
            file,
            oldCommitment_,
            newCommitment_
        );
        _verifyProposeSignerReplacementSignature(
            cidId,
            recaller_,
            oldCommitment_,
            newCommitment_,
            signersCommitmentAfter,
            timestamp_,
            signature_
        );

        if (_rosterSignedCount(file) == 0) {
            _applySignerSubstitution(
                file,
                cidId,
                oldCommitment_,
                newCommitment_,
                routingOrderAfter_,
                quorumSetAfter_
            );
            emit SignerReplacementExecuted(
                cidId,
                recaller_,
                oldCommitment_,
                newCommitment_,
                0
            );
            return;
        }

        _storePendingSignerReplacement(
            cidId,
            recaller_,
            oldCommitment_,
            newCommitment_,
            signersCommitmentAfter,
            routingOrderAfter_,
            quorumSetAfter_
        );
    }

    function _verifyProposeSignerReplacementSignature(
        bytes32 cidId,
        address recaller_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_,
        bytes20 signersCommitmentAfter_,
        uint256 timestamp_,
        bytes calldata signature_
    ) private view {
        bytes32 structHash = keccak256(
            abi.encode(
                PROPOSE_SIGNER_REPLACEMENT_TYPEHASH,
                cidId,
                recaller_,
                oldCommitment_,
                newCommitment_,
                signersCommitmentAfter_,
                timestamp_
            )
        );
        if (
            !FSSignatureValidation.isValid(
                recaller_,
                _hashTypedDataV4(structHash),
                signature_
            )
        ) revert InvalidSignature();
    }

    function _storePendingSignerReplacement(
        bytes32 cidId,
        address recaller_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_,
        bytes20 signersCommitmentAfter_,
        bytes32[] calldata routingOrderAfter_,
        bytes32[] calldata quorumSetAfter_
    ) private {
        _pendingReplacement[cidId] = PendingSignerReplacement({
            oldCommitment: oldCommitment_,
            newCommitment: newCommitment_,
            recaller: recaller_,
            routingOrderHashAfter: hashCommitments(routingOrderAfter_),
            quorumSetHashAfter: hashCommitments(quorumSetAfter_),
            signersCommitmentAfter: signersCommitmentAfter_,
            proposedAt: uint48(block.timestamp),
            active: true
        });
        emit SignerReplacementProposed(
            cidId,
            recaller_,
            oldCommitment_,
            newCommitment_,
            signersCommitmentAfter_
        );
    }

    function executeSignerReplacement(
        string calldata pieceCid_,
        address recaller_,
        bytes32[] calldata routingOrderAfter_,
        bytes32[] calldata quorumSetAfter_
    ) external onlyServer {
        bytes32 cidId = FSCommitmentLib.cidIdentifier(pieceCid_);
        PendingSignerReplacement storage pending = _pendingReplacement[cidId];
        if (!pending.active) revert NoSignerReplacementPending();

        EnvelopeRegistration storage file = _envelopeRegistrations[cidId];
        if (file.timestamp == 0) revert FileNotRegistered();
        _assertNotRevoked(file);
        _assertNotComplete(file);
        _assertRecallerAuthorized(file, recaller_);

        _validateSignerReplacementInputs(
            file,
            pending.oldCommitment,
            pending.newCommitment
        );

        if (hashCommitments(routingOrderAfter_) != pending.routingOrderHashAfter)
            revert InvalidRoutingConfig();
        if (hashCommitments(quorumSetAfter_) != pending.quorumSetHashAfter)
            revert InvalidRoutingConfig();

        bytes32 oldCommitment = pending.oldCommitment;
        bytes32 newCommitment = pending.newCommitment;
        bytes20 signersCommitmentAfter = pending.signersCommitmentAfter;

        _assertNoPaidLegsIfConfigured(cidId);

        uint8 cleared = _resetEnvelopeSigningProgress(file, cidId);

        _applySignerSubstitution(
            file,
            cidId,
            oldCommitment,
            newCommitment,
            routingOrderAfter_,
            quorumSetAfter_
        );

        if (file.signersCommitment != signersCommitmentAfter)
            revert InvalidSignersCommitment();

        delete _pendingReplacement[cidId];

        emit SignerReplacementExecuted(
            cidId,
            recaller_,
            oldCommitment,
            newCommitment,
            cleared
        );
    }

    function cancelSignerReplacement(
        string calldata pieceCid_,
        address recaller_,
        uint256 timestamp_,
        bytes calldata signature_
    ) external onlyServer {
        bytes32 cidId = FSCommitmentLib.cidIdentifier(pieceCid_);
        PendingSignerReplacement storage pending = _pendingReplacement[cidId];
        if (!pending.active) revert NoSignerReplacementPending();

        EnvelopeRegistration storage file = _envelopeRegistrations[cidId];
        if (file.timestamp == 0) revert FileNotRegistered();
        _assertNotRevoked(file);
        _assertNotComplete(file);
        _assertRecallerAuthorized(file, recaller_);
        _assertSignatureTimestamp(timestamp_);

        bytes32 structHash = keccak256(
            abi.encode(
                CANCEL_SIGNER_REPLACEMENT_TYPEHASH,
                cidId,
                recaller_,
                timestamp_
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        if (!FSSignatureValidation.isValid(recaller_, digest, signature_))
            revert InvalidSignature();

        delete _pendingReplacement[cidId];

        emit SignerReplacementCancelled(cidId, recaller_);
    }

    function recallEnvelope(
        string calldata pieceCid_,
        address recaller_,
        uint256 timestamp_,
        bytes calldata signature_
    ) external onlyServer {
        bytes32 cidId = FSCommitmentLib.cidIdentifier(pieceCid_);
        EnvelopeRegistration storage file = _envelopeRegistrations[cidId];
        if (file.timestamp == 0) revert FileNotRegistered();
        _assertNotRevoked(file);
        _assertNotComplete(file);

        _assertRecallerAuthorized(file, recaller_);
        _assertSignatureTimestamp(timestamp_);

        bytes32 structHash = keccak256(
            abi.encode(
                RECALL_ENVELOPE_TYPEHASH,
                cidId,
                recaller_,
                file.orgIdCommitment,
                timestamp_
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        if (!FSSignatureValidation.isValid(recaller_, digest, signature_))
            revert InvalidSignature();

        if (_pendingReplacement[cidId].active) {
            delete _pendingReplacement[cidId];
        }

        file.revokedBeforeCompletedAt = uint48(timestamp_);
        file.revokedBy = recaller_;
        emit EnvelopeRevokedBeforeComplete(
            cidId,
            recaller_,
            file.revokedBeforeCompletedAt
        );
    }

    function clearEnvelopeSignatures(
        string calldata pieceCid_,
        address recaller_,
        uint256 timestamp_,
        bytes calldata signature_
    ) external onlyServer {
        bytes32 cidId = FSCommitmentLib.cidIdentifier(pieceCid_);
        EnvelopeRegistration storage file = _envelopeRegistrations[cidId];
        if (file.timestamp == 0) revert FileNotRegistered();
        _assertNotRevoked(file);
        _assertNotComplete(file);

        _assertRecallerAuthorized(file, recaller_);
        _assertSignatureTimestamp(timestamp_);

        bytes32 structHash = keccak256(
            abi.encode(
                CLEAR_ENVELOPE_SIGNATURES_TYPEHASH,
                cidId,
                recaller_,
                timestamp_
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        if (!FSSignatureValidation.isValid(recaller_, digest, signature_))
            revert InvalidSignature();

        _assertNoPaidLegsIfConfigured(cidId);

        if (_pendingReplacement[cidId].active) {
            delete _pendingReplacement[cidId];
        }

        uint8 cleared = _resetEnvelopeSigningProgress(file, cidId);

        emit EnvelopeSignaturesCleared(cidId, recaller_, cleared);
    }

    function registerEnvelopeSignature(
        string calldata pieceCid_,
        address sender_,
        address signerWallet_,
        bytes32 signerEmailCommitment_,
        bytes32 authSubjectCommitment_,
        bytes20 dl3SignatureCommitment_,
        uint256 bindTimestamp_,
        bytes calldata bindSignature_,
        uint256 timestamp_,
        bytes calldata signature_,
        bytes32 completionsRoot_,
        uint8 leafSchemaVersion_,
        bytes32[] calldata routingOrder_,
        bytes32[] calldata quorumSet_
    ) external onlyServer {
        bytes32 cidId = FSCommitmentLib.cidIdentifier(pieceCid_);
        EnvelopeRegistration storage file = _envelopeRegistrations[cidId];

        if (file.timestamp == 0) revert FileNotRegistered();
        _assertNotRevoked(file);
        _assertNotComplete(file);
        _assertNoPendingReplacement(cidId);
        if (file.signatures[signerEmailCommitment_].length != 0)
            revert AlreadySigned();

        address bound = _boundSignerWallet[cidId][signerEmailCommitment_];
        if (bound == address(0)) {
            if (
                !_validateEnvelopeAckSignature(
                    file,
                    cidId,
                    sender_,
                    signerWallet_,
                    signerEmailCommitment_,
                    authSubjectCommitment_,
                    bindTimestamp_,
                    bindSignature_
                )
            ) revert InvalidSignature();
            _boundSignerWallet[cidId][signerEmailCommitment_] = signerWallet_;
            emit SignerWalletBound(
                cidId,
                signerEmailCommitment_,
                signerWallet_
            );
        } else if (bound != signerWallet_) {
            revert SignerWalletMismatch();
        }

        if (
            !validateEnvelopeSigningSignature(
                pieceCid_,
                sender_,
                signerWallet_,
                signerEmailCommitment_,
                authSubjectCommitment_,
                dl3SignatureCommitment_,
                timestamp_,
                signature_,
                completionsRoot_,
                leafSchemaVersion_
            )
        ) {
            revert InvalidSignature();
        }

        _assertRoutingCalldata(file, routingOrder_, quorumSet_);

        if (!file.isRequiredSigner[signerEmailCommitment_])
            revert InvalidSigner();

        if (file.routingMode == RoutingMode.Sequential) {
            _enforceSequentialOrder(
                file,
                signerEmailCommitment_,
                routingOrder_
            );
        }

        file.signatures[signerEmailCommitment_] = signature_;
        file.signaturesCount++;
        file.requiredSignaturesCount++;

        emit EnvelopeSigned(
            cidId,
            sender_,
            signerWallet_,
            uint48(block.timestamp)
        );

        _markCompleteIfNeeded(file, cidId, quorumSet_);
    }

    function registerEnvelopeAck(
        string calldata pieceCid_,
        address sender_,
        address viewerWallet_,
        bytes32 viewerEmailCommitment_,
        bytes32 authSubjectCommitment_,
        uint256 timestamp_,
        bytes calldata signature_
    ) external onlyServer {
        bytes32 cidId = FSCommitmentLib.cidIdentifier(pieceCid_);
        EnvelopeRegistration storage file = _envelopeRegistrations[cidId];
        if (file.timestamp == 0) revert FileNotRegistered();
        _assertNotRevoked(file);
        _assertNotComplete(file);
        _assertNoPendingReplacement(cidId);

        if (
            !_validateEnvelopeAckSignature(
                file,
                cidId,
                sender_,
                viewerWallet_,
                viewerEmailCommitment_,
                authSubjectCommitment_,
                timestamp_,
                signature_
            )
        ) revert InvalidSignature();

        if (file.isRequiredSigner[viewerEmailCommitment_]) {
            address bound = _boundSignerWallet[cidId][viewerEmailCommitment_];
            if (bound == address(0)) {
                _boundSignerWallet[cidId][viewerEmailCommitment_] = viewerWallet_;
                emit SignerWalletBound(
                    cidId,
                    viewerEmailCommitment_,
                    viewerWallet_
                );
            } else if (bound != viewerWallet_) {
                revert SignerWalletMismatch();
            }
        }
    }

    function boundSignerWallet(
        bytes32 cidId,
        bytes32 emailCommitment_
    ) external view returns (address) {
        return _boundSignerWallet[cidId][emailCommitment_];
    }

    function isSigner(
        bytes32 cidId,
        bytes32 signerEmailCommitment_
    ) external view returns (bool) {
        return
            _envelopeRegistrations[cidId].isRequiredSigner[
                signerEmailCommitment_
            ];
    }

    function hasSigned(
        bytes32 cidId,
        bytes32 signerEmailCommitment_
    ) external view returns (bool) {
        return
            _envelopeRegistrations[cidId]
                .signatures[signerEmailCommitment_]
                .length != 0;
    }

    function rosterSignedCount(bytes32 cidId) external view returns (uint8) {
        return _rosterSignedCount(_envelopeRegistrations[cidId]);
    }

    function _rosterSignedCount(
        EnvelopeRegistration storage file
    ) private view returns (uint8 signed) {
        if (file.timestamp == 0) return 0;
        for (uint256 i = 0; i < file.signerRoster.length; ) {
            if (file.signatures[file.signerRoster[i]].length != 0) {
                signed++;
            }
            unchecked {
                ++i;
            }
        }
    }

    function validateEnvelopeRegistrationSignature(
        RegisterEnvelopeInput calldata input
    ) public view returns (bool) {
        if (input.optionalCommitments.length > 0) return false;

        RegisterEnvelopeSigInput memory sigInput = RegisterEnvelopeSigInput({
            cidId: FSCommitmentLib.cidIdentifier(input.pieceCid),
            sender: input.sender,
            signersCommitment: FSCommitmentLib.computeEmailSignerCommitment(
                input.requiredCommitments
            ),
            viewersCommitment: FSCommitmentLib.computeEmailSignerCommitment(
                input.viewerEmailCommitments
            ),
            placementCommitment: input.placementCommitment,
            documentSha256: input.documentSha256,
            senderEmailCommitment: input.senderEmailCommitment,
            senderAuthSubjectCommitment: input.senderAuthSubjectCommitment,
            orgIdCommitment: input.orgIdCommitment,
            requiredHash: hashCommitments(input.requiredCommitments),
            optionalHash: hashCommitments(input.optionalCommitments),
            routingMode: input.routingMode,
            routingOrderHash: hashCommitments(input.routingOrder),
            quorumN: input.quorumN,
            quorumSetHash: hashCommitments(input.quorumSet),
            timestamp: input.timestamp
        });
        return _verifyRegisterEnvelopeSignature(sigInput, input.signature);
    }

    function validateEnvelopeSigningSignature(
        string calldata pieceCid_,
        address sender_,
        address signerWallet_,
        bytes32 signerEmailCommitment_,
        bytes32 authSubjectCommitment_,
        bytes20 dl3SignatureCommitment_,
        uint256 timestamp_,
        bytes calldata signature_,
        bytes32 completionsRoot_,
        uint8 leafSchemaVersion_
    ) public view returns (bool) {
        _assertSignatureTimestamp(timestamp_);

        EnvelopeRegistration storage file = _envelopeRegistrations[
            FSCommitmentLib.cidIdentifier(pieceCid_)
        ];
        if (!file.isRequiredSigner[signerEmailCommitment_])
            revert InvalidSigner();
        if (file.sender != sender_) revert InvalidSender();
        _assertNotRevoked(file);
        _assertNotComplete(file);

        bytes32 cidId = FSCommitmentLib.cidIdentifier(pieceCid_);
        if (_pendingReplacement[cidId].active) return false;

        bytes32 structHash = keccak256(
            abi.encode(
                SIGN_ENVELOPE_TYPEHASH,
                cidId,
                sender_,
                signerWallet_,
                signerEmailCommitment_,
                authSubjectCommitment_,
                dl3SignatureCommitment_,
                completionsRoot_,
                leafSchemaVersion_,
                file.signersCommitment,
                timestamp_
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        return FSSignatureValidation.isValid(signerWallet_, digest, signature_);
    }

    function validateEnvelopeAckSignature(
        string calldata pieceCid_,
        address sender_,
        address viewerWallet_,
        bytes32 viewerEmailCommitment_,
        bytes32 authSubjectCommitment_,
        uint256 timestamp_,
        bytes calldata signature_
    ) public view returns (bool) {
        EnvelopeRegistration storage file = _envelopeRegistrations[
            FSCommitmentLib.cidIdentifier(pieceCid_)
        ];
        if (file.timestamp == 0) return false;
        bytes32 cidId = FSCommitmentLib.cidIdentifier(pieceCid_);
        return
            _validateEnvelopeAckSignature(
                file,
                cidId,
                sender_,
                viewerWallet_,
                viewerEmailCommitment_,
                authSubjectCommitment_,
                timestamp_,
                signature_
            );
    }

    function cidIdentifier(
        string calldata pieceCid_
    ) public pure returns (bytes32) {
        return FSCommitmentLib.cidIdentifier(pieceCid_);
    }

    function _assertRecallerAuthorized(
        EnvelopeRegistration storage file,
        address recaller_
    ) private view {
        if (recaller_ == file.sender) return;
        if (
            file.orgIdCommitment != bytes32(0) &&
            _isOrgController[file.orgIdCommitment][recaller_]
        ) return;
        revert UnauthorizedRecaller();
    }

    function _assertNotRevoked(EnvelopeRegistration storage file) private view {
        if (file.revokedBeforeCompletedAt != 0) revert EnvelopeRecalled();
    }

    function _assertNotComplete(
        EnvelopeRegistration storage file
    ) private view {
        if (file.completedAt != 0) revert EnvelopeAlreadyComplete();
    }

    function _assertRoutingCalldata(
        EnvelopeRegistration storage file,
        bytes32[] calldata routingOrder_,
        bytes32[] calldata quorumSet_
    ) private view {
        if (hashCommitments(routingOrder_) != file.routingOrderHash)
            revert InvalidRoutingConfig();
        if (hashCommitments(quorumSet_) != file.quorumSetHash)
            revert InvalidRoutingConfig();
    }

    function _validateSignerReplacementInputs(
        EnvelopeRegistration storage file,
        bytes32 oldCommitment_,
        bytes32 newCommitment_
    ) private view {
        if (oldCommitment_ == bytes32(0) || newCommitment_ == bytes32(0))
            revert ZeroSigner();
        if (file.timestamp == 0) revert FileNotRegistered();
        _assertNotRevoked(file);
        _assertNotComplete(file);
        if (file.signatures[oldCommitment_].length != 0) revert AlreadySigned();
        if (!file.isRequiredSigner[oldCommitment_]) revert InvalidSigner();
        if (file.isRequiredSigner[newCommitment_]) revert DuplicateCommitment();
    }

    function _assertNoPendingReplacement(bytes32 cidId) private view {
        if (_pendingReplacement[cidId].active) revert SignerReplacementPending();
    }

    function _previewSignersCommitmentAfter(
        EnvelopeRegistration storage file,
        bytes32 oldCommitment_,
        bytes32 newCommitment_
    ) private view returns (bytes20) {
        bytes32[] memory roster = _rebuildRoster(file);
        for (uint256 i = 0; i < roster.length; ) {
            if (roster[i] == oldCommitment_) {
                roster[i] = newCommitment_;
            }
            unchecked {
                ++i;
            }
        }
        FSCommitmentLib.sortCommitments(roster);
        return FSCommitmentLib.computeEmailSignerCommitmentMemory(
            roster,
            roster.length
        );
    }

    function _applySignerSubstitution(
        EnvelopeRegistration storage file,
        bytes32 cidId,
        bytes32 oldCommitment_,
        bytes32 newCommitment_,
        bytes32[] calldata routingOrderAfter_,
        bytes32[] calldata quorumSetAfter_
    ) private {
        delete _boundSignerWallet[cidId][oldCommitment_];

        file.isRequiredSigner[oldCommitment_] = false;
        file.isRequiredSigner[newCommitment_] = true;

        for (uint256 i = 0; i < file.signerRoster.length; ) {
            if (file.signerRoster[i] == oldCommitment_) {
                file.signerRoster[i] = newCommitment_;
            }
            unchecked {
                ++i;
            }
        }

        bytes32[] memory roster = _rebuildRoster(file);
        FSCommitmentLib.sortCommitments(roster);
        file.signersCommitment = FSCommitmentLib
            .computeEmailSignerCommitmentMemory(roster, roster.length);
        for (uint256 i = 0; i < roster.length; ) {
            file.signerRoster[i] = roster[i];
            unchecked {
                ++i;
            }
        }

        file.routingOrderHash = hashCommitments(routingOrderAfter_);
        file.quorumSetHash = hashCommitments(quorumSetAfter_);

        _remapSignerCommitmentsIfConfigured(
            cidId,
            oldCommitment_,
            newCommitment_
        );
    }

    function _resetEnvelopeSigningProgress(
        EnvelopeRegistration storage file,
        bytes32 cidId
    ) private returns (uint8 cleared) {
        cleared = _clearAllEnvelopeSignatures(file);
        _clearAllBoundSignerWallets(file, cidId);
    }

    function _assertNoPaidLegsIfConfigured(bytes32 cidId) private view {
        address validator = paymentValidator;
        if (validator == address(0)) return;
        if (IFSPaymentValidatorRegistry(validator).hasAnyPaidLegForCid(cidId)) {
            revert PaymentLegsAlreadyPaid();
        }
    }

    function _remapSignerCommitmentsIfConfigured(
        bytes32 cidId,
        bytes32 oldCommitment,
        bytes32 newCommitment
    ) private {
        address validator = paymentValidator;
        if (validator != address(0)) {
            IFSPaymentValidatorRegistry(validator).remapSignerCommitment(
                cidId,
                oldCommitment,
                newCommitment
            );
        }
        address attachment = attachmentRelease;
        if (attachment != address(0)) {
            IFSAttachmentReleaseRegistry(attachment).remapSignerCommitment(
                cidId,
                oldCommitment,
                newCommitment
            );
        }
    }

    function _clearAllEnvelopeSignatures(
        EnvelopeRegistration storage file
    ) private returns (uint8 cleared) {
        file.completedAt = 0;
        file.requiredSignaturesCount = 0;
        file.signaturesCount = 0;

        for (uint256 i = 0; i < file.signerRoster.length; ) {
            bytes32 c = file.signerRoster[i];
            if (file.signatures[c].length != 0) {
                delete file.signatures[c];
                cleared++;
            }
            unchecked {
                ++i;
            }
        }
    }

    function _assertSignerReplacementRouting(
        EnvelopeRegistration storage file,
        bytes32[] calldata routingOrderBefore_,
        bytes32[] calldata routingOrderAfter_,
        bytes32[] calldata quorumSetBefore_,
        bytes32[] calldata quorumSetAfter_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_
    ) private view {
        if (hashCommitments(routingOrderBefore_) != file.routingOrderHash)
            revert InvalidRoutingConfig();
        if (hashCommitments(quorumSetBefore_) != file.quorumSetHash)
            revert InvalidRoutingConfig();
        if (
            !_commitmentArraySingleSubstitution(
                routingOrderBefore_,
                routingOrderAfter_,
                oldCommitment_,
                newCommitment_
            )
        ) revert InvalidRoutingConfig();
        if (
            !_commitmentArraySingleSubstitution(
                quorumSetBefore_,
                quorumSetAfter_,
                oldCommitment_,
                newCommitment_
            )
        ) revert InvalidRoutingConfig();
    }

    function _commitmentArraySingleSubstitution(
        bytes32[] calldata before_,
        bytes32[] calldata after_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_
    ) private pure returns (bool) {
        if (before_.length != after_.length) return false;
        for (uint256 i = 0; i < before_.length; ) {
            if (before_[i] != after_[i]) {
                if (before_[i] != oldCommitment_ || after_[i] != newCommitment_)
                    return false;
            }
            unchecked {
                ++i;
            }
        }
        return true;
    }

    function _routingComplete(
        EnvelopeRegistration storage file,
        bytes32[] calldata quorumSet_
    ) private view returns (bool) {
        if (file.quorumN > 0) {
            uint8 signed;
            for (uint256 i = 0; i < quorumSet_.length; ) {
                if (file.signatures[quorumSet_[i]].length != 0) {
                    signed++;
                    if (signed >= file.quorumN) return true;
                }
                unchecked {
                    ++i;
                }
            }
            return false;
        }
        return
            file.requiredSignaturesCount == file.requiredSignersCount &&
            file.requiredSignersCount > 0;
    }

    function _markCompleteIfNeeded(
        EnvelopeRegistration storage file,
        bytes32 cidId,
        bytes32[] calldata quorumSet_
    ) private {
        if (file.completedAt != 0) return;
        if (!_routingComplete(file, quorumSet_)) return;
        file.completedAt = uint48(block.timestamp);
        emit EnvelopeCompleted(cidId, file.completedAt);
    }

    function _assertSignatureTimestamp(uint256 timestamp_) private view {
        if (timestamp_ > block.timestamp + SIGNATURE_CLOCK_DRIFT_TOLERANCE)
            revert SignatureFuture();
        if (block.timestamp > timestamp_ + SIGNATURE_VALIDITY_PERIOD)
            revert SignatureExpired();
    }

    function _rebuildRoster(
        EnvelopeRegistration storage file
    ) private view returns (bytes32[] memory roster) {
        roster = new bytes32[](file.signerRoster.length);
        for (uint256 i = 0; i < file.signerRoster.length; ) {
            roster[i] = file.signerRoster[i];
            unchecked {
                ++i;
            }
        }
    }

    function _enforceSequentialOrder(
        EnvelopeRegistration storage file,
        bytes32 signerEmailCommitment_,
        bytes32[] calldata routingOrder_
    ) private view {
        for (uint256 i = 0; i < routingOrder_.length; ) {
            bytes32 c = routingOrder_[i];
            if (c == signerEmailCommitment_) {
                for (uint256 j = 0; j < i; ) {
                    if (file.signatures[routingOrder_[j]].length == 0)
                        revert SequentialOrderViolation();
                    unchecked {
                        ++j;
                    }
                }
                return;
            }
            unchecked {
                ++i;
            }
        }
        revert InvalidSigner();
    }

    function _validateEnvelopeAckSignature(
        EnvelopeRegistration storage file,
        bytes32 cidId,
        address sender_,
        address viewerWallet_,
        bytes32 viewerEmailCommitment_,
        bytes32 authSubjectCommitment_,
        uint256 timestamp_,
        bytes calldata signature_
    ) private view returns (bool) {
        _assertSignatureTimestamp(timestamp_);
        if (
            !file.viewerEmailRegistered[viewerEmailCommitment_] &&
            !file.isRequiredSigner[viewerEmailCommitment_]
        ) revert InvalidSigner();
        if (file.sender != sender_) revert InvalidSender();
        _assertNotRevoked(file);
        _assertNotComplete(file);

        bytes32 structHash = keccak256(
            abi.encode(
                ACK_ENVELOPE_TYPEHASH,
                cidId,
                sender_,
                viewerWallet_,
                viewerEmailCommitment_,
                authSubjectCommitment_,
                file.signersCommitment,
                timestamp_
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        return FSSignatureValidation.isValid(viewerWallet_, digest, signature_);
    }

    function _clearAllBoundSignerWallets(
        EnvelopeRegistration storage file,
        bytes32 cidId
    ) private {
        for (uint256 i = 0; i < file.signerRoster.length; ) {
            delete _boundSignerWallet[cidId][file.signerRoster[i]];
            unchecked {
                ++i;
            }
        }
    }
}
