// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "../errors/EFSEnvelopeRegistry.sol";
import "./FSCommitmentLib.sol";

/// @dev Register-time routing and quorum validation for FSEnvelopeRegistry.
library FSEnvelopeRoutingLib {
    uint8 internal constant ROUTING_PARALLEL = 0;
    uint8 internal constant ROUTING_SEQUENTIAL = 1;

    function validateRegisterRouting(
        bytes32[] calldata requiredCommitments_,
        uint8 routingMode_,
        bytes32[] calldata routingOrder_,
        uint8 quorumN_,
        bytes32[] calldata quorumSet_
    ) internal pure {
        if (requiredCommitments_.length == 0) revert InvalidRoutingConfig();
        if (
            requiredCommitments_.length >
            FSCommitmentLib.MAX_SIGNERS_PER_ENVELOPE
        ) revert ExceedsMaxSigners();
        if (routingOrder_.length > FSCommitmentLib.MAX_SIGNERS_PER_ENVELOPE)
            revert ExceedsMaxSigners();
        if (quorumSet_.length > FSCommitmentLib.MAX_SIGNERS_PER_ENVELOPE)
            revert ExceedsMaxSigners();

        FSCommitmentLib.assertSortedUnique(requiredCommitments_);

        if (routingMode_ > ROUTING_SEQUENTIAL) revert InvalidRoutingConfig();

        if (routingMode_ == ROUTING_SEQUENTIAL) {
            if (routingOrder_.length == 0) revert InvalidRoutingConfig();
            if (routingOrder_.length != requiredCommitments_.length)
                revert InvalidRoutingConfig();
            assertRoutingOrderMatchesRequired(
                routingOrder_,
                requiredCommitments_
            );
        } else if (routingOrder_.length > 0) {
            revert InvalidRoutingConfig();
        }

        if (quorumSet_.length > 0) {
            FSCommitmentLib.assertSortedUnique(quorumSet_);
            if (quorumN_ == 0 || quorumN_ > quorumSet_.length)
                revert InvalidQuorumConfig();
            for (uint256 i = 0; i < quorumSet_.length; i++) {
                bool inRoster;
                for (uint256 j = 0; j < requiredCommitments_.length; j++) {
                    if (quorumSet_[i] == requiredCommitments_[j]) {
                        inRoster = true;
                        break;
                    }
                }
                if (!inRoster) revert InvalidQuorumConfig();
            }
        } else if (quorumN_ != 0) {
            revert InvalidQuorumConfig();
        }
    }

    function assertRoutingOrderMatchesRequired(
        bytes32[] calldata order_,
        bytes32[] calldata required_
    ) private pure {
        if (order_.length != required_.length) revert InvalidRoutingConfig();
        for (uint256 i = 0; i < order_.length; i++) {
            bool found;
            for (uint256 j = 0; j < required_.length; j++) {
                if (order_[i] == required_[j]) {
                    found = true;
                    break;
                }
            }
            if (!found) revert InvalidRoutingConfig();
        }
        for (uint256 i = 0; i < required_.length; i++) {
            bool found;
            for (uint256 j = 0; j < order_.length; j++) {
                if (required_[i] == order_[j]) {
                    found = true;
                    break;
                }
            }
            if (!found) revert InvalidRoutingConfig();
        }
    }
}
