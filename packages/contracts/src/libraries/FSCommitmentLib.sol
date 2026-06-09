// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "../errors/EFSEnvelopeRegistry.sol";

/// @dev Sorted commitment lists, roster merge, and piece CID hashing for FSEnvelopeRegistry.
library FSCommitmentLib {
    uint8 internal constant MAX_SIGNERS_PER_ENVELOPE = 128;

    function cidIdentifier(
        string calldata pieceCid_
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(pieceCid_));
    }

    function hashCommitments(
        bytes32[] calldata commitments_
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(commitments_));
    }

    /// Sorted unique commitments (ascending); `ripemd160(packed)`; empty list => zero `bytes20`.
    function computeEmailSignerCommitment(
        bytes32[] calldata commitments_
    ) internal pure returns (bytes20) {
        return computeEmailSignerCommitmentMemory(
            commitments_,
            commitments_.length
        );
    }

    function computeEmailSignerCommitmentMemory(
        bytes32[] memory commitments_,
        uint256 len
    ) internal pure returns (bytes20) {
        if (len == 0) {
            return bytes20(0);
        }
        if (len > MAX_SIGNERS_PER_ENVELOPE) revert ExceedsMaxSigners();
        for (uint256 i = 0; i < len; ) {
            if (commitments_[i] == bytes32(0)) revert ZeroSigner();
            if (i > 0 && commitments_[i] <= commitments_[i - 1])
                revert UnsortedSigners();
            unchecked {
                ++i;
            }
        }
        bytes32[] memory slice = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            slice[i] = commitments_[i];
        }
        return ripemd160(abi.encodePacked(slice));
    }

    function sortCommitments(bytes32[] memory commitments_) internal pure {
        for (uint256 i = 1; i < commitments_.length; ) {
            bytes32 key = commitments_[i];
            uint256 j = i;
            while (j > 0 && commitments_[j - 1] > key) {
                commitments_[j] = commitments_[j - 1];
                unchecked {
                    --j;
                }
            }
            commitments_[j] = key;
            unchecked {
                ++i;
            }
        }
    }

    function mergeSortedCommitments(
        bytes32[] calldata required_,
        bytes32[] calldata optional_
    ) internal pure returns (bytes32[] memory merged) {
        merged = new bytes32[](required_.length + optional_.length);
        uint256 i;
        uint256 j;
        uint256 k;
        while (i < required_.length && j < optional_.length) {
            if (required_[i] < optional_[j]) {
                merged[k++] = required_[i++];
            } else {
                merged[k++] = optional_[j++];
            }
        }
        while (i < required_.length) merged[k++] = required_[i++];
        while (j < optional_.length) merged[k++] = optional_[j++];
    }

    function assertSortedUnique(
        bytes32[] calldata commitments_
    ) internal pure {
        for (uint256 i = 0; i < commitments_.length; i++) {
            if (commitments_[i] == bytes32(0)) revert ZeroSigner();
            if (i > 0 && commitments_[i] <= commitments_[i - 1])
                revert UnsortedSigners();
        }
    }
}
