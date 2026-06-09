// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

interface IFSAttachmentReleaseRegistry {
    function remapSignerCommitment(
        bytes32 cidId_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_
    ) external;
}
