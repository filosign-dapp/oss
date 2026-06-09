// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

interface IFSPaymentValidatorRegistry {
    function hasAnyPaidLegForCid(bytes32 cidId_) external view returns (bool);

    function remapSignerCommitment(
        bytes32 cidId_,
        bytes32 oldCommitment_,
        bytes32 newCommitment_
    ) external;
}
