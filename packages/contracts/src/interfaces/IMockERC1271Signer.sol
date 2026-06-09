// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// Auto-generated from src/MockERC1271Signer.sol — DO NOT EDIT (regenerate with the script only)

interface IMockERC1271Signer {
    function valid() external view returns (bool);
    function setValid(bool valid_) external;
    function isValidSignature(bytes32, bytes memory) external view returns (bytes4);
}
