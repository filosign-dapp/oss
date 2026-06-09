// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// Auto-generated from src/MockFeeOnTransferToken.sol — DO NOT EDIT (regenerate with the script only)

interface IMockFeeOnTransferToken {
    function FEE_BPS() external view returns (uint256);
    function decimals() external pure returns (uint8);
    function mint(address to, uint256 amount) external;
}
