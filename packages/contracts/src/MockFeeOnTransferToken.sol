// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Test-only token that deducts 1% on every transfer (fee-on-transfer quirk).
contract MockFeeOnTransferToken is ERC20, Ownable {
    uint256 public constant FEE_BPS = 100;

    constructor(address initialOwner) ERC20("Mock Fee Token", "FEE") Ownable(initialOwner) {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function _update(
        address from,
        address to,
        uint256 value
    ) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 fee = (value * FEE_BPS) / 10_000;
            if (fee > 0) {
                super._update(from, address(this), fee);
                value -= fee;
            }
        }
        super._update(from, to, value);
    }
}
