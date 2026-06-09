// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";

contract MockERC1271Signer is IERC1271 {
    bool public valid;

    constructor(bool valid_) {
        valid = valid_;
    }

    function setValid(bool valid_) external {
        valid = valid_;
    }

    function isValidSignature(bytes32, bytes memory) external view override returns (bytes4) {
        return valid ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
