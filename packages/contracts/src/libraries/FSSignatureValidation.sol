// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @dev EOA (ECDSA) and ERC-1271 contract wallets (e.g. Safe).
library FSSignatureValidation {
    function isValid(
        address signer_,
        bytes32 digest_,
        bytes calldata signature_
    ) internal view returns (bool) {
        return
            SignatureChecker.isValidSignatureNow(signer_, digest_, signature_);
    }
}
