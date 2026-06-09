// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

error RuleAlreadyExecuted();
error RuleAlreadyCancelled();
error RuleNotExecutable();
error InvalidPayer();
error InvalidAmount();
error InvalidReleaseConfig();
error UnauthorizedRuleRegistration();
error UnauthorizedRuleCancellation();
error FileNotRegistered();
error InsufficientTransferReceived();
error ExceedsMaxLegs();
error ExceedsMaxCommitments();
error InvalidLegIndex();
error LegAlreadyPaid();
error PayerCannotBeRecipient();
error RecipientCannotBeValidator();
error RecipientCannotBeToken();
error RequiredSigningStarted();
error UnauthorizedRegistry();
error ExceedsMaxRulesPerCid();
error InsufficientAllowance();
