import type { Abi } from "viem";
import attachmentReleaseAbiJson from "./FSAttachmentRelease.json";
import envelopeRegistryAbiJson from "./FSEnvelopeRegistry.json";
import paymentValidatorAbiJson from "./FSPaymentValidator.json";

export const envelopeRegistryAbi = envelopeRegistryAbiJson as Abi;
export const paymentValidatorAbi = paymentValidatorAbiJson as Abi;
export const attachmentReleaseAbi = attachmentReleaseAbiJson as Abi;
