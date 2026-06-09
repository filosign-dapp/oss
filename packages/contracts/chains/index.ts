import type { Address, Chain } from "viem";
import { getAddress } from "viem";
import { base, baseSepolia, hardhat } from "viem/chains";
import manifest from "./manifest.json";

export type ChainManifestEntry = {
	name: string;
	registryAddress?: Address;
	paymentValidatorAddress?: Address;
	attachmentReleaseAddress?: Address;
	explorerTxUrl: string;
	defaultRpcUrl?: string;
};

export type ChainManifest = Record<string, ChainManifestEntry>;

const VIEM_CHAINS: Record<number, Chain> = {
	[base.id]: base,
	[baseSepolia.id]: baseSepolia,
	[hardhat.id]: hardhat,
};

const parsed = manifest as Record<
	string,
	{
		name: string;
		registryAddress?: string;
		paymentValidatorAddress?: string;
		attachmentReleaseAddress?: string;
		explorerTxUrl: string;
		defaultRpcUrl?: string;
	}
>;

export const chainManifest: ChainManifest = Object.fromEntries(
	Object.entries(parsed).map(([chainId, entry]) => [
		chainId,
		{
			name: entry.name,
			registryAddress: entry.registryAddress
				? getAddress(entry.registryAddress)
				: undefined,
			paymentValidatorAddress: entry.paymentValidatorAddress
				? getAddress(entry.paymentValidatorAddress)
				: undefined,
			attachmentReleaseAddress: entry.attachmentReleaseAddress
				? getAddress(entry.attachmentReleaseAddress)
				: undefined,
			explorerTxUrl: entry.explorerTxUrl,
			defaultRpcUrl: entry.defaultRpcUrl,
		},
	]),
);

export function getChainManifest(chainId: number): ChainManifestEntry | null {
	return chainManifest[String(chainId)] ?? null;
}

export function chainDisplayName(chainId: number): string {
	return (
		getChainManifest(chainId)?.name ??
		VIEM_CHAINS[chainId]?.name ??
		`Chain ${chainId}`
	);
}

export function chainForViem(chainId: number): Chain {
	const known = VIEM_CHAINS[chainId];
	if (known) return known;

	const entry = getChainManifest(chainId);
	return {
		id: chainId,
		name: entry?.name ?? `Chain ${chainId}`,
		nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
		rpcUrls: {
			default: {
				http: entry?.defaultRpcUrl ? [entry.defaultRpcUrl] : [],
			},
		},
	};
}

export function defaultRpcUrlForChain(chainId: number): string | null {
	const entry = getChainManifest(chainId);
	if (entry?.defaultRpcUrl) return entry.defaultRpcUrl;
	return VIEM_CHAINS[chainId]?.rpcUrls.default.http[0] ?? null;
}

export type VerifierNetwork = "local" | "testnet" | "mainnet";

export type VerifierNetworkOption = {
	id: VerifierNetwork;
	label: string;
	chainId: number;
};

export const VERIFIER_NETWORKS: VerifierNetworkOption[] = [
	{ id: "local", label: "Local (Hardhat)", chainId: hardhat.id },
	{ id: "testnet", label: "Testnet (Base Sepolia)", chainId: baseSepolia.id },
	{ id: "mainnet", label: "Mainnet (Base)", chainId: base.id },
];

export function chainIdForNetwork(network: VerifierNetwork): number {
	const option = VERIFIER_NETWORKS.find((entry) => entry.id === network);
	if (!option) {
		throw new Error(`Unknown verifier network: ${network}`);
	}
	return option.chainId;
}

export function networkForChainId(chainId: number): VerifierNetwork | null {
	return (
		VERIFIER_NETWORKS.find((entry) => entry.chainId === chainId)?.id ?? null
	);
}

export function networkLabel(network: VerifierNetwork): string {
	return (
		VERIFIER_NETWORKS.find((entry) => entry.id === network)?.label ?? network
	);
}

export function explorerTxUrl(chainId: number, txHash: string): string | null {
	const entry = getChainManifest(chainId);
	if (!entry?.explorerTxUrl) return null;
	return `${entry.explorerTxUrl}${txHash}`;
}
