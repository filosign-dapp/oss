import {
	chainDisplayName,
	defaultRpcUrlForChain,
} from "@filosign/contracts/chains";
import type { VerifySummary } from "@filosign/verify";
import { parsePacket, verifyPacket } from "@filosign/verify";
import {
	buildVerificationReport,
	type VerificationReport,
} from "./build-verification-report";

export type VerifyRunResult = {
	summary: VerifySummary;
	fileName: string;
	chainId: number;
	chainName: string;
	report: VerificationReport;
};

export async function runVerifyFromZip(file: File): Promise<VerifyRunResult> {
	const bytes = new Uint8Array(await file.arrayBuffer());
	const parsed = parsePacket(bytes);
	const chainId = parsed.bundle.chainId;
	const chainName = chainDisplayName(chainId);
	const rpcUrl = defaultRpcUrlForChain(chainId);

	if (!rpcUrl) {
		throw new Error(`No RPC configured for ${chainName} (${chainId})`);
	}

	const summary = await verifyPacket({
		zipBytes: bytes,
		rpcUrl,
		tiers: ["local", "chain", "documents"],
	});

	const report = buildVerificationReport({
		fileName: file.name,
		chainId,
		chainName,
		packet: parsed,
		summary,
	});

	return {
		summary,
		fileName: file.name,
		chainId,
		chainName,
		report,
	};
}
