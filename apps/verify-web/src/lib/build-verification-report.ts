import type {
	CheckResult,
	ParsedProofPacket,
	VerifySummary,
} from "@filosign/verify";

type ComplianceBundle = ParsedProofPacket["bundle"];

export type ReportRowResult = "pass" | "fail" | "warn" | "skip";

export type VerificationReportRow = {
	claim: string;
	exportValue: string;
	verifiedAgainst: string;
	result: ReportRowResult;
	detail?: string;
	explorerUrl?: string | null;
};

export type VerificationReportSection = {
	title: string;
	intro?: string;
	rows: VerificationReportRow[];
};

export type VerificationReport = {
	verdict: "verified" | "failed";
	fileName: string;
	network: { chainId: number; chainName: string };
	counts: {
		passed: number;
		info: number;
		failed: number;
		skipped: number;
	};
	sections: VerificationReportSection[];
	technicalChecks: CheckResult[];
};

function findCheck(
	results: CheckResult[],
	id: string,
): CheckResult | undefined {
	return results.find((result) => result.id === id);
}

function checksMatching(results: CheckResult[], prefix: string): CheckResult[] {
	return results.filter((result) => result.id.startsWith(prefix));
}

function rowFromCheck(
	check: CheckResult | undefined,
	args: {
		claim: string;
		exportValue: string;
		verifiedAgainst: string;
		fallbackResult?: ReportRowResult;
		detail?: string;
	},
): VerificationReportRow {
	if (!check) {
		return {
			claim: args.claim,
			exportValue: args.exportValue,
			verifiedAgainst: args.verifiedAgainst,
			result: args.fallbackResult ?? "skip",
			detail: args.detail ?? "Check not run",
		};
	}
	return {
		claim: args.claim,
		exportValue: args.exportValue,
		verifiedAgainst: args.verifiedAgainst,
		result: check.status,
		detail:
			args.detail ??
			check.message ??
			(check.status === "fail" && check.expected && check.actual
				? `Expected ${check.expected}, got ${check.actual}`
				: undefined),
		explorerUrl: check.explorerUrl,
	};
}

function signerIdentity(signer: ComplianceBundle["signers"][number]): string {
	const parts: string[] = [];
	if (signer.displayName) parts.push(signer.displayName);
	if (signer.email) parts.push(signer.email);
	parts.push(signer.wallet);
	return parts.join(" / ");
}

function truncateHash(value: string, head = 10, tail = 8): string {
	if (value.length <= head + tail + 3) return value;
	return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function buildAboutSection(args: {
	bundle: ComplianceBundle;
	bundleSha256Sidecar: string | null;
	chainName: string;
	results: CheckResult[];
}): VerificationReportSection {
	const { bundle, bundleSha256Sidecar, chainName, results } = args;
	const hashCheck = findCheck(results, "local.bundle.sha256.sidecar");

	return {
		title: "About this workflow",
		rows: [
			{
				claim: "Workflow status",
				exportValue:
					bundle.executionStatus === "fully_executed"
						? "Complete"
						: "Incomplete",
				verifiedAgainst: "Export file",
				result: "pass",
			},
			{
				claim: "Network",
				exportValue: `${chainName} (${bundle.chainId})`,
				verifiedAgainst: "Export file",
				result: "pass",
			},
			{
				claim: "Generated",
				exportValue: bundle.exportedAtIso,
				verifiedAgainst: "Export file",
				result: "pass",
			},
			rowFromCheck(hashCheck, {
				claim: "Proof export hash",
				exportValue: bundleSha256Sidecar ?? "—",
				verifiedAgainst: "Bundle hash",
			}),
			{
				claim: "Document storage ID",
				exportValue: bundle.pieceCid,
				verifiedAgainst: "On-chain registry",
				result:
					findCheck(results, "chain.registration.cidIdentifier")?.status ??
					"skip",
			},
			{
				claim: "Sender wallet",
				exportValue: bundle.registration.sender,
				verifiedAgainst: "On-chain registry",
				result:
					findCheck(results, "chain.registration.sender")?.status ?? "skip",
			},
		],
	};
}

function buildSignersSection(
	bundle: ComplianceBundle,
	results: CheckResult[],
): VerificationReportSection {
	const rows: VerificationReportRow[] = [];

	for (const signer of bundle.signers) {
		const txPrefix = signer.onchainTxHash?.slice(2, 10);
		const txCheck = txPrefix
			? findCheck(results, `chain.tx.${txPrefix}`)
			: undefined;

		rows.push({
			claim: signer.signed
				? "Required signer (signed)"
				: "Required signer (not signed)",
			exportValue: signerIdentity(signer),
			verifiedAgainst: signer.signed ? "Transaction receipt" : "Export only",
			result: signer.signed ? (txCheck?.status ?? "skip") : "pass",
			detail: signer.signedAtIso
				? `Signed at ${signer.signedAtIso}`
				: undefined,
			explorerUrl: txCheck?.explorerUrl,
		});

		if (signer.onchainTxHash) {
			rows.push({
				claim: "Signature transaction",
				exportValue: truncateHash(signer.onchainTxHash),
				verifiedAgainst: txCheck?.message ?? "Transaction receipt",
				result: txCheck?.status ?? "skip",
				explorerUrl: txCheck?.explorerUrl,
			});
		}
	}

	if (rows.length === 0) {
		rows.push({
			claim: "Signers",
			exportValue: "None listed in export",
			verifiedAgainst: "—",
			result: "skip",
		});
	}

	return { title: "Who signed", rows };
}

function buildPublicRegistrationSection(
	bundle: ComplianceBundle,
	results: CheckResult[],
): VerificationReportSection {
	const chainFields: Array<{
		claim: string;
		checkId: string;
		exportValue: string;
	}> = [
		{
			claim: "Placement commitment",
			checkId: "chain.registration.placementCommitment",
			exportValue: bundle.placementCommitment,
		},
		{
			claim: "Document verification root",
			checkId: "chain.registration.documentSha256",
			exportValue: bundle.registration.registerDocumentSha256,
		},
		{
			claim: "Signers roster commitment",
			checkId: "chain.registration.signersCommitment",
			exportValue: bundle.onchainRegistration?.signersCommitment ?? "—",
		},
		{
			claim: "Viewers roster commitment",
			checkId: "chain.registration.viewersCommitment",
			exportValue: bundle.onchainRegistration?.viewersCommitment ?? "—",
		},
		{
			claim: "Sender email commitment",
			checkId: "chain.registration.senderEmailCommitment",
			exportValue: bundle.onchainRegistration?.senderEmailCommitment ?? "—",
		},
	];

	const rows = chainFields
		.filter(
			(field) => findCheck(results, field.checkId) || field.exportValue !== "—",
		)
		.map((field) => {
			const check = findCheck(results, field.checkId);
			return rowFromCheck(check, {
				claim: field.claim,
				exportValue: check?.expected ?? field.exportValue,
				verifiedAgainst: "On-chain registry",
				detail:
					check?.status === "pass" && check.actual
						? `Chain: ${truncateHash(check.actual)}`
						: check?.message,
			});
		});

	const existsCheck = findCheck(results, "chain.registration.exists");
	rows.unshift(
		rowFromCheck(existsCheck, {
			claim: "Envelope registered on-chain",
			exportValue: bundle.pieceCid,
			verifiedAgainst: "On-chain registry",
		}),
	);

	if (bundle.onchainRegistration) {
		const sigCount = findCheck(results, "chain.registration.signaturesCount");
		rows.push(
			rowFromCheck(sigCount, {
				claim: "Signatures recorded on-chain",
				exportValue:
					sigCount?.expected ??
					String(bundle.onchainRegistration.signaturesCount),
				verifiedAgainst: "On-chain registry",
			}),
		);
	}

	return { title: "Public registration", rows };
}

function buildDocumentsSection(
	bundle: ComplianceBundle,
	results: CheckResult[],
): VerificationReportSection {
	const rootCheck = findCheck(results, "documents.merkle.root");
	const rows: VerificationReportRow[] = [
		{
			claim: "Document files",
			exportValue: bundle.placementManifest.documents
				.map((document) => document.name)
				.join(", "),
			verifiedAgainst: "File hash and on-chain root",
			result: rootCheck?.status ?? "skip",
		},
		rowFromCheck(rootCheck, {
			claim: "Document verification root",
			exportValue:
				rootCheck?.expected ?? bundle.registration.registerDocumentSha256,
			verifiedAgainst: "File hash",
		}),
	];

	for (const document of bundle.placementManifest.documents) {
		const proofCheck = findCheck(results, `documents.proof.${document.id}`);
		rows.push(
			rowFromCheck(proofCheck, {
				claim: `Document: ${document.name}`,
				exportValue: truncateHash(document.sha256Plaintext),
				verifiedAgainst: "Merkle proof",
			}),
		);
	}

	return { title: "Documents", rows };
}

function buildTransactionsSection(
	bundle: ComplianceBundle,
	results: CheckResult[],
): VerificationReportSection {
	const rows: VerificationReportRow[] = [];
	const regPrefix = bundle.registration.registrationTxHash.slice(2, 10);
	const regCheck = findCheck(results, `chain.tx.${regPrefix}`);

	rows.push({
		claim: "Registration transaction",
		exportValue: truncateHash(bundle.registration.registrationTxHash),
		verifiedAgainst: regCheck?.message ?? "Transaction receipt",
		result: regCheck?.status ?? "skip",
		explorerUrl: regCheck?.explorerUrl,
	});

	for (const check of checksMatching(results, "chain.tx.")) {
		if (check.id === `chain.tx.${regPrefix}`) continue;
		rows.push({
			claim: "On-chain transaction",
			exportValue: check.id.replace("chain.tx.", "0x"),
			verifiedAgainst: check.message ?? "Transaction receipt",
			result: check.status,
			explorerUrl: check.explorerUrl,
		});
	}

	return { title: "Transactions", rows };
}

function partyLabel(party: ComplianceBundle["parties"][number]): string {
	const name = party.displayName ?? party.email;
	return `${party.role}: ${name}`;
}

function buildNotesSection(
	bundle: ComplianceBundle,
	results: CheckResult[],
): VerificationReportSection | null {
	const warnChecks = results.filter((result) => result.status === "warn");
	if (warnChecks.length === 0) return null;

	const rows: VerificationReportRow[] = [];

	for (const check of warnChecks) {
		const partyMatch = check.id.match(
			/^local\.parties\[(\d+)\]\.authSubjectCommitment$/,
		);
		if (partyMatch) {
			const party = bundle.parties[Number(partyMatch[1])];
			if (!party) continue;
			rows.push({
				claim: "Sign-in provider ID",
				exportValue: partyLabel(party),
				verifiedAgainst: "Filosign",
				result: "warn",
			});
			continue;
		}

		rows.push({
			claim: check.id,
			exportValue: "In export",
			verifiedAgainst: "Not in packet",
			result: "warn",
			detail: check.message,
		});
	}

	if (rows.length === 0) return null;

	return {
		title: "Notes",
		intro:
			"Sign-in identity is stored by Filosign and is not included in this export.",
		rows,
	};
}

function buildSettlementsSection(
	bundle: ComplianceBundle,
	results: CheckResult[],
): VerificationReportSection | null {
	if (bundle.settlements.length === 0) return null;
	const rows: VerificationReportRow[] = [];

	for (const pay of bundle.settlements) {
		const ruleCheck = findCheck(results, `chain.settlement.${pay.onChainRuleId}.exists`);
		const statusCheck = findCheck(results, `chain.settlement.${pay.onChainRuleId}.status`);

		rows.push(
			rowFromCheck(ruleCheck, {
				claim: `Settlement rule ${pay.onChainRuleId}`,
				exportValue: `Token: ${truncateHash(pay.tokenAddress)}`,
				verifiedAgainst: "On-chain rules",
			}),
			rowFromCheck(statusCheck, {
				claim: `Rule ${pay.onChainRuleId} payout state`,
				exportValue: pay.status === "executed" ? "Executed" : "Pending/Cancelled",
				verifiedAgainst: "On-chain status",
			})
		);

		if (pay.payoutTxHash) {
			const txPrefix = pay.payoutTxHash.slice(2, 10);
			const txCheck = findCheck(results, `chain.tx.${txPrefix}`);
			rows.push({
				claim: `Payout transaction (rule ${pay.onChainRuleId})`,
				exportValue: truncateHash(pay.payoutTxHash),
				verifiedAgainst: txCheck?.message ?? "Transaction receipt",
				result: txCheck?.status ?? "skip",
				explorerUrl: txCheck?.explorerUrl,
			});
		}
	}

	return { title: "Payout rules", rows };
}

function buildAttachmentsSection(
	bundle: ComplianceBundle,
	results: CheckResult[],
): VerificationReportSection | null {
	if (bundle.attachments.length === 0) return null;
	const rows: VerificationReportRow[] = [];

	for (const att of bundle.attachments) {
		const attCheck = findCheck(results, `chain.attachment.${att.packetId}.exists`);
		const relCheck = findCheck(results, `chain.attachment.${att.packetId}.released`);

		rows.push(
			{
				claim: "Attachment packet",
				exportValue: att.label ? `${att.label} (${att.packetId})` : att.packetId,
				verifiedAgainst: "Export packet metadata",
				result: "pass",
			},
			rowFromCheck(attCheck, {
				claim: `Attachment ${att.packetId} rule`,
				exportValue: `Release mode: ${att.releaseMode}`,
				verifiedAgainst: "On-chain rules",
			})
		);

		if (att.packetContentHash) {
			const hashCheck = findCheck(
				results,
				`chain.attachment.${att.packetId}.packetContentHash`,
			);
			rows.push(
				rowFromCheck(hashCheck, {
					claim: `Attachment ${att.packetId} content hash`,
					exportValue: truncateHash(att.packetContentHash),
					verifiedAgainst: "On-chain rule",
				}),
			);
		}

		if (att.releaseMode === "conditional" && att.onChainRuleId) {
			rows.push(
				rowFromCheck(relCheck, {
					claim: `Attachment ${att.packetId} state`,
					exportValue: att.unlocked ? "Released" : "Gated",
					verifiedAgainst: "On-chain release state",
				})
			);
		}

		if (att.releaseTxHash) {
			const txPrefix = att.releaseTxHash.slice(2, 10);
			const txCheck = findCheck(results, `chain.tx.${txPrefix}`);
			rows.push({
				claim: `Release transaction (packet ${att.packetId})`,
				exportValue: truncateHash(att.releaseTxHash),
				verifiedAgainst: txCheck?.message ?? "Transaction receipt",
				result: txCheck?.status ?? "skip",
				explorerUrl: txCheck?.explorerUrl,
			});
		}

		for (const byteCheck of checksMatching(
			results,
			`documents.attachments.${att.packetId}`,
		)) {
			if (byteCheck.id.endsWith(".packetContentHash")) {
				rows.push(
					rowFromCheck(byteCheck, {
						claim: `Attachment ${att.packetId} file bundle hash`,
						exportValue: att.packetContentHash
							? truncateHash(att.packetContentHash)
							: "—",
						verifiedAgainst: "Exported file bytes",
					}),
				);
				continue;
			}
			if (byteCheck.id.endsWith(".sha256")) {
				const fileSegment = byteCheck.id
					.slice(`documents.attachments.${att.packetId}.`.length)
					.replace(/\.sha256$/, "");
				rows.push(
					rowFromCheck(byteCheck, {
						claim: `Attachment file: ${fileSegment}`,
						exportValue: byteCheck.expected
							? truncateHash(byteCheck.expected)
							: "—",
						verifiedAgainst: "File bytes in packet",
					}),
				);
			}
		}
	}

	return { title: "Attached files", rows };
}

export function buildVerificationReport(args: {
	fileName: string;
	chainId: number;
	chainName: string;
	packet: ParsedProofPacket;
	summary: VerifySummary;
}): VerificationReport {
	const { bundle } = args.packet;
	const { summary } = args;
	const results = summary.results;

	const sections: VerificationReportSection[] = [
		buildAboutSection({
			bundle,
			bundleSha256Sidecar: args.packet.bundleSha256Sidecar,
			chainName: args.chainName,
			results,
		}),
		buildSignersSection(bundle, results),
		buildPublicRegistrationSection(bundle, results),
		buildDocumentsSection(bundle, results),
		buildTransactionsSection(bundle, results),
	];

	const settlements = buildSettlementsSection(bundle, results);
	if (settlements) sections.push(settlements);

	const attachments = buildAttachmentsSection(bundle, results);
	if (attachments) sections.push(attachments);

	const notes = buildNotesSection(bundle, results);
	if (notes) sections.push(notes);

	return {
		verdict: summary.failed === 0 ? "verified" : "failed",
		fileName: args.fileName,
		network: { chainId: args.chainId, chainName: args.chainName },
		counts: {
			passed: summary.passed,
			info: summary.warned,
			failed: summary.failed,
			skipped: summary.skipped,
		},
		sections,
		technicalChecks: results,
	};
}
