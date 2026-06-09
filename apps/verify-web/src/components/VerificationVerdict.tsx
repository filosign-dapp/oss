import type { VerificationReport } from "../lib/build-verification-report";

type VerificationVerdictProps = {
	report: VerificationReport;
};

export function VerificationVerdict({ report }: VerificationVerdictProps) {
	const ok = report.verdict === "verified";

	return (
		<section
			className={`verdict${ok ? " verdict-ok" : " verdict-fail"}`}
			aria-live="polite"
		>
			<p className="verdict-eyebrow">{report.fileName}</p>
			<h2 className="verdict-title">
				{ok ? "Verified" : "Some checks failed"}
			</h2>
			<p className="verdict-summary">
				{report.network.chainName} ({report.network.chainId}){" · "}
				{report.counts.passed} passed
				{report.counts.info > 0 ? ` · ${report.counts.info} info` : ""}
				{report.counts.failed > 0 ? ` · ${report.counts.failed} failed` : ""}
			</p>
		</section>
	);
}
