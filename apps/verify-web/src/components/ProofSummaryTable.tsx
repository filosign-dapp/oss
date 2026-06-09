import type { VerificationReport } from "../lib/build-verification-report";
import { ReportTable } from "./ReportTable";

type ProofSummaryTableProps = {
	report: VerificationReport;
};

export function ProofSummaryTable({ report }: ProofSummaryTableProps) {
	return (
		<section className="proof-summary">
			<h2>Results</h2>
			{report.sections.map((section) => (
				<div key={section.title} className="report-section">
					<h3>{section.title}</h3>
					{section.intro ? (
						<p className="section-intro">{section.intro}</p>
					) : null}
					<ReportTable rows={section.rows} />
				</div>
			))}
		</section>
	);
}
