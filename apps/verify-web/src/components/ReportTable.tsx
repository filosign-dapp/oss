import type { VerificationReportRow } from "../lib/build-verification-report";

const RESULT_LABEL: Record<VerificationReportRow["result"], string> = {
	pass: "Match",
	fail: "Mismatch",
	warn: "Not checkable",
	skip: "Skipped",
};

type ReportTableProps = {
	rows: VerificationReportRow[];
};

export function ReportTable({ rows }: ReportTableProps) {
	return (
		<div className="table-wrap">
			<table className="report-table">
				<thead>
					<tr>
						<th scope="col">Item</th>
						<th scope="col">In packet</th>
						<th scope="col">Checked against</th>
						<th scope="col">Result</th>
					</tr>
				</thead>
				<tbody>
					{rows.map((row) => (
						<tr key={`${row.claim}-${row.exportValue}`}>
							<th scope="row">{row.claim}</th>
							<td className="mono" title={row.exportValue}>
								{row.exportValue}
							</td>
							<td>
								{row.verifiedAgainst}
								{row.detail ? <p className="row-detail">{row.detail}</p> : null}
								{row.explorerUrl ? (
									<a href={row.explorerUrl} target="_blank" rel="noreferrer">
										View transaction
									</a>
								) : null}
							</td>
							<td>
								<span className={`result-pill result-${row.result}`}>
									{RESULT_LABEL[row.result]}
								</span>
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}
