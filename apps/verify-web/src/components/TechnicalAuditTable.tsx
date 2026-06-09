import type { CheckResult, CheckTier } from "@filosign/verify";
import { labelForCheck, TIER_LABELS } from "../lib/check-labels";

const STATUS_LABEL: Record<CheckResult["status"], string> = {
	pass: "Pass",
	fail: "Fail",
	skip: "Skip",
	warn: "Info",
};

const TIER_ORDER: CheckTier[] = ["local", "chain", "documents"];

type TechnicalAuditTableProps = {
	checks: CheckResult[];
};

export function TechnicalAuditTable({ checks }: TechnicalAuditTableProps) {
	const grouped = TIER_ORDER.map((tier) => ({
		tier,
		label: TIER_LABELS[tier],
		checks: checks.filter((check) => check.tier === tier),
	})).filter((group) => group.checks.length > 0);

	return (
		<details className="technical-audit">
			<summary>Technical details ({checks.length} checks)</summary>
			{grouped.map((group) => (
				<div key={group.tier} className="audit-group">
					<h3>{group.label}</h3>
					<div className="table-wrap">
						<table className="report-table audit-table">
							<thead>
								<tr>
									<th scope="col">Check</th>
									<th scope="col">ID</th>
									<th scope="col">Status</th>
									<th scope="col">Detail</th>
								</tr>
							</thead>
							<tbody>
								{group.checks.map((check) => (
									<tr key={check.id}>
										<td>{labelForCheck(check.id)}</td>
										<td className="mono" title={check.id}>
											{check.id}
										</td>
										<td>
											<span
												className={`result-pill result-${check.status === "warn" ? "warn" : check.status}`}
											>
												{STATUS_LABEL[check.status]}
											</span>
										</td>
										<td>
											{check.message ?? "—"}
											{check.expected &&
											check.actual &&
											check.status === "fail" ? (
												<p className="row-detail">
													expected {check.expected} · actual {check.actual}
												</p>
											) : null}
											{check.explorerUrl ? (
												<a
													href={check.explorerUrl}
													target="_blank"
													rel="noreferrer"
												>
													View transaction
												</a>
											) : null}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</div>
			))}
		</details>
	);
}
