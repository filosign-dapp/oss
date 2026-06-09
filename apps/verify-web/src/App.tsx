import { useState } from "react";
import { DropZone } from "./components/DropZone";
import { ProofSummaryTable } from "./components/ProofSummaryTable";
import { TechnicalAuditTable } from "./components/TechnicalAuditTable";
import { ThemeToggle } from "./components/ThemeToggle";
import { VerificationVerdict } from "./components/VerificationVerdict";
import type { VerifyRunResult } from "./lib/run-verify";

export function App() {
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [result, setResult] = useState<VerifyRunResult | null>(null);

	return (
		<main className="page">
			<header className="page-header">
				<div className="hero">
					<div className="brand-lockup">
						<div className="brand-logo-wrap">
							<img
								src="/logo.webp"
								alt=""
								className="brand-logo"
								width={32}
								height={32}
							/>
						</div>
						<p className="brand-name">Filosign OSS</p>
					</div>
					<h1>Verify your proof packet</h1>
					<p className="lede">
						Drop a Filosign proof packet ZIP to check it against the blockchain.
					</p>
				</div>
				<ThemeToggle />
			</header>

			<DropZone
				onBusyChange={setBusy}
				onComplete={(next) => {
					setError(null);
					setResult(next);
				}}
				onError={(message) => {
					setResult(null);
					setError(message);
				}}
			/>

			{busy ? <p className="footnote">Running verification…</p> : null}
			{error ? <section className="banner banner-fail">{error}</section> : null}
			{result ? (
				<>
					<VerificationVerdict report={result.report} />
					<ProofSummaryTable report={result.report} />
					<TechnicalAuditTable checks={result.report.technicalChecks} />
				</>
			) : null}
		</main>
	);
}
