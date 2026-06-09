import { useCallback, useState } from "react";
import { runVerifyFromZip, type VerifyRunResult } from "../lib/run-verify";

type DropZoneProps = {
	onComplete: (result: VerifyRunResult) => void;
	onError: (message: string) => void;
	onBusyChange: (busy: boolean) => void;
};

export function DropZone({ onComplete, onError, onBusyChange }: DropZoneProps) {
	const [dragOver, setDragOver] = useState(false);

	const handleFile = useCallback(
		async (file: File) => {
			if (!file.name.toLowerCase().endsWith(".zip")) {
				onError("Please drop a .zip proof packet.");
				return;
			}
			onBusyChange(true);
			try {
				onComplete(await runVerifyFromZip(file));
			} catch (error) {
				const message =
					error instanceof Error ? error.message : "Verification failed";
				onError(message);
			} finally {
				onBusyChange(false);
			}
		},
		[onBusyChange, onComplete, onError],
	);

	return (
		<section
			aria-label="Proof packet upload"
			className={`dropzone${dragOver ? " dropzone-active" : ""}`}
			onDragOver={(event) => {
				event.preventDefault();
				setDragOver(true);
			}}
			onDragLeave={() => setDragOver(false)}
			onDrop={(event) => {
				event.preventDefault();
				setDragOver(false);
				const file = event.dataTransfer.files[0];
				if (file) void handleFile(file);
			}}
		>
			<p>Drop proof packet ZIP here</p>
			<label className="file-button">
				Choose file
				<input
					type="file"
					accept=".zip,application/zip"
					hidden
					onChange={(event) => {
						const file = event.target.files?.[0];
						if (file) void handleFile(file);
					}}
				/>
			</label>
		</section>
	);
}
