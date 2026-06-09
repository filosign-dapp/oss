import type { Hex } from "viem";
import type { PlacementManifest } from "../placement/manifest";
import { uniqueSignerEmailsFromManifest } from "../placement/manifest";
import { emailCommitRoot, sortedCommitsForEmails } from "./email";

export function sortedSignerCommitsForManifest(
	manifest: PlacementManifest,
): Hex[] {
	return sortedCommitsForEmails(uniqueSignerEmailsFromManifest(manifest));
}

export function buildRegistrationEmailCommitments(args: {
	placementManifest: PlacementManifest;
	viewerEmails: string[];
}) {
	const requiredCommitments = sortedSignerCommitsForManifest(
		args.placementManifest,
	);
	const viewerEmailCommitmentsSorted = sortedCommitsForEmails(
		args.viewerEmails,
	);
	return {
		requiredCommitments,
		viewerEmailCommitmentsSorted,
		signersCommitment: emailCommitRoot(requiredCommitments),
		viewersCommitment: emailCommitRoot(viewerEmailCommitmentsSorted),
	};
}
