import type { ComplianceBundle, VerifyManifestV1 } from "@filosign/protocol";
import {
	complianceBundleSha256Hex,
	computeLeafHashV1,
	computePlacementCommitment,
	hashNormalizedSignerEmail,
	merkleRootFromLeafAndSiblings,
} from "@filosign/protocol";
import type { CheckResult } from "../types";
import {
	compareCheck,
	normalizeHex,
	statusCheck,
	summarizeChecks,
} from "../utils/check";

export async function runLocalChecks(args: {
	bundle: ComplianceBundle;
	bundleSha256Sidecar?: string | null;
	manifest?: VerifyManifestV1 | null;
}): Promise<CheckResult[]> {
	const { bundle } = args;
	const results: CheckResult[] = [
		statusCheck({
			id: "local.bundle.schema",
			tier: "local",
			status: "pass",
			message: "bundle.json parsed against zComplianceBundle",
		}),
	];

	const computedHash = await complianceBundleSha256Hex(bundle);
	if (args.bundleSha256Sidecar) {
		results.push(
			compareCheck({
				id: "local.bundle.sha256.sidecar",
				tier: "local",
				expected: args.bundleSha256Sidecar,
				actual: computedHash,
				message: "bundle.sha256 matches canonical bundle JSON",
			}),
		);
	} else {
		results.push(
			statusCheck({
				id: "local.bundle.sha256.sidecar",
				tier: "local",
				status: "skip",
				message: "No bundle.sha256 sidecar in packet",
			}),
		);
	}

	if (args.manifest) {
		results.push(
			compareCheck({
				id: "local.manifest.bundleSha256",
				tier: "local",
				expected: args.manifest.bundleSha256,
				actual: computedHash,
				message: "verify-manifest.json bundleSha256 matches bundle",
			}),
		);
		if (args.bundleSha256Sidecar) {
			results.push(
				compareCheck({
					id: "local.manifest.sidecarMatch",
					tier: "local",
					expected: args.manifest.bundleSha256,
					actual: args.bundleSha256Sidecar,
					message: "Manifest hash matches bundle.sha256 sidecar",
				}),
			);
		}
	}

	results.push(
		compareCheck({
			id: "local.placement.commitment",
			tier: "local",
			expected: bundle.placementCommitment,
			actual: computePlacementCommitment(bundle.placementManifest),
			message: "Placement manifest recomputes to bundle.placementCommitment",
		}),
	);

	for (const [index, party] of bundle.parties.entries()) {
		const recomputed = hashNormalizedSignerEmail(party.email);
		results.push(
			compareCheck({
				id: `local.parties[${index}].emailCommitment`,
				tier: "local",
				expected: party.emailCommitment,
				actual: recomputed,
				message: `Email commitment for ${party.role} ${party.email}`,
			}),
		);
		if (party.authSubjectCommitment) {
			results.push(
				statusCheck({
					id: `local.parties[${index}].authSubjectCommitment`,
					tier: "local",
					status: "warn",
					message:
						"authSubjectCommitment present; independent recompute requires IdP subject (not in bundle)",
				}),
			);
		}
	}

	const snapshot = bundle.onchainRegistration;
	if (snapshot) {
		results.push(
			compareCheck({
				id: "local.snapshot.placementCommitment",
				tier: "local",
				expected: snapshot.placementCommitment,
				actual: bundle.placementCommitment,
			}),
			compareCheck({
				id: "local.snapshot.documentSha256",
				tier: "local",
				expected: snapshot.documentSha256,
				actual: bundle.registration.registerDocumentSha256,
			}),
		);
	}

	for (const [index, signer] of bundle.signers.entries()) {
		if (!signer.completionsRoot || signer.merkleProofs.length === 0) {
			continue;
		}
		for (const proof of signer.merkleProofs) {
			const recomputedRoot = merkleRootFromLeafAndSiblings(
				proof.leafHash,
				proof.siblings,
			);
			results.push(
				compareCheck({
					id: `local.signers[${index}].merkleProof.${proof.fieldId}`,
					tier: "local",
					expected: signer.completionsRoot,
					actual: recomputedRoot,
					message: `Merkle proof for field ${proof.fieldId}`,
				}),
			);
			if (signer.signed && signer.wallet) {
				const leaf = computeLeafHashV1({
					fieldId: proof.fieldId,
					placementCommitment: bundle.placementCommitment,
					pieceCid: bundle.pieceCid,
					signer: signer.wallet,
				});
				results.push(
					compareCheck({
						id: `local.signers[${index}].leafHash.${proof.fieldId}`,
						tier: "local",
						expected: proof.leafHash,
						actual: leaf,
					}),
				);
			}
		}
	}

	return results;
}

export async function verifyLocal(args: {
	bundle: ComplianceBundle;
	bundleSha256Sidecar?: string | null;
	manifest?: VerifyManifestV1 | null;
}) {
	const results = await runLocalChecks(args);
	return summarizeChecks(results);
}

export function bundleHashMatchesSidecar(
	computedHash: string,
	sidecar: string | null | undefined,
): boolean {
	if (!sidecar) return false;
	return normalizeHex(computedHash) === normalizeHex(sidecar);
}
