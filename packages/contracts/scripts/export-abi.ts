/**
 * Writes committed ABIs under abis/ from Hardhat compile artifacts.
 * Phase A: FSEnvelopeRegistry only (verify engine dependency).
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const artifactPath = path.join(
	root,
	"artifacts/src/FSEnvelopeRegistry.sol/FSEnvelopeRegistry.json",
);

async function main() {
	const raw = await Bun.file(artifactPath).json();
	const abi = raw.abi;
	if (!Array.isArray(abi)) {
		throw new Error(
			`Missing abi in ${artifactPath}. Run bun run compile first.`,
		);
	}
	await mkdir(path.join(root, "abis"), { recursive: true });
	await writeFile(
		path.join(root, "abis/FSEnvelopeRegistry.json"),
		`${JSON.stringify(abi, null, 2)}\n`,
	);
	console.log("Wrote abis/FSEnvelopeRegistry.json");
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
