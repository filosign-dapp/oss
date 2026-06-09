import { describe, expect, it } from "bun:test";
import { getAddress } from "viem";
import {
	completionsMerkleRootV1,
	computeCidIdentifier,
	computeLeafHashV1,
	computePlacementCommitment,
} from "../src/index";

describe("field completion Merkle", () => {
	it("computeLeafHashV1 is deterministic", () => {
		const params = {
			fieldId: "6d3963cf-0a07-4d06-ae13-c5f5e3d88c91",
			placementCommitment:
				"0xaa480278bf1148637fef7bce84b6125a10c08da3c01aca69ed0b9b30bbd5e255" as const,
			pieceCid:
				"bafkzcibe2o4rad2bs2o35uomwrnal7kg6dvsfh4jlecejh6x2cjnkaaqro7iemerde",
			signer: getAddress("0x7C9a6875e752D5ACD63FE35A2A704D896c4aE32d"),
		};
		expect(computeLeafHashV1(params)).toBe(computeLeafHashV1(params));
	});

	it("completionsMerkleRootV1 matches single-field leaf", () => {
		const placementCommitment =
			"0xaa480278bf1148637fef7bce84b6125a10c08da3c01aca69ed0b9b30bbd5e255" as const;
		const pieceCid =
			"bafkzcibe2o4rad2bs2o35uomwrnal7kg6dvsfh4jlecejh6x2cjnkaaqro7iemerde";
		const signer = getAddress("0x7C9a6875e752D5ACD63FE35A2A704D896c4aE32d");
		const fieldId = "6d3963cf-0a07-4d06-ae13-c5f5e3d88c91";
		const root = completionsMerkleRootV1({
			fieldIds: [fieldId],
			placementCommitment,
			pieceCid,
			signer,
		});
		const leaf = computeLeafHashV1({
			fieldId,
			placementCommitment,
			pieceCid,
			signer,
		});
		expect(root).toBe(leaf);
	});
});

describe("computeCidIdentifier", () => {
	it("hashes piece CID string", () => {
		const cid =
			"bafkzcibe2o4rad2bs2o35uomwrnal7kg6dvsfh4jlecejh6x2cjnkaaqro7iemerde";
		expect(computeCidIdentifier(cid)).toBe(
			"0x7ac1b9499d2b8a6d2e364551f00023e2c9dfca4f74732156171a1685bae5494f",
		);
	});
});

describe("computePlacementCommitment golden vector", () => {
	it("matches known DePIN Day fixture commitment", () => {
		const manifest = {
			version: 1 as const,
			documents: [
				{
					id: "51cb3a2e-b4cd-46e1-a947-b0ffa0124d9c",
					name: "DePIN Day.pdf",
					sha256Plaintext:
						"0x5a65ba36055b0c88ab34117088a62a7a3b10d81d3aa43cdbf97a7496575a5a3e",
					pageCount: 1,
				},
			],
			fields: [
				{
					id: "6d3963cf-0a07-4d06-ae13-c5f5e3d88c91",
					pageIndex: 0,
					rect: {
						x: 0.2609049479166667,
						y: 0.04474852071005917,
						width: 0.3333333333333333,
						height: 0.08284023668639054,
					},
					assignedRecipientEmail: "ishtails@gmail.com",
					required: true,
					type: "signature" as const,
					documentId: "51cb3a2e-b4cd-46e1-a947-b0ffa0124d9c",
				},
			],
		};
		expect(computePlacementCommitment(manifest)).toBe(
			"0xaa480278bf1148637fef7bce84b6125a10c08da3c01aca69ed0b9b30bbd5e255",
		);
	});
});
