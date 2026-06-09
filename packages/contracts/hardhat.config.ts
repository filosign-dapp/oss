import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox-viem";

const config: HardhatUserConfig = {
	solidity: {
		version: "0.8.26",
		settings: {
			optimizer: { enabled: true, runs: 400 },
			viaIR: true,
			evmVersion: "cancun",
		},
	},
	sourcify: { enabled: false },
	paths: {
		sources: "./src",
		tests: "./test",
	},
	networks: {
		hardhat: {
			allowUnlimitedContractSize: true,
		},
	},
};

export default config;
