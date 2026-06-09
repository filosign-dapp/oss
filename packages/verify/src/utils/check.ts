import type { CheckResult, CheckStatus, CheckTier } from "../types";

export function normalizeHex(value: string): string {
	return value.toLowerCase().replace(/^0x/, "");
}

export function bytes20Hex(value: string): `0x${string}` {
	const hex = normalizeHex(value);
	return `0x${hex.slice(-40)}` as `0x${string}`;
}

export function compareCheck(args: {
	id: string;
	tier: CheckTier;
	expected: string;
	actual: string;
	message?: string;
}): CheckResult {
	const expected = normalizeHex(args.expected);
	const actual = normalizeHex(args.actual);
	return {
		id: args.id,
		tier: args.tier,
		status: expected === actual ? "pass" : "fail",
		expected: `0x${expected}`,
		actual: `0x${actual}`,
		message: args.message,
	};
}

export function statusCheck(args: {
	id: string;
	tier: CheckTier;
	status: CheckStatus;
	message?: string;
}): CheckResult {
	return {
		id: args.id,
		tier: args.tier,
		status: args.status,
		message: args.message,
	};
}

export function summarizeChecks(results: CheckResult[]) {
	let passed = 0;
	let failed = 0;
	let skipped = 0;
	let warned = 0;
	for (const result of results) {
		switch (result.status) {
			case "pass":
				passed++;
				break;
			case "fail":
				failed++;
				break;
			case "skip":
				skipped++;
				break;
			case "warn":
				warned++;
				break;
		}
	}
	return {
		passed,
		failed,
		skipped,
		warned,
		total: results.length,
		results,
	};
}
