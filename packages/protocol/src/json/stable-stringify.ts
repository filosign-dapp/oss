import fjsStringify from "fast-json-stable-stringify";

function stringifyReplacer(_key: string, value: unknown): unknown {
	if (typeof value === "bigint") {
		const asNumber = Number(value);
		if (BigInt(asNumber) === value) return asNumber;
		return value.toString();
	}
	return value;
}

/** Stable JSON for hashing (plain objects; bigints normalized). */
export function stableJsonStringify(obj: unknown): string {
	return fjsStringify(JSON.parse(JSON.stringify(obj, stringifyReplacer)));
}
