import { z } from "zod";

export const zFieldValueKind = z.enum(["visual", "text", "checkbox", "auto"]);

export const zContentSha256Hex = z.string().regex(/^[0-9a-f]{64}$/, {
	error: "contentSha256 must be 64 lowercase hex chars",
});

export const zFieldCompletionWireRow = z.object({
	fieldId: z.string().min(1),
	valueKind: zFieldValueKind,
	sourceArtifactId: z.uuid().nullable(),
	storageKey: z.string().nullable(),
	contentSha256: zContentSha256Hex.nullable(),
	textValue: z.string().nullable(),
	previewUrl: z.string().nullable(),
	signer: z.string().optional(),
});

export type FieldCompletionWireRow = z.infer<typeof zFieldCompletionWireRow>;
