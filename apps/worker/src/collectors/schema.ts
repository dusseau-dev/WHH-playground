// Copyright (C) 2025 Keygraph, Inc.

import { type Static, type TSchema, type TSchemaOptions, Type } from 'typebox';
import { Value } from 'typebox/value';

/** TypeBox string enum whose static type remains the exact literal union. */
export function stringEnum<const T extends readonly string[]>(values: T, options: TSchemaOptions = {}) {
  return Type.Unsafe<T[number]>({ ...options, type: 'string', enum: [...values] });
}

/** Strip fields the tool schema did not offer before retaining agent output. */
export function cleanInput<T extends TSchema>(schema: T, input: Static<T>): Static<T> {
  return Value.Clean(schema, structuredClone(input)) as Static<T>;
}

export function toolResult(payload: Record<string, unknown>) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }], details: undefined };
}
