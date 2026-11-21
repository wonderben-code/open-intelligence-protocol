// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** How schemas are named and how they refer to each other. */

import { type Static, type TSchema, Type } from "typebox";

/** The `$id` of the schema called `name`: a URN, so that it does not depend on any domain. */
export function schemaId(name: string): string {
  return `urn:oip:schema:${name}`;
}

/** Schema metadata: `$id`, `title` and a description that cites the specification. */
export function meta(name: string, description: string) {
  return { $id: schemaId(name), title: name, description };
}

/**
 * A reference to a named schema. The JSON Schema carries a `$ref`; the static
 * type is the referenced schema's. A schema with an `$id` is only ever used
 * through `ref`, so that it is one resource however often it is used.
 */
export function ref<S extends TSchema>(schema: S) {
  const id: unknown = (schema as { readonly $id?: unknown }).$id;
  if (typeof id !== "string") throw new TypeError("ref() needs a schema with an $id");
  return Type.Unsafe<Static<S>>({ $ref: id });
}

const definitions: Record<string, object> = {};

/**
 * Names a schema that many records share, and returns a reference to it. Each
 * definition is a schema resource of its own (`urn:oip:schema:def:<name>`), so
 * that it is stated once and compiled once. `Defs` bundles them into one
 * document.
 */
export function define<S extends TSchema>(name: string, schema: S) {
  if (Object.hasOwn(definitions, name)) throw new Error(`definition ${name} already exists`);
  const $id = schemaId(`def:${name}`);
  definitions[name] = { $id, ...schema };
  return Type.Unsafe<Static<S>>({ $ref: $id });
}

/**
 * The shared definitions, as one compound schema document: each member of
 * `$defs` is a resource with its own `$id`. Complete once every schema module
 * has loaded.
 */
export const Defs = {
  ...meta(
    "Defs",
    "Value syntaxes and structures that several record types share (core Sections 1, 3, 4, 6 and 8).",
  ),
  $defs: definitions,
};
