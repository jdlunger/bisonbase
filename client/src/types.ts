// Column specs and the row types inferred from them.

/** The column types a table can declare. */
export type ColumnType = 'text' | 'integer' | 'real' | 'boolean' | 'blob' | 'json'

/** Any value that survives JSON.stringify / JSON.parse. */
export type Json = string | number | boolean | null | readonly Json[] | { readonly [key: string]: Json }

interface TypeMap {
  text: string
  integer: number
  real: number
  boolean: boolean
  blob: Uint8Array
  json: Json
}

/** `"text"`, or `"text?"` for a nullable column. */
type BaseSpec = ColumnType | `${ColumnType}?`

type ValueOfBase<B> = B extends `${infer T extends ColumnType}?`
  ? TypeMap[T] | null
  : B extends ColumnType
    ? TypeMap[B]
    : never

/** `[type, default]`: the default must have the column's type. */
type WithDefault<B> = B extends BaseSpec ? readonly [B, ValueOfBase<B>] : never

/**
 * A column: `"text"`, `"text?"` (nullable), or `["boolean", false]` (with a default).
 * Nullable columns and columns with a default are optional on insert.
 */
export type ColumnSpec = BaseSpec | WithDefault<BaseSpec>

/** The columns passed to `createTable`. `id` is added automatically. */
export type Columns = { readonly [name: string]: ColumnSpec }

type BaseOf<S> = S extends readonly [infer B, unknown] ? B : S

/** The TypeScript type of a column's values. */
export type ValueOf<S> = ValueOfBase<BaseOf<S>>

type Simplify<T> = { [K in keyof T]: T[K] } & {}

type OptionalKeys<C> = {
  [K in keyof C]: C[K] extends readonly unknown[] ? K : C[K] extends `${string}?` ? K : never
}[keyof C]

/** A row as read from a table with these columns. */
export type RowFor<C> = Simplify<{ id: number } & { -readonly [K in keyof C]: ValueOf<C[K]> }>

/** What `insert` takes: nullable columns and columns with a default may be left out. */
export type InsertFor<C> = Simplify<
  { id?: number } & { -readonly [K in Exclude<keyof C, OptionalKeys<C>>]: ValueOf<C[K]> } & {
    -readonly [K in OptionalKeys<C>]?: ValueOf<C[K]>
  }
>

/** What `update` takes: any subset of the columns. */
export type UpdateFor<C> = Simplify<{ -readonly [K in keyof C]?: ValueOf<C[K]> }>

/** Comparisons other than equality, e.g. `{ start: { $gte: from, $lt: to } }`. */
export interface Ops<T> {
  $ne?: T
  $lt?: T
  $lte?: T
  $gt?: T
  $gte?: T
  $in?: readonly T[]
}

/** Rows match when every listed column matches. `null` matches NULL. */
export type Where<R> = { [K in keyof R]?: R[K] | Ops<R[K]> }

/** A column name, optionally followed by `" asc"` or `" desc"`. */
export type OrderBy<R> = (keyof R & string) | `${keyof R & string} ${'asc' | 'desc'}`

export interface SelectOptions<R> {
  where?: Where<R>
  orderBy?: OrderBy<R> | readonly OrderBy<R>[]
  limit?: number
  offset?: number
}

/** A value as sent to or returned by the bisonbase API. */
export type Wire = string | number | null | { $base64: string }
