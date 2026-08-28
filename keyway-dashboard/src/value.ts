import { parse, stringify } from "yaml";

/** What the value dialogs send as a secret's payload.
 *
 *  The backend never learns about key/value — a kv secret is a JSON blob by
 *  the time it reaches a store — so accepting YAML is purely this console's
 *  affordance: a YAML mapping becomes that JSON blob here.
 *
 *  JSON input is returned byte-for-byte, not reserialised: it is already the
 *  canonical form, and rewriting it would make the stored payload differ from
 *  what the person typed. Anything that is neither JSON nor a YAML mapping is
 *  text and stays exactly as written. */
export function normalizeValue(raw: string): string {
  try {
    JSON.parse(raw);
    return raw;
  } catch {
    // Not JSON; YAML is the next candidate.
  }
  try {
    const parsed: unknown = parse(raw);
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      return JSON.stringify(parsed);
    }
  } catch {
    // Not YAML either.
  }
  return raw;
}

/** A kv payload rendered the way a person reads it: YAML, with multiline
 *  values as block scalars instead of \n-riddled JSON strings.
 *
 *  Returns null when the payload is not a kv blob — plain text is already in
 *  its readable form, and pretending otherwise would corrupt it. */
export function asYaml(raw: string): string | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      return stringify(parsed);
    }
  } catch {
    // Not a kv blob.
  }
  return null;
}
