// What the console asks the backend for.
//
// Its own types rather than generated ones: the API is small, and a hand-written
// type is a place to write down what a field means.

export type Level = "guest" | "read" | "write";

export interface Me {
  handle: string;
  groups: string[];
  roles: string[];
  is_admin: boolean;
  may_create: boolean;
  /** Whether a Directory is configured. Without one an API token cannot see a
   *  grant addressed to a group, which is why delegating warns. */
  directory: boolean;
  branding: Branding;
}

export interface Branding {
  name: string;
  logo: string;
  favicon: string;
  accent: string;
}

export interface Store {
  id: string;
  title: string;
  allow: string[];
}

export interface Secret {
  /** What every route takes. The name is a label people read. */
  id: string;
  store: string;
  name: string;
  labels?: Record<string, string>;
  latest_version?: string;
  level: Level | null;
  /** owner | admin | delegated | nothing — why this caller can see it. */
  basis: string;
}

export interface Version {
  id: string;
  state: "enabled" | "disabled" | "destroyed";
}

export interface Grant {
  id: string;
  subject_kind: "user" | "group";
  subject: string;
  level: Level;
  keys?: string[];
  granted_by: string;
  granted_at: string;
  expires_at: string | null;
  note?: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  /** The token that acted, absent for a browser session. */
  via_token?: string;
  action: string;
  store: string;
  secret: string;
  version?: string;
  keys?: string[];
  subject?: string;
  note?: string;
}

export interface Token {
  id: string;
  name: string;
  created_at: string;
  expires_at: string | null;
  last_used: string | null;
}

/** A failure the console can show as a sentence. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...init?.headers },
  });

  if (!response.ok) {
    // The backend answers `{ error }`; anything else is a proxy or a crash.
    const body = await response.text();
    let message = body;
    try {
      message = (JSON.parse(body) as { error?: string }).error ?? body;
    } catch {
      // Keep the raw body.
    }
    throw new ApiError(response.status, message || response.statusText);
  }

  if (response.status === 204) return undefined as T;
  const text = await response.text();
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

export const api = {
  me: () => request<Me>("/api/me"),
  stores: () => request<Store[]>("/api/stores"),
  secrets: () => request<Secret[]>("/api/secrets"),
  secret: (id: string) => request<Secret>(`/api/secrets/${id}`),
  versions: (id: string) => request<Version[]>(`/api/secrets/${id}/versions`),
  history: (id: string) => request<AuditEntry[]>(`/api/secrets/${id}/history`),

  /** Reveals a value. Audited — call it only when somebody asked. */
  reveal: async (id: string, key?: string) => {
    const query = key ? `?key=${encodeURIComponent(key)}` : "";
    const response = await fetch(`/api/secrets/${id}/value${query}`);
    if (!response.ok) {
      throw new ApiError(response.status, await response.text());
    }
    return response.text();
  },

  create: (store: string, name: string, value: string, note: string) =>
    request<Secret>("/api/secrets", {
      method: "POST",
      body: JSON.stringify({ store, name, value, note }),
    }),

  patch: (id: string, value: string, note: string) =>
    request<Version>(`/api/secrets/${id}/versions`, {
      method: "POST",
      body: JSON.stringify({ value, note }),
    }),

  remove: (id: string) =>
    request<void>(`/api/secrets/${id}`, { method: "DELETE" }),

  grants: (id: string) => request<Grant[]>(`/api/secrets/${id}/grants`),

  delegate: (
    id: string,
    grant: {
      subject_kind: "user" | "group";
      subject: string;
      level: Level;
      keys: string[];
      days: number;
      note: string;
    },
  ) =>
    request<Grant>(`/api/secrets/${id}/grants`, {
      method: "POST",
      body: JSON.stringify(grant),
    }),

  revoke: (id: string, grantId: string) =>
    request<void>(`/api/secrets/${id}/grants/${grantId}`, { method: "DELETE" }),

  audit: () => request<AuditEntry[]>("/api/audit?limit=200"),

  tokens: () => request<Token[]>("/api/tokens"),
  mintToken: (name: string, days: number) =>
    request<{ id: string; name: string; token: string; expires_at: string | null }>(
      "/api/tokens",
      { method: "POST", body: JSON.stringify({ name, days }) },
    ),
  revokeToken: (id: string) =>
    request<void>(`/api/tokens/${id}`, { method: "DELETE" }),
};
