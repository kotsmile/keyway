import { useCallback, useEffect, useState } from "react";
import {
  api,
  type AuditEntry,
  type Grant,
  type Level,
  type Me,
  type Secret,
  type Version,
} from "../api";
import { asYaml, normalizeValue } from "../value";

/** Markers a reconciler stamps. A secret carrying one is shown and never
 *  edited — the backend refuses anyway, and a disabled button with a reason
 *  beats a save that silently vanishes on the next sync. */
const RECONCILER_LABELS = [
  "reconcile.external-secrets.io/managed",
  "app.kubernetes.io/managed-by",
];

function managedBy(secret: Secret): string | null {
  for (const key of RECONCILER_LABELS) {
    const value = secret.labels?.[key];
    if (value) return `${key}=${value}`;
  }
  return null;
}

export function SecretPage({ id, me }: { id: string; me: Me }) {
  const [secret, setSecret] = useState<Secret | null>(null);
  const [versions, setVersions] = useState<Version[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [history, setHistory] = useState<AuditEntry[]>([]);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [delegating, setDelegating] = useState(false);

  const load = useCallback(() => {
    api.secret(id).then(setSecret).catch(show);
    api.versions(id).then(setVersions).catch(() => setVersions([]));
    api.grants(id).then(setGrants).catch(() => setGrants([]));
    api.history(id).then(setHistory).catch(() => setHistory([]));
  }, [id]);

  const show = (e: unknown) =>
    setError(e instanceof Error ? e.message : String(e));

  useEffect(load, [load]);

  if (error) return <p className="error">{error}</p>;
  if (!secret) return <p className="muted">Loading…</p>;

  const owns = secret.basis === "owner" || secret.basis === "admin";
  const locked = managedBy(secret);
  const canWrite = secret.level === "write" && !locked;
  const canReveal = secret.level === "read" || secret.level === "write";

  return (
    <>
      <a href="#/secrets" className="muted">
        ← Secrets
      </a>

      <div
        className="row"
        style={{ justifyContent: "space-between", marginTop: 8 }}
      >
        <div>
          <h1>{secret.name}</h1>
          <p className="muted" style={{ margin: 0 }}>
            {secret.store} · <span className="mono">{secret.id}</span>
          </p>
        </div>
        <div className="row">
          {canWrite && <button onClick={() => setEditing(true)}>New version</button>}
          {owns && (
            <button className="primary" onClick={() => setDelegating(true)}>
              Delegate
            </button>
          )}
        </div>
      </div>

      {locked && (
        <div className="warning">
          <strong>Managed by a reconciler</strong> — <code>{locked}</code>. This
          secret is readable here, but an edit would be overwritten on the next
          sync. Change it at its source.
        </div>
      )}

      <h2>Value</h2>
      {canReveal ? (
        revealed === null ? (
          <button
            onClick={() => {
              // Only on a click: reading is an audited reveal, and a page that
              // fetched values on load would fill the log with reads nobody
              // performed.
              api.reveal(id).then(setRevealed).catch(show);
            }}
          >
            Reveal — this is recorded
          </button>
        ) : (
          (() => {
            // YAML is the reading format; the raw JSON blob is what a store
            // actually holds, one click away rather than hidden.
            const yaml = asYaml(revealed);
            return (
              <>
                <div className="value">
                  {yaml === null || showRaw ? revealed : yaml}
                </div>
                <div className="row" style={{ marginTop: 8 }}>
                  <button onClick={() => setRevealed(null)}>Hide</button>
                  {yaml !== null && (
                    <button onClick={() => setShowRaw(!showRaw)}>
                      {showRaw ? "Show YAML" : "Show stored JSON"}
                    </button>
                  )}
                </div>
              </>
            );
          })()
        )
      ) : (
        <p className="muted">
          Your access is <span className="tag level">{secret.level}</span> — you
          can see that this secret exists, but not its value.
        </p>
      )}

      <h2>Who can see this</h2>
      {grants.length === 0 ? (
        <p className="muted">Nobody but its owner.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Subject</th>
              <th>Level</th>
              <th>Keys</th>
              <th>Granted by</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {grants.map((grant) => (
              <tr key={grant.id}>
                <td>
                  <span className="tag">{grant.subject_kind}</span>{" "}
                  {grant.subject}
                </td>
                <td>
                  <span className="tag level">{grant.level}</span>
                </td>
                <td className="muted mono">
                  {grant.keys?.length ? grant.keys.join(", ") : "whole secret"}
                </td>
                <td className="muted">{grant.granted_by}</td>
                <td>
                  {owns && (
                    <button
                      className="danger"
                      onClick={() => {
                        api.revoke(id, grant.id).then(load).catch(show);
                      }}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Versions</h2>
      <table>
        <thead>
          <tr>
            <th>Version</th>
            <th>State</th>
          </tr>
        </thead>
        <tbody>
          {versions.map((version) => (
            <tr key={version.id}>
              <td className="mono">{version.id}</td>
              <td className="muted">{version.state}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>History</h2>
      {history.length === 0 ? (
        <p className="muted">Nothing recorded yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Who</th>
              <th>What</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {history.map((entry) => (
              <tr key={entry.id}>
                <td className="muted">
                  {new Date(entry.at).toLocaleString()}
                </td>
                <td>
                  {entry.actor}
                  {/* Which credential acted, not merely which account. */}
                  {entry.via_token && (
                    <>
                      {" "}
                      <span className="tag mono">token {entry.via_token}</span>
                    </>
                  )}
                </td>
                <td>{entry.action}</td>
                <td className="muted">
                  {entry.subject ?? entry.keys?.join(", ") ?? entry.note ?? ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {editing && (
        <NewVersionDialog
          id={id}
          onClose={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            setRevealed(null);
            load();
          }}
        />
      )}
      {delegating && (
        <DelegateDialog
          id={id}
          me={me}
          onClose={() => setDelegating(false)}
          onGranted={() => {
            setDelegating(false);
            load();
          }}
        />
      )}
    </>
  );
}

function NewVersionDialog({
  id,
  onClose,
  onSaved,
}: {
  id: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h1>New version</h1>
        <p className="muted">
          The current value is not shown here — writing a new one does not
          require reading the old one, and pre-filling it would mean an audited
          reveal every time somebody opened this.
        </p>

        <div className="field">
          <label htmlFor="value">
            Value — YAML or JSON for key/value, anything else for text
          </label>
          <textarea
            id="value"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="note">Note</label>
          <input
            id="note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Why it changed"
          />
        </div>

        {error && <p className="error">{error}</p>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button onClick={onClose}>Cancel</button>
          <button
            className="primary"
            disabled={saving || !value}
            onClick={() => {
              setSaving(true);
              api
                .patch(id, normalizeValue(value), note)
                .then(onSaved)
                .catch((e: unknown) => {
                  setError(e instanceof Error ? e.message : String(e));
                  setSaving(false);
                });
            }}
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

function DelegateDialog({
  id,
  me,
  onClose,
  onGranted,
}: {
  id: string;
  me: Me;
  onClose: () => void;
  onGranted: () => void;
}) {
  const [kind, setKind] = useState<"user" | "group">("user");
  const [subject, setSubject] = useState("");
  const [level, setLevel] = useState<Level>("read");
  const [keys, setKeys] = useState("");
  const [days, setDays] = useState(0);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h1>Delegate</h1>
        <p className="muted">
          A grant opens exactly what it says. It does not let the grantee
          re-delegate or transfer the secret — those belong to ownership.
        </p>

        <div className="field">
          <label htmlFor="kind">Who</label>
          <div className="row">
            <select
              id="kind"
              value={kind}
              onChange={(e) => setKind(e.target.value as "user" | "group")}
              style={{ width: 120 }}
            >
              <option value="user">Person</option>
              <option value="group">Group</option>
            </select>
            <input
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder={kind === "user" ? "alice" : "SRE"}
            />
          </div>
        </div>

        {/* The consequence ADR-0004 names, said at the moment it matters. */}
        {kind === "group" && !me.directory && (
          <div className="warning">
            No directory is configured, so <strong>API tokens cannot see a
            grant made to a group</strong> — only ones addressed to a person by
            name. If this is for External Secrets or CI, delegate to that
            account directly.
          </div>
        )}

        <div className="field">
          <label htmlFor="level">Level</label>
          <select
            id="level"
            value={level}
            onChange={(e) => setLevel(e.target.value as Level)}
          >
            <option value="guest">guest — sees it exists and which keys</option>
            <option value="read">read — may reveal the value</option>
            <option value="write">write — may also push a new version</option>
          </select>
        </div>

        <div className="field">
          <label htmlFor="keys">
            Keys, comma-separated — empty means the whole secret
          </label>
          <input
            id="keys"
            value={keys}
            onChange={(e) => setKeys(e.target.value)}
            placeholder="db_password"
          />
        </div>

        <div className="field">
          <label htmlFor="days">Expires after (days) — 0 never expires</label>
          <input
            id="days"
            type="number"
            min={0}
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
          />
        </div>

        <div className="field">
          <label htmlFor="note">Note</label>
          <input
            id="note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="The sentence the next admin needs"
          />
        </div>

        {error && <p className="error">{error}</p>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button onClick={onClose}>Cancel</button>
          <button
            className="primary"
            disabled={saving || !subject.trim()}
            onClick={() => {
              setSaving(true);
              api
                .delegate(id, {
                  subject_kind: kind,
                  subject: subject.trim(),
                  level,
                  keys: keys
                    .split(",")
                    .map((k) => k.trim())
                    .filter(Boolean),
                  days,
                  note,
                })
                .then(onGranted)
                .catch((e: unknown) => {
                  setError(e instanceof Error ? e.message : String(e));
                  setSaving(false);
                });
            }}
          >
            {saving ? "Granting…" : "Grant"}
          </button>
        </div>
      </div>
    </div>
  );
}
