import { useEffect, useState } from "react";
import { api, type AuditEntry } from "../api";

/** Reads are the interesting ones here, so they get a colour of their own. */
function actionTag(action: string) {
  const notable = action === "reveal" || action === "delete";
  return (
    <span className={notable ? "tag locked" : "tag"}>{action}</span>
  );
}

export function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [only, setOnly] = useState("");

  useEffect(() => {
    api
      .audit()
      .then(setEntries)
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e)),
      );
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!entries) return <p className="muted">Loading…</p>;

  const shown = only ? entries.filter((e) => e.action === only) : entries;

  return (
    <>
      <h1>Audit</h1>
      <p className="muted" style={{ marginTop: 0 }}>
        Everything, reads included. For a secrets console the interesting
        question is far more often <em>who looked at this</em> than{" "}
        <em>who changed it</em>.
      </p>

      <div className="field" style={{ maxWidth: 220 }}>
        <label htmlFor="only">Action</label>
        <select id="only" value={only} onChange={(e) => setOnly(e.target.value)}>
          <option value="">everything</option>
          {["reveal", "create", "update", "delete", "delegate", "revoke", "transfer"].map(
            (action) => (
              <option key={action} value={action}>
                {action}
              </option>
            ),
          )}
        </select>
      </div>

      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Who</th>
            <th>Action</th>
            <th>Secret</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((entry) => (
            <tr key={entry.id}>
              <td className="muted">{new Date(entry.at).toLocaleString()}</td>
              <td>
                {entry.actor}
                {entry.via_token && (
                  <>
                    {" "}
                    <span className="tag mono">token {entry.via_token}</span>
                  </>
                )}
              </td>
              <td>{actionTag(entry.action)}</td>
              <td>
                <span className="muted">{entry.store}</span> /{" "}
                {entry.secret_id ? (
                  <a href={`#/secrets/${entry.secret_id}`}>{entry.secret}</a>
                ) : (
                  entry.secret
                )}
              </td>
              <td className="muted">
                {entry.subject ?? entry.keys?.join(", ") ?? entry.note ?? ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {shown.length === 0 && <p className="muted">Nothing recorded yet.</p>}
    </>
  );
}
