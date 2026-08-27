import { useEffect, useState } from "react";
import { api, type Token } from "../api";

export function TokensPage() {
  const [tokens, setTokens] = useState<Token[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [minting, setMinting] = useState(false);
  /** Shown once, then gone. Only the hash is stored server-side. */
  const [justMinted, setJustMinted] = useState<string | null>(null);

  const load = () => api.tokens().then(setTokens).catch(show);
  const show = (e: unknown) =>
    setError(e instanceof Error ? e.message : String(e));

  useEffect(() => {
    void load();
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!tokens) return <p className="muted">Loading…</p>;

  return (
    <>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div>
          <h1>API tokens</h1>
          <p className="muted" style={{ margin: 0 }}>
            For callers that cannot hold a browser session — External Secrets,
            CI, the CLI. A token acts as you.
          </p>
        </div>
        <button className="primary" onClick={() => setMinting(true)}>
          New token
        </button>
      </div>

      {justMinted && (
        <div className="card" style={{ marginTop: 14 }}>
          <strong>Copy this now.</strong> It is shown once and never again —
          only its hash is stored, so a lost token is replaced rather than
          recovered.
          <div className="value" style={{ marginTop: 8 }}>
            {justMinted}
          </div>
          <button style={{ marginTop: 8 }} onClick={() => setJustMinted(null)}>
            I have copied it
          </button>
        </div>
      )}

      <div style={{ height: 14 }} />

      {tokens.length === 0 ? (
        <div className="card muted">You have no tokens.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Id</th>
              <th>Created</th>
              <th>Last used</th>
              <th>Expires</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {tokens.map((token) => (
              <tr key={token.id}>
                <td>{token.name}</td>
                {/* The public half — what an audit row names. */}
                <td className="mono muted">{token.id}</td>
                <td className="muted">
                  {new Date(token.created_at).toLocaleDateString()}
                </td>
                <td className="muted">
                  {token.last_used
                    ? new Date(token.last_used).toLocaleString()
                    : "never"}
                </td>
                <td className="muted">
                  {token.expires_at
                    ? new Date(token.expires_at).toLocaleDateString()
                    : "never"}
                </td>
                <td>
                  <button
                    className="danger"
                    onClick={() => {
                      api.revokeToken(token.id).then(load).catch(show);
                    }}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {minting && (
        <MintDialog
          onClose={() => setMinting(false)}
          onMinted={(plaintext) => {
            setMinting(false);
            setJustMinted(plaintext);
            void load();
          }}
        />
      )}
    </>
  );
}

function MintDialog({
  onClose,
  onMinted,
}: {
  onClose: () => void;
  onMinted: (plaintext: string) => void;
}) {
  const [name, setName] = useState("");
  const [days, setDays] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h1>New token</h1>

        <div className="field">
          <label htmlFor="name">
            Name — the only thing that answers "can I delete this one" later
          </label>
          <input
            id="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="eso — payments prod"
            maxLength={80}
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
          <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
            Leave this at 0 for a reconcile loop. An expiry on the credential a
            reconciler presents is an outage scheduled for a day nobody picked.
          </p>
        </div>

        {error && <p className="error">{error}</p>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button onClick={onClose}>Cancel</button>
          <button
            className="primary"
            disabled={saving || !name.trim()}
            onClick={() => {
              setSaving(true);
              api
                .mintToken(name.trim(), days)
                .then((minted) => onMinted(minted.token))
                .catch((e: unknown) => {
                  setError(e instanceof Error ? e.message : String(e));
                  setSaving(false);
                });
            }}
          >
            {saving ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
