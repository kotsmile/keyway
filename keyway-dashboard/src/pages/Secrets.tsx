import { useEffect, useState } from "react";
import { api, type Me, type Secret, type Store } from "../api";
import { normalizeValue } from "../value";

export function SecretsPage({ me }: { me: Me }) {
  const [secrets, setSecrets] = useState<Secret[] | null>(null);
  const [stores, setStores] = useState<Store[]>([]);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = () => {
    api.secrets().then(setSecrets).catch(showError);
    api.stores().then(setStores).catch(() => setStores([]));
  };
  const showError = (e: unknown) =>
    setError(e instanceof Error ? e.message : String(e));

  useEffect(load, []);

  if (error) return <p className="error">{error}</p>;
  if (!secrets) return <p className="muted">Loading…</p>;

  const needle = filter.trim().toLowerCase();
  const shown = needle
    ? secrets.filter(
        (s) =>
          s.name.toLowerCase().includes(needle) ||
          s.store.toLowerCase().includes(needle),
      )
    : secrets;

  // Only Stores this deployment lets keyway create in.
  const writable = stores.filter((s) => s.allow.includes("create"));

  return (
    <>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div>
          <h1>Secrets</h1>
          <p className="muted" style={{ margin: 0 }}>
            {secrets.length} you can see, across {stores.length}{" "}
            {stores.length === 1 ? "store" : "stores"}
          </p>
        </div>
        {me.may_create && writable.length > 0 && (
          <button className="primary" onClick={() => setCreating(true)}>
            New secret
          </button>
        )}
      </div>

      <div style={{ margin: "14px 0" }}>
        <input
          placeholder="Filter by name or store…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>

      {shown.length === 0 ? (
        <div className="card muted">
          {secrets.length === 0
            ? "Nothing has been delegated to you yet."
            : "No secret matches that."}
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Store</th>
              <th>Access</th>
              <th>Version</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((secret) => (
              <tr
                key={secret.id}
                className="clickable"
                onClick={() => {
                  window.location.hash = `/secrets/${secret.id}`;
                }}
              >
                <td>{secret.name}</td>
                <td className="muted">{secret.store}</td>
                <td>
                  {secret.level && (
                    <span className="tag level">{secret.level}</span>
                  )}{" "}
                  {/* An owner needs to know they are one: it is what lets them
                      delegate and delete. */}
                  {secret.basis === "owner" && <span className="tag">owner</span>}
                </td>
                <td className="muted mono">{secret.latest_version || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {creating && (
        <CreateDialog
          stores={writable}
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            load();
          }}
        />
      )}
    </>
  );
}

function CreateDialog({
  stores,
  onClose,
  onCreated,
}: {
  stores: Store[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [store, setStore] = useState(stores[0]?.id ?? "");
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const submit = () => {
    setSaving(true);
    setError(null);
    api
      .create(store, name.trim(), normalizeValue(value), note)
      .then(onCreated)
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : String(e));
        setSaving(false);
      });
  };

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h1>New secret</h1>
        <p className="muted">
          You will own it, which means you can change, delegate, transfer or
          delete it whatever role you hold.
        </p>

        <div className="field">
          <label htmlFor="store">Store</label>
          <select
            id="store"
            value={store}
            onChange={(e) => setStore(e.target.value)}
          >
            {stores.map((s) => (
              <option key={s.id} value={s.id}>
                {s.title}
              </option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="name">Name</label>
          <input
            id="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="payments-db"
          />
        </div>

        <div className="field">
          <label htmlFor="value">
            Value — YAML or JSON for key/value, anything else for text
          </label>
          <textarea
            id="value"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={"db_password: …"}
          />
        </div>

        <div className="field">
          <label htmlFor="note">Note</label>
          <input
            id="note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Why this exists"
          />
        </div>

        {error && <p className="error">{error}</p>}

        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button onClick={onClose}>Cancel</button>
          <button
            className="primary"
            onClick={submit}
            disabled={saving || !name.trim() || !store}
          >
            {saving ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
