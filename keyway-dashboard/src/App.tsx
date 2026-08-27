import { useCallback, useEffect, useState } from "react";
import { ApiError, api, type Me } from "./api";
import { SecretsPage } from "./pages/Secrets";
import { SecretPage } from "./pages/Secret";
import { TokensPage } from "./pages/Tokens";
import { AuditPage } from "./pages/Audit";

type Route =
  | { page: "secrets" }
  | { page: "secret"; id: string }
  | { page: "tokens" }
  | { page: "audit" };

/** The hash IS the route, so a secret's page can be linked and pasted — which
 *  is how somebody hands a colleague the uuid an ExternalSecret needs. */
function routeFromHash(): Route {
  const hash = window.location.hash.replace(/^#\/?/, "");
  const [page, id] = hash.split("/");
  if (page === "secrets" && id) return { page: "secret", id };
  if (page === "tokens") return { page: "tokens" };
  if (page === "audit") return { page: "audit" };
  return { page: "secrets" };
}

export function App() {
  const [route, setRoute] = useState<Route>(routeFromHash);
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onChange = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  useEffect(() => {
    api
      .me()
      .then((me) => {
        setMe(me);
        applyBranding(me);
      })
      .catch((e: unknown) => {
        // 401 means sign in rather than "something broke".
        if (e instanceof ApiError && e.status === 401) {
          window.location.href = "/auth/login";
          return;
        }
        setError(e instanceof Error ? e.message : String(e));
      });
  }, []);

  const go = useCallback((to: string) => {
    window.location.hash = to;
  }, []);

  if (error) {
    return (
      <div className="main">
        <h1>keyway</h1>
        <p className="error">{error}</p>
      </div>
    );
  }
  if (!me) return <div className="main muted">Loading…</div>;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          {me.branding.logo ? (
            <img src={me.branding.logo} alt="" />
          ) : (
            <span className="dot" />
          )}
          <span>{me.branding.name}</span>
        </div>

        <nav className="nav">
          <button
            onClick={() => go("/secrets")}
            aria-current={
              route.page === "secrets" || route.page === "secret"
                ? "page"
                : undefined
            }
          >
            Secrets
          </button>
          <button
            onClick={() => go("/tokens")}
            aria-current={route.page === "tokens" ? "page" : undefined}
          >
            API tokens
          </button>
          {/* The audit feed is admin-only; the backend refuses it anyway, and
              showing a button that always 403s is a worse answer than hiding
              it. */}
          {me.is_admin && (
            <button
              onClick={() => go("/audit")}
              aria-current={route.page === "audit" ? "page" : undefined}
            >
              Audit
            </button>
          )}
        </nav>

        <div style={{ marginTop: 24 }} className="muted">
          <div>{me.handle}</div>
          {me.groups.length > 0 && (
            <div style={{ fontSize: 12 }}>{me.groups.join(", ")}</div>
          )}
          <a href="/auth/logout" style={{ color: "inherit", fontSize: 12 }}>
            Sign out
          </a>
        </div>
      </aside>

      <main className="main">
        {route.page === "secrets" && <SecretsPage me={me} />}
        {route.page === "secret" && <SecretPage id={route.id} me={me} />}
        {route.page === "tokens" && <TokensPage />}
        {route.page === "audit" && <AuditPage />}
      </main>
    </div>
  );
}

/** Branding is four values from the server, applied as custom properties.
 *
 *  At runtime rather than at build time, so one image serves every deployment
 *  and changing a colour does not mean rebuilding the console. */
function applyBranding(me: Me) {
  if (me.branding.accent) {
    document.documentElement.style.setProperty("--kw-accent", me.branding.accent);
  }
  if (me.branding.name) {
    document.title = me.branding.name;
  }
  if (me.branding.favicon) {
    let icon = document.querySelector<HTMLLinkElement>("link[rel='icon']");
    if (!icon) {
      icon = document.createElement("link");
      icon.rel = "icon";
      document.head.appendChild(icon);
    }
    icon.href = me.branding.favicon;
  }
}
