# Deploying keyway

Two artifacts per release, built by [the Release workflow](../.github/workflows/release.yml)
when a `v*` tag is pushed:

- `ghcr.io/kotsmile/keyway` — the backend
- `ghcr.io/kotsmile/keyway-dashboard` — the console

`quickstart.yml` is the compose quickstart's config; the Kubernetes story is
the Helm chart in [`chart/keyway`](chart/keyway).

## Helm

The chart deploys the backend (with a migrate init container), the console,
and optionally an Ingress. It does NOT deploy Postgres — point
`config.postgres.addr` at one you run — and it does not hold secrets: the
config file pulls them from the environment (`${env:...}`), fed by a Secret
you create first:

```sh
kubectl create secret generic keyway-env \
  --from-literal=PGPASSWORD=... \
  --from-literal=KEYWAY_KEY="$(openssl rand -base64 32)"

helm install keyway ./deploy/chart/keyway \
  --set-json 'config.postgres={addr: "my-postgres:5432", name: keyway, user: keyway, password: "${env:PGPASSWORD}", sslmode: disable}'
```

The whole keyway config lives under `.Values.config`, rendered verbatim. The
default is the quickstart's dev mode — no `oidc.issuer`, everyone is `dev` —
so a real deployment overrides at least `oidc`, `postgres` and `stores`.

## ArgoCD

The chart is plain files in this repository, so an Application points straight
at it:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: keyway
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/kotsmile/keyway
    targetRevision: v0.1.0
    path: deploy/chart/keyway
    helm:
      valuesObject:
        config:
          oidc:
            issuer: https://keycloak.example.com/realms/main
            client_id: keyway
            client_secret: ${env:KEYWAY_OIDC_CLIENT_SECRET}
  destination:
    server: https://kubernetes.default.svc
    namespace: keyway
  syncPolicy:
    automated: { prune: true }
    syncOptions: [CreateNamespace=true]
```

Pin `targetRevision` to a release tag; the image tags default to the chart's
`appVersion`, so tracking a tag upgrades images and templates together.
