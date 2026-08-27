# Using keyway with External Secrets

keyway is a **provider** External Secrets reads from. It holds no cluster
credentials, generates no manifests and runs no reconcile loop of its own — you
point a store at keyway's API and reference secrets by uuid.

## The contract

```
GET /api/secrets/<uuid>/value
Authorization: Bearer kw-<id>-<secret>
```

| Request | Response |
| --- | --- |
| no `key` parameter, key/value secret | flat JSON — `{"db_password":"hunter2"}` |
| no `key` parameter, text secret | the text, verbatim |
| `?key=db_password` | the raw value, **unquoted** |
| anything not delegated to the caller | `404` |

The unquoted single value matters: a JSON-quoted one would land in the
Kubernetes Secret with the quotes still in it. `eso_reads_one_property_as_a_raw_value`
in `keyway/tests/api.rs` pins that, along with the other two shapes — treat
those tests as the contract, because breaking them breaks reconcile loops
rather than a screen.

Every read is an audited reveal by whoever the token acts as.

## Setting it up

**1. Make an account for the reconciler and mint it a token.**

A token acts as the person who minted it (ADR-0004), so sign in as the account
the cluster should act as — not as yourself, or the cluster sees everything you
can see. Mint from the tokens page; the value is shown once.

Leave the expiry empty. An expiry on the credential a reconcile loop presents
is an outage scheduled for a day nobody picked.

**2. Put the token in the cluster.**

```bash
kubectl create secret generic keyway-token \
  --namespace external-secrets \
  --from-literal=token=kw-...
```

**3. Declare the store.**

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: keyway
spec:
  provider:
    webhook:
      url: "https://keyway.example.com/api/secrets/{{ .remoteRef.key }}/value{{ if .remoteRef.property }}?key={{ .remoteRef.property }}{{ end }}"
      headers:
        Authorization: "Bearer {{ .token }}"
      secrets:
        - name: token
          secretRef:
            name: keyway-token
            namespace: external-secrets
            key: token
      result:
        jsonPath: ""
```

**4. Reference a secret by its uuid.**

The uuid is in the page URL — secrets are addressed by uuid and never by name,
because the name is somebody else's contract.

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: payments-db
spec:
  secretStoreRef:
    kind: ClusterSecretStore
    name: keyway
  target:
    name: payments-db
  data:
    - secretKey: DB_PASSWORD
      remoteRef:
        key: 7b0d1e2f-3a4b-5c6d-8e9f-0a1b2c3d4e5f   # the secret's uuid
        property: db_password                        # one key; omit for all
```

**5. Delegate the secret to that account.**

In the console, grant it `read`. Scope the grant to the keys the workload
actually needs — that is what makes it safe to keep a bot's credentials in one
secret and hand out exactly one of them.

No admin, no infrastructure change: a team hands a secret to its cluster by
writing one grant.

## A caveat worth reading before you delegate to a group

Without a Directory configured, an API token can only see grants addressed to
its holder **by name**. A grant to a *group* is invisible to it, because a
token carries no claim and keyway falls back to the groups it remembered at
that account's last sign-in — which for an account that only ever mints tokens
may be empty.

Either delegate to the account directly, or configure a Directory. The console
warns about this at the point of delegating.
