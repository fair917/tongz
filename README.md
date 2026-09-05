# tongz

> Tongz — your agent never touches a credential.

A credential broker for AI coding agents. The container the agent runs in holds
no credentials at all; the authentication it needs is attached from outside, per
request, by a proxy that keeps the secrets on the host.

Tokens are never written to the container's filesystem, environment, or process
memory. An agent that reads every file it can reach finds nothing to exfiltrate.

## How it works

```
host
├── tongz proxy            credentials live here
│     ├── /install         hands out the CA and container setup
│     └── MITM + header injection
└── container (agent)
      └── HTTPS_PROXY → tongz, no credentials
```

The guarantee comes from where the credentials are stored, not from forcing
traffic through a particular path. A client that bypasses the proxy does not
escape anything — it just makes unauthenticated requests.

Only hosts named by a rule are decrypted. Everything else is tunnelled with
`CONNECT` and never touched, so TLS breakage is confined to what you configured.

## Quick start

```sh
go build ./cmd/tongz
cp tongz.example.yaml tongz.yaml   # edit the rules
GITHUB_TOKEN=ghp_... ./tongz -config tongz.yaml
```

Then, inside the container:

```sh
curl -fsSL http://<gateway>:8080/install | sh
```

In a devcontainer, use `postStartCommand` rather than `postCreateCommand` so
that it also runs when a cached container restarts:

```json
{
  "containerEnv": {
    "HTTP_PROXY": "http://host.docker.internal:8080",
    "HTTPS_PROXY": "http://host.docker.internal:8080"
  },
  "postStartCommand": "curl -fsSL http://host.docker.internal:8080/install | sh"
}
```

## Providers

| Provider | Example                                  | What the container needs                                      |
| -------- | ---------------------------------------- | ------------------------------------------------------------- |
| GitHub   | [`examples/github.yaml`](examples/github.yaml) | nothing beyond the proxy; git needs no credential helper |
| AWS      | [`examples/aws.yaml`](examples/aws.yaml) | placeholder `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`      |
| GCP      | [`examples/gcp.yaml`](examples/gcp.yaml) | nothing; `/install` writes `GCE_METADATA_HOST`                 |

AWS and GCP client libraries will not build a request without finding
credentials somewhere, so they are given placeholders — a fake access key, a
metadata server that returns a worthless token. Tongz discards whatever the
client did with them and attaches the real credential on the way out. The
container never holds anything usable, not even briefly.

## Configuration

See [`tongz.example.yaml`](tongz.example.yaml). A rule matches on host, path and
method, because a host alone is too coarse to scope a token, and then takes one
of three actions.

**`inject`** writes a header:

```yaml
secrets:
  github/repo-scoped: env:GITHUB_TOKEN

rules:
  - match: {host: api.github.com, path: /repos/*/issues, method: [GET, POST]}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: github/repo-scoped
```

`{token}` substitutes the credential; `{basic:username}` encodes it as a Basic
credential, which is what git over HTTPS wants.

**`sign`** computes a signature that cannot be written declaratively:

```yaml
secrets:
  aws/default:
    fields:
      access_key_id: env:AWS_ACCESS_KEY_ID
      secret_access_key: env:AWS_SECRET_ACCESS_KEY

rules:
  - match: {host: "*.s3.us-west-2.amazonaws.com", method: [GET, HEAD]}
    sign: {method: aws-sigv4}
    token: aws/default
```

**`respond`** answers from the proxy without contacting anything, which is how
the GCP metadata server is served:

```yaml
rules:
  - match: {host: metadata.google.internal}
    respond: {method: gcp-metadata, project_id: my-project}
```

Credentials come from `env:`, `file:`, or `exec:` — the standard output of a
command on the host, for helpers like `gcloud auth print-access-token`. Add
`refresh` to re-read one that expires:

```yaml
secrets:
  gcp/default:
    value: exec:gcloud auth print-access-token
    refresh: 30m
```

Resolution happens at startup and refreshes run in the background, so no lookup
ever sits on the request path.

Path patterns are segment-aware: `*` matches one segment, `**` matches any
number. An existing header is replaced, never appended to, so a credential the
agent supplied itself cannot survive. A request to an intercepted host that
matches no rule is refused rather than forwarded without a credential.

## Endpoints

The proxy serves these on its own listener, over plain HTTP:

| Path       | Purpose                                            |
| ---------- | -------------------------------------------------- |
| `/install` | setup script: CA trust stores plus proxy variables |
| `/ca.pem`  | the CA certificate alone                           |
| `/healthz` | liveness                                           |

## Threat model

What is defended: the agent inside the container reaching credentials it was not
granted, and credentials existing inside the container at all.

Explicitly out of scope: compromise of the host, other processes on the host,
anyone holding the Docker socket, and egress control. The trust boundary is the
container edge — once the host is compromised, the keychain and the proxy's
memory are both readable and there is nothing left to protect.

## Status

Early. What works today:

- explicit proxy with per-host interception and `CONNECT` passthrough
- rule matching on host, path and method, fail-closed on no match
- header injection, AWS SigV4 re-signing, and the GCP metadata responder
- secrets from `env:`, `file:` and `exec:`, with background refresh
- CA generation, per-SNI leaf issuance, `/install` distribution
- `Proxy-Authorization` gate and an audit log that records token identifiers,
  never token values

Not yet implemented:

- **HTTP/2 and gRPC.** Only `http/1.1` is offered in ALPN, so clients negotiate
  down. Injecting into gRPC needs connection-scoped HPACK handling; until then
  the Google APIs that are gRPC-only (Pub/Sub, Firestore, Spanner, Bigtable)
  are out of reach.
- **AWS chunked payload signing.** An upload whose body is signed chunk by
  chunk cannot be re-signed without rewriting every chunk, so it is refused
  with an explanation.
- **GCP identity tokens.** A signed assertion has nothing to substitute later.
- **Protocol upgrades**, including WebSocket, on an intercepted host. They are
  refused with a message rather than half-handled.
- **OS keychain secrets.** `exec:` covers most of it in the meantime.
- **Connection authorization** (`tongz connect`, image-digest approval). Any
  client that reaches the listener and presents the proxy secret may use it.

See [`docs/design.md`](docs/design.md) for the full design and the reasoning
behind these choices.

## License

MIT
