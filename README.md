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

## Configuration

See [`tongz.example.yaml`](tongz.example.yaml). A rule matches on host, path and
method, because a host alone is too coarse to scope a token:

```yaml
secrets:
  github/repo-scoped: env:GITHUB_TOKEN

rules:
  - match: {host: api.github.com, path: /repos/*/issues, method: [GET, POST]}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: github/repo-scoped
```

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
- header injection from host-held secrets (`env:`, `file:`)
- CA generation, per-SNI leaf issuance, `/install` distribution
- `Proxy-Authorization` gate and an audit log that records token identifiers,
  never token values

Not yet implemented:

- **HTTP/2 and gRPC.** Only `http/1.1` is offered in ALPN, so clients negotiate
  down. Injecting into gRPC needs connection-scoped HPACK handling.
- **Protocol upgrades**, including WebSocket, on an intercepted host. They are
  refused with a message rather than half-handled.
- **OS keychain secrets.** `env:` and `file:` only for now.
- **Connection authorization** (`tongz connect`, image-digest approval). Any
  client that reaches the listener and presents the proxy secret may use it.
- **GCP metadata server**, signature-based auth such as SigV4.

See [`docs/design.md`](docs/design.md) for the full design and the reasoning
behind these choices.

## License

MIT
