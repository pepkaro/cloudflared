# CLAUDE.md - Project Intelligence

## CRITICAL: Environment Safety
- **NEVER** use `pkill` with broad patterns (e.g. `pkill -f "python3"`, `pkill -f "cloudflared"`) in this environment
- The session depends on an egress proxy process. Killing it crashes the Claude Code session entirely.
- To kill specific processes, use their exact PID (captured at launch) instead of pattern matching
- Always store PIDs when starting background processes: `command & PID=$!`
- Kill only by PID: `kill $PID` — never by name pattern

## Environment
- This is a proxy-only environment: no direct DNS, no direct outbound TCP
- All outbound traffic must go through the egress proxy at `$HTTPS_PROXY` / `$HTTP_PROXY`
- The proxy uses JWT-based auth and has an allowlist of hosts
- `CLAUDE_CODE_PROXY_RESOLVES_HOSTS=true` — the proxy handles DNS resolution

## HTTP Proxy Support - Edge Infrastructure Limitation

### What works (client-side)
All client-side proxy infrastructure is implemented and tested:
- Quick Tunnel API uses proxy (`http.ProxyFromEnvironment`)
- Edge discovery bypasses DNS, uses known hostnames (`region1/2.v2.argotunnel.com:7844`)
- Protocol selector forces HTTP/2 (QUIC/UDP can't traverse HTTP CONNECT)
- Feature selector skips DNS lookup behind proxy (avoids 10s timeout)
- `DialThroughProxy` establishes CONNECT tunnels with Basic auth
- 19 unit tests covering all proxy code paths

### What doesn't work (edge-side limitation)
The tunnel's HTTP/2 connection fails through a proxy because of an HTTP/2 role conflict:
- **Direct mode**: Edge acts as H2 CLIENT, sends requests to cloudflared's `ServeConn`
- **Through proxy**: Connection hits Cloudflare's HTTP/2 gateway (Envoy), which acts as H2 SERVER

Tested combinations:
1. No ALPN, no wrapper → Edge returns "HTTP/1.1 400 Bad Request"
2. ALPN "h2", no wrapper → Edge closes with EOF immediately
3. ALPN "h2" + client preface → Edge becomes H2 server, SETTINGS exchanged, then deadlock (both sides waiting for requests)
4. Client mode (`http2.Transport.NewClientConn`) → Edge's gateway returns 503 "DNS resolution failure" for h2.cftunnel.com (gateway can't route to tunnel backend)

### Resolution path
Requires Cloudflare edge infrastructure changes: the HTTP/2 gateway needs to recognize tunnel connections through proxied paths and route them to the tunnel backend with the correct H2 role assignment.
