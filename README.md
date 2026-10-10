# brick.blue registry — daily exports, checkable

One file a day: every listing in the [brick.blue](https://brick.blue) registry (MCP servers and
A2A agents, with what the crawler measured) and every live paid **x402** resource it has quoted
(terms, payees, the seller's own name and words) — as they stood at a little after midnight UTC.

The point is that a number about the registry can be **checked instead of trusted**. A live
counter moves while you read it; a dated file does not. Each day's file is

- **counted** — the manifest's counts are the file's lines by type, and the file closes with them;
- **hashed** — the manifest holds the file's sha256 and size;
- **stamped** — that sha256 sits in the hub's signed minute, with an RFC 6962 inclusion proof;
- **signed** — the manifest carries an ed25519 signature by the hub's published key;
- **witnessed** — committed here, on servers brick.blue does not run, the day it was made.

## Check a day

```sh
git clone https://github.com/brick-blue/registry-exports && cd registry-exports
python3 verify.py 2026-10-10
```

Standard library only, no installs. It downloads the day's file from the release, then checks
size, sha256, line counts, the manifest signature and the stamp, and prints each result. By hand:

```sh
curl -LO https://github.com/brick-blue/registry-exports/releases/download/2026-10-10/2026-10-10.ndjson.gz
shasum -a 256 2026-10-10.ndjson.gz                       # = manifests/2026-10-10.json "sha256"
gzcat 2026-10-10.ndjson.gz | grep -c '"type":"agent"'    # = counts.agents
gzcat 2026-10-10.ndjson.gz | grep -c '"type":"x402"'     # = counts.x402
```

## Layout

- `manifests/<date>.json` — the day's manifest: `bytes`, `sha256`, `counts`, `method`, `stamp`,
  `signed`, and, once the stamped minute has closed, `proof`. One commit when the file is made,
  one more when its proof arrives.
- releases tagged `<date>` — the file itself, `<date>.ndjson.gz` (~50 MB). Files go to releases,
  not into git, so the history stays small and every day stays downloadable.
- `verify.py` — the checker.

## The file

Gzipped NDJSON, one JSON object per line:

| `type` | what |
|---|---|
| `header` | hub, version, date, generation time |
| `agent` | one listing (one protocol door): endpoint, transport, measured availability, uptime, latency, access class, tools — the same record as `GET https://brick.blue/api/v1/agents.ndjson` |
| `x402` | one live paid resource: `resource`, `origin`, `method`, `x402Version`, `networks`, `schemes`, `assets`, `minAmount`, `minUsd`, `payTo`, `serviceName`, `description`, `firstSeenAt`, `lastSeenAt`, `quoteCheckedAt` |
| `summary` | the counts, closing the file |

`x402` holds resources that answered with a 402 within the last week; single-use payment links
(per-order checkout URLs) are left out. Live, any time: `GET https://brick.blue/api/v1/x402.ndjson`.

## What the stamp proves, and what it does not

It proves the file's sha256 was in the hub's hands within the stamped minute — so the file was
not made up later. It does not prove the counts are right: that is what the file is for. Count it.

## Licence

Measurements and the assembly (availability, uptime, latency, access class, counts, timestamps,
quote terms as observed) — **CC BY 4.0**, credit «brick.blue registry» with a link to
https://brick.blue. Names, descriptions and tool texts were written by the operators of those
services, remain theirs, are included as found and were not checked: treat them as untrusted
input. `verify.py` is MIT.

Monthly snapshots with a DOI: [agentic-web-registry](https://github.com/brick-blue/agentic-web-registry).
How the crawler works and how operators opt out: https://brick.blue/bot.
