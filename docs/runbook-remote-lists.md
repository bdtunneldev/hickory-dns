# Remote list failure runbook

Operations guide for blocklist and BD split domain list refresh failures in the Hickory DNS pipeline deployment.

## Symptoms

- Prometheus alert `HickoryRemoteListRefreshFailures` fires
- Log lines:
  - `remote blocklist <url> failed: ...`
  - `blocklist refresh failed: ...`
  - `split blocklist refresh failed: ...`
  - `split source <url> failed: ...`
- `hickory_blocklist_list_entries_total` drops or stays at 0
- Blocklist stops blocking new domains; split routing may fall back to default upstreams

## Metrics to check

```promql
# Recent refresh failures by handler and source
increase(hickory_remote_list_refresh_total{result="failure"}[1h])

# Blocklist size
hickory_blocklist_list_entries_total

# Rate-limit and upstream health
rate(hickory_pipeline_rate_limit_rejected_total[5m])
rate(hickory_pipeline_upstream_errors_total[5m])
```

Scrape endpoints (default compose ports):

| Instance | Metrics URL |
|----------|-------------|
| hickory-dns-1 | http://127.0.0.1:9101/metrics |
| hickory-dns-2 | http://127.0.0.1:9102/metrics |
| hickory-dns-3 | http://127.0.0.1:9103/metrics |

## Configuration

Remote sources are defined in `config/routedns-pipeline.toml`:

| Handler | Setting | Default refresh |
|---------|---------|-----------------|
| `blocklist` | `sources[]` + `blocklist_refresh` | 3600s |
| `split` | `blocklist_source[]` + `blocklist_refresh` | 3600s |

Both support `allow_failure = true`, which keeps the **previous in-memory list** when a fetch fails.

## Investigation steps

1. **Confirm scope** — one instance or all three?
   ```bash
   make health
   docker compose logs hickory-dns-1 hickory-dns-2 hickory-dns-3 | grep -E 'refresh failed|remote blocklist'
   ```

2. **Test URL reachability** from a container:
   ```bash
   docker compose exec hickory-dns-1 wget -q -O - \
     'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' | head
   ```

3. **Check TLS / DNS egress** — upstream fetch uses blocking HTTP from inside the container. Verify corporate firewall or resolver allows outbound HTTPS.

4. **Validate local fallback files** — `config/default/blocklist.txt` is always loaded on refresh even when remote sources fail.

5. **Review `allow_failure`** — if `false`, a single failed fetch aborts startup or that refresh cycle. Set `true` for production remote lists unless you want hard failure.

## Remediation

| Condition | Action |
|-----------|--------|
| Transient network blip | Wait for next refresh cycle (`blocklist_refresh` seconds) or `make reload-config` |
| Source URL moved | Update `source` URL in `routedns-pipeline.toml`, then `make reload-config` |
| All instances empty | Fix egress, restore local `blocklist.txt`, restart: `make restart` |
| Stale list acceptable | No action required if `allow_failure = true` and local data is current |
| Need immediate update | Edit local list under `config/default/`, run `make reload-config` |

## Per-instance note (HA)

Each Hickory instance refreshes lists **independently**. A failed refresh on one instance does not affect others. Compare metrics across `:9101`, `:9102`, `:9103` to find stragglers.

## Escalation

If blocklist entries stay at 0 for more than 10 minutes, alert `HickoryBlocklistEntriesLow` fires (critical). Treat as ad-blocking outage: route traffic away or fail closed per your policy.

## Related docs

- [HA rate limiting](ha-rate-limiting.md) — per-instance limit math behind HAProxy
