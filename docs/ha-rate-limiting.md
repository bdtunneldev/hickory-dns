# HA rate limiting

How per-IP and per-tenant rate limits behave when running multiple Hickory DNS instances behind HAProxy.

## Topology

```
Clients → HAProxy (:53, send-proxy-v2) → round-robin → hickory-dns-{1,2,3} (:5301)
```

Each Hickory instance maintains **in-memory, per-process** counters. Limits are **not** shared via Redis/Valkey (unlike some RouteDNS deployments).

## Configured limits (`routedns-pipeline.toml`)

| Tier | Handler | Limit | Window | Key |
|------|---------|-------|--------|-----|
| A | `rate_limiter` | 500 | 60s | Client IP from PROXY v2 |
| B | `tenant_rate_limiter` | 400 | 60s | PPv2 TLV `0xE1` tenant id |

## Per-instance math

For `N` healthy backends and HAProxy **round-robin**:

### Per-IP limit (tier A)

Each instance enforces **500 requests / 60s / IP** independently.

A client IP hashed consistently to one backend (not the case with round-robin) would see 500/min. With round-robin across `N` instances, the same client can send roughly:

```
effective_burst ≈ N × 500 requests per 60s window
```

**Example (3 instances):** up to **~1,500** requests per client IP per minute before all backends refuse.

### Per-tenant limit (tier B)

Same formula with **400/min/instance**:

```
effective_tenant_burst ≈ N × 400 requests per 60s
```

**Example (3 instances):** up to **~1,200** tenant-scoped requests per minute.

### Fixed-window caveat

Counters reset on wall-clock window boundaries **per instance** (not synchronized). Short spikes at window edges can exceed the nominal limit.

## Tuning for production

To achieve a **cluster-wide** limit of `L` requests/min for tier A with `N` instances:

```
requests_per_instance = floor(L / N)
```

**Example:** cluster cap 500/min with 3 instances → set `requests = 167` (conservative) or `166`.

Add headroom for uneven load if clients stick to one backend due to connection reuse.

## HAProxy considerations

- **send-proxy-v2** is required so Hickory sees real client IPs and tenant TLVs.
- Health checks use TCP; failed instances are removed from rotation.
- When an instance is down, effective cluster capacity drops but per-instance limits stay the same.

## Monitoring

```promql
# Rejections per instance
rate(hickory_pipeline_rate_limit_rejected_total[5m])
rate(hickory_pipeline_tenant_rate_limit_rejected_total[5m])

# Compare across instances
sum by (instance) (rate(hickory_pipeline_rate_limit_rejected_total[5m]))
```

Rejected queries return **REFUSED** (rcode 5) to clients.

## Future improvement

Shared rate-limit state (Redis/Valkey) would enforce exact cluster-wide caps. Current design favors simplicity and matches single-node RouteDNS semantics per instance.
