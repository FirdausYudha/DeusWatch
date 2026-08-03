# GeoIP enrichment — country codes for source IPs

Every external source IP in an event is enriched with a country ISO code so the dashboard's flag
list, the attack-origins map, and the country-scoped queries all work. As of **v2.10.0** DeusWatch
tries **three** GeoIP sources and uses whichever answers first:

| Source                                | When it fires                             | Rate limit         | Offline? | Preferred? |
|---------------------------------------|-------------------------------------------|--------------------|----------|------------|
| MaxMind GeoLite2-Country (`.mmdb`)    | `GEOIP_MMDB_PATH` is set                  | none               | yes      | **yes** — first |
| AbuseIPDB `countryCode`               | AbuseIPDB integration configured          | provider quota     | no       | fills gap  |
| OTX `country_code`                    | OTX integration configured                | provider quota     | no       | fills gap  |
| ip-api.com (free)                     | `GEOIP_ENABLED` != `0` (default **on**)   | 45 req/min free    | no       | last-resort fallback |

The first hit wins for the country field, so the ordering above is what actually happens: MaxMind
if you shipped a `.mmdb`, else whichever paid CTI you wired, else ip-api.com's free lookup.

## Why v2.10.0 turned ip-api on by default

Operators without any CTI keys were seeing public IPs (e.g. `37.48.254.107`, `167.148.33.174`)
land with an **empty** `source_geo_country_iso` because the only path that filled it was one of the
paid providers. Turning ip-api on by default plugs that gap; opt out with `GEOIP_ENABLED=0` if you
prefer to keep the data plane fully local (or add a MaxMind `.mmdb` — see below).

## Adding the MaxMind offline database

1. Sign up for a free MaxMind account and download `GeoLite2-Country.mmdb` (~7 MB, permissive
   licence, updated weekly).
2. Copy it into the manager host at a path the container can read:
   ```bash
   sudo mkdir -p /opt/deuswatch/geoip
   sudo cp GeoLite2-Country.mmdb /opt/deuswatch/geoip/
   ```
3. Mount it into the worker container and point the env var at it in `deploy/docker-compose.yml`:
   ```yaml
   worker:
     environment:
       GEOIP_MMDB_PATH: /etc/deuswatch/GeoLite2-Country.mmdb
     volumes:
       - /opt/deuswatch/geoip:/etc/deuswatch:ro
   ```
4. `docker compose up -d worker` — the log line
   `worker: real CTI provider active (… maxmind=true)` confirms the DB loaded. Country lookups
   are now offline and unlimited; ip-api.com stays wired as the safety net for IPs MaxMind's DB
   doesn't attribute (anycast, unallocated).

## Refresh cadence

The `.mmdb` is read-only-mmap'd at worker startup. Weekly regeneration is:

```bash
sudo cp new-GeoLite2-Country.mmdb /opt/deuswatch/geoip/GeoLite2-Country.mmdb
docker compose restart worker
```

A restart takes ~2 seconds. There is no hot-reload of the file (avoiding subtle mmap-invalidation
bugs), so schedule the restart during quiet hours if you care.
