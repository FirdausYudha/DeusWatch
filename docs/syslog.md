# Native syslog input (agentless devices)

DeusWatch can receive **syslog directly** — over UDP and TCP, in RFC 3164 (BSD) or RFC 5424
format — so devices that can't run a DeusWatch agent (routers, switches, firewalls, printers,
appliances, or another log server) ship logs straight into the pipeline. Each message is
normalized to DCS and runs through detection / playbooks / response like any other event.

## Enable it

Set `SYSLOG_LISTEN` in the worker's environment and **publish the port** on the worker container.

```dotenv
# deploy/.env
SYSLOG_LISTEN=:5514        # UDP + TCP on 5514 (port 514 needs root; 5514 avoids that)
SYSLOG_DATASET=syslog      # dataset label for messages with no program tag
```

Publish the port on the **worker** service in `deploy/docker-compose.yml`:

```yaml
  worker:
    # …
    ports:
      - "5514:5514/udp"
      - "5514:5514/tcp"
```

Apply: `docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d worker`. The log
shows `syslog: listening on :5514 (udp+tcp)`.

> Prefer **5514**. Binding **514** requires root or `CAP_NET_BIND_SERVICE` on the container.

## Point a device at it

Most devices just need a destination host + port. Examples:

- **A Linux box (rsyslog)** — forward everything to DeusWatch:
  ```
  # /etc/rsyslog.d/90-deuswatch.conf
  *.*  @deuswatch-host:5514      # @ = UDP;  @@ = TCP
  ```
- **OPNsense / pfSense** — System → Settings → Logging/Targets → add a remote target
  `deuswatch-host:5514`, UDP or TCP.
- **MikroTik** — `/system logging action add name=deuswatch target=remote remote=deuswatch-host
  remote-port=5514` then log topics to it.

## How it's parsed

- The **program tag** (`sshd`, `sudo`, `kernel`, `httpd`, …) becomes the **dataset**, so the
  matching built-in or custom decoder runs — an `sshd` syslog line hits the SSH parser, a
  ModSecurity line is recognized as a WAF block, etc. Tag-less messages use `SYSLOG_DATASET`.
- The sending host appears in the dashboard's **Agent** column as `syslog/<host>`.
- Both framings on TCP are accepted: newline-delimited and octet-counted (RFC 6587, rsyslog's
  default). UDP datagrams may carry one or several newline-separated messages.
- A line in a shape we don't fully recognize is still ingested as a raw event (never dropped),
  so you can write a custom decoder for it in the Decoders UI.

## Notes

- Syslog (plain UDP/TCP) is **unauthenticated and unencrypted** — only expose the port on a
  trusted network, or restrict it with a host firewall. For untrusted networks prefer the mTLS
  agent or the token-authenticated [ingest webhook](wazuh-webhook.md).
- High-volume UDP can drop packets under load (a property of UDP, not DeusWatch); use TCP from
  the device when every message matters.
