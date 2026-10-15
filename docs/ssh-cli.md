# Block on any network device over SSH

For switches, routers and firewalls with a command line but no usable REST API — Ruijie, Aruba,
Cisco, H3C and most others.

DeusWatch supplies the SSH transport, the address validation and the host-key pinning. **You
supply the commands your device actually takes.**

## Why it works this way

There is no Ruijie connector in DeusWatch, and that is deliberate.

A vendor command list shipped inside the product is a list that was never tested against your
hardware, your firmware version or your configuration. When it is wrong it does not fail loudly —
the command is rejected, the ban appears to succeed, and you believe the network is protected
while it is not. A quietly broken enforcement path is worse than no enforcement path.

So the commands come from you, and they are the ones you already type. The same mechanism covers
the other thing the field team raised: *"switch kita biasanya pakai Ruijie, terus nanti ada
perubahan kontrak, ada Aruba. Nah itu sinkronisasi teknologinya."* Changing vendor means changing
four text fields, not waiting for a new release.

---

## 1. On the device: a dedicated account and a dedicated ACL

Create an account for DeusWatch with **only** the privilege to edit the one ACL it manages. Do not
reuse an admin account.

Create an ACL that DeusWatch owns completely, and nothing else writes to. Reconciliation
(below) removes any address in that list that DeusWatch does not expect, so a shared ACL will
have your manual entries deleted.

Get the host key fingerprint:

```sh
ssh-keyscan -t ed25519 10.0.0.1 | ssh-keygen -lf -
# 256 SHA256:x1Y2z3... 10.0.0.1 (ED25519)
```

Copy the `SHA256:…` part.

---

## 2. In DeusWatch: Integrations → Network device over SSH

| Field | Notes |
|---|---|
| Address | `10.0.0.1` or `10.0.0.1:2222` (default port 22) |
| Username / Password | the dedicated account |
| Private key (PEM) | preferred over a password where the device supports it |
| Host key fingerprint | the `SHA256:…` from above |
| Skip host key check | leave off — see the warning below |
| Block command | **required** |
| Unblock command | optional, but see below |
| List command | optional, enables reconciliation |
| List pattern | regex with one capture group |
| Verify command | a read-only command proving the device answers |

Credentials are encrypted at rest and never shown again.

### Command templates

Available substitutions:

| | |
|---|---|
| `{{.IP}}` | the address to block, always a canonical IP |
| `{{.Seconds}}` | ban duration in seconds, `0` for permanent |
| `{{.Duration}}` | human form, e.g. `10m0s`, or the word `permanent` |
| `{{.Comment}}` | always `deuswatch` |

Example for a Cisco-style CLI (Ruijie's RGOS is close; **check against your own device**):

```
Block:   configure terminal ; ip access-list extended DEUSWATCH ; deny ip host {{.IP}} any
Unblock: configure terminal ; ip access-list extended DEUSWATCH ; no deny ip host {{.IP}} any
List:    show ip access-list DEUSWATCH
Pattern: deny ip host (\S+) any
Verify:  show version
```

Work out the exact lines by typing them on the device yourself first. If a command needs a
`write memory` or `commit` to persist, append it to the same template.

### Without an unblock command

Blocking still works. Lifting a ban does not — it has to be undone by hand on the device, and
DeusWatch will tell you so rather than reporting a success. Configure one unless your ACL genuinely
has no removal syntax.

### Reconciliation

With a list command and pattern, DeusWatch periodically makes the device's list match its own
active blocks: it adds what is missing and **removes what is no longer wanted**. That is what
restores your blocks after a device reboot.

It is also why the ACL must belong to DeusWatch alone. Anything in that list which DeusWatch does
not expect is removed.

Only text that matches the pattern *and* parses as an IP address is used, so version numbers and
interface names in the output cannot poison the comparison.

---

## Safety

**Addresses are validated, not trusted.** The address comes from an alert, which means it is
influenced by whoever is attacking you. A "source IP" of `1.2.3.4; reload` would reboot your core
switch. Every address is parsed and re-rendered from the parsed form before it reaches the
template, so what arrives at the device is always a canonical address and never the original
string. Anything that is not an address is refused and no command is sent.

**Host keys are pinned.** Without verification, a machine-in-the-middle can impersonate your
switch — and a session that accepts blocking commands can also accept unblocking ones. DeusWatch
refuses to create a device with neither a fingerprint nor an explicit opt-out.

Ticking *Skip host key check* is for a first setup on a trusted link. It is logged loudly at every
worker start. Do not leave it on.

**Nothing is pushed in dry-run.** As with every responder, bans only reach the device when
`RESPONSE_LIVE=1`. The startup log says plainly when a device is configured but dry-run is active.

**Verify is read-only** and runs on a timer, so point it at `show version` or similar — never at
something that changes state.

---

## Troubleshooting

`docker compose logs -f worker | grep -i ssh`

| Message | Cause |
|---|---|
| `NOT usable, bans will not reach it` | the configuration was rejected — the message names which field, usually a missing block command or host key |
| `host key mismatch: device presented … expected …` | the device was replaced or reinstalled, or you are not talking to the device you think |
| `check FAILED: … cannot connect` | wrong address or port, or SSH is closed to the DeusWatch host |
| `check FAILED: … ssh handshake` | wrong username, password or key; or the device demands keyboard-interactive, which DeusWatch already tries with the same password |
| `check FAILED:` plus device text | the verify command is wrong for this model, or the account lacks privilege |
| Bans logged as executed but nothing on the device | `RESPONSE_LIVE` is not `1`, or the block command is accepted but wrong — check the ACL on the device by hand once |
| Manual ACL entries disappearing | the list command points at a shared ACL; give DeusWatch its own |
| `host key checking DISABLED` | the opt-out is on; pin the fingerprint |

A device that fails its startup check is still kept: it may be temporarily unreachable. Check the
log rather than assuming the configuration is wrong.
