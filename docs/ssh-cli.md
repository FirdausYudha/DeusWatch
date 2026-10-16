# Blocking on any network device, over SSH

DeusWatch can push a block to a switch, router or firewall by running **your** commands on it over
SSH. It works with Ruijie, Aruba, Cisco, H3C or anything else with a CLI, because the commands are
configuration rather than a driver.

## Why there is no Ruijie driver

A hospital running full Ruijie at the edge could use none of DeusWatch's auto-blocking: the
responders were nftables, MikroTik REST and CrowdSec. The obvious fix is a Ruijie responder. It is
the wrong one, and their own engineer said why without being asked:

> "Switch kita biasanya pakai Ruijie, terus nanti ada perubahan kontrak, ada Aruba. Nah itu
> sinkronisasi teknologinya."

A driver per vendor expires with the procurement contract. So the commands are a field you fill in.
You already have them: these switches are configured by script today, and nobody here can test a
guess against hardware they do not own. This is the same choice the SNMP work made, for the same
reason.

## Setting it up

**Integrations → Network device over SSH (any vendor).** One entry per device; a ban reaches all of
them.

| Field | Notes |
|---|---|
| Address | `10.0.0.1` or `10.0.0.1:2222`. Port defaults to 22 |
| Username | |
| Password **or** Private key | One of the two |
| Host key fingerprint | `SHA256:...`, see below |
| Skip host key check | Only for a device on a trusted management VLAN |
| Block command | Must contain `{{ip}}` |
| Unblock command | Must contain `{{ip}}` |
| Verify command | Read-only, for the health probe |

Get the fingerprint with:

```bash
ssh-keyscan -t rsa 10.0.0.1 | ssh-keygen -lf -
```

Paste the `SHA256:...` part. **Verification is on unless you turn it off**, and that default is the
point: an unverified SSH session to the device that enforces your blocks is a machine-in-the-middle
away from someone who watches every address you ban and answers as the switch while blocking
nothing.

### The commands

Several lines run in **one session**, so config mode works. Blank lines and `#` comments are
skipped. An IOS-like device looks roughly like this, and the exact syntax is yours to confirm
against your own hardware:

```
configure terminal
ip access-list extended DEUSWATCH
 deny ip host {{ip}} any
exit
end
```

Unblock is the same with `no` in front of the rule. A read-only verify command such as
`show version` proves reachability and credentials on a timer without touching the configuration.

**`{{ip}}` is required.** A block command that never names the address either does nothing or does
it to everything, and both look like success from here, so the command is refused instead.

## What it will not do

**No blocklist reconciliation.** MikroTik has a periodic sync that reconciles the router's full
address list and self-heals after a reboot. This responder has Block and Unblock only. Reading an
ACL back and parsing it is different on every vendor and is exactly the per-vendor knowledge this
exists to avoid, so a device that reboots and loses its rules is a gap you should know about rather
than one papered over by a parser nobody could test against your hardware.

**The address is validated, then re-rendered.** What goes into the command is the parsed address,
never the text that arrived, so it can only ever contain hex digits, dots and colons. A value like
`1.2.3.4; reboot` is refused, not escaped: this is the last gate before a command runs with
privilege on a switch.

**A device that answers "% Invalid input" is a failure**, even though it exits zero. CLI devices
report errors in their output and almost never in the exit status, so the output is what is judged.
Without that, a mistyped command reports a successful block that never happened.

## Checking it works

The worker probes each device at startup and on a timer, and logs the verdict:

```
worker: SSH device "sw-core-1" reachable
worker: responder from 2 Integrations SSH device(s): sw-core-1, sw-dist-2
```

A failure names the device and the reason. Ask the assistant "is the firewall connected?" for the
same answer in words.

**Bans are not pushed anywhere until `RESPONSE_LIVE=1`.** With it unset, everything is prepared and
logged as a dry run, which is the right way to run the first week.

## Both kinds at once

A site with a MikroTik at the perimeter and Ruijie switches inside gets both: a ban fans out to
every configured device of either kind. Neither takes precedence, because picking one would leave
half the edge unblocked without saying so.
