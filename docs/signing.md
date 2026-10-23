# Signed releases and policies

Makes a compromised manager unable to run code on your endpoints.

## The problem this fixes

Two paths let the manager put code on an endpoint and have it run as root:

1. **Self-update.** The agent downloads a binary from the manager and replaces its own running
   executable.
2. **A pushed CIS policy.** A policy's `c:` rules are shell commands, run as the agent's user.

Both were authenticated only by TLS to the manager's CA. TLS proves **which host answered**, not
**what it sent**. So whoever controlled the manager controlled every endpoint in the estate, and
every other control in this product was downstream of that one fact.

Signing moves the trust from the transport to the content. You hold a private key, each endpoint
holds only the matching public key, and the manager becomes a courier that cannot forge what it
carries. Taking over the manager then buys the ability to **withhold** updates, which is a denial
of service you will notice and can recover from, instead of the ability to **execute code**, which
you will not and cannot.

Ed25519: one curve, one hash, nothing to misconfigure, and a public key short enough to paste into
an environment variable.

## Setting it up

### 1. Make a key, once

```bash
go build -o dwsign ./cmd/dwsign
./dwsign -gen -out ./keys
```

You get `keys/update.key` (private) and `keys/update.pub` (public), plus the one-line form of the
public key for container deployments.

**The private key must never reach the manager.** A manager that can sign its own payloads makes
the signature decoration, and the manager is the exact component this exists to survive. Keep it
in a password manager or an offline store, and back it up: losing it means re-keying every
endpoint.

### 2. Put the public key on each endpoint

The installer takes it:

```bash
curl -fsSL http://MANAGER:8080/api/agent/install.sh | sudo MANAGER=<ip> TOKEN=<token> NAME=<name> \
  UPDATE_PUBKEY="$(cat keys/update.pub)" sh
```

The Add-agent wizard has a field for it that builds the same command for you. What you paste there
is only used to compose the command in your browser; the manager never receives or stores it.

For an agent already installed, write the key to `/etc/deuswatch/certs/update.pub` (or set
`UPDATE_PUBKEY`) and restart it. Override the path with `UPDATE_PUBKEY_FILE`.

**Deliberately not fetched from the manager.** Taking the key from the manager would mean trusting
the manager to hand over the key that checks the manager, which is not a check.

### 3. Sign what you publish

Agent binaries:

```bash
./dwsign -key keys/update.key -in dist/deuswatch-agent-linux-amd64
```

That writes `dist/deuswatch-agent-linux-amd64.sig`. CIS policies, the same way:

```bash
./dwsign -key keys/update.key -in policies/cis_debian10.yml
```

Then attach the signature when you upload the policy: Benchmarks -> Policies has a signature box
that also loads a `.sig` file.

Verify before anybody depends on it:

```bash
./dwsign -verify -pub keys/update.pub -in dist/deuswatch-agent-linux-amd64
```

Lost the public key? Derive it from the private one:

```bash
./dwsign -pubout -key keys/update.key > update.pub
```

## What happens then

| On the endpoint | Signature | Result |
|---|---|---|
| Trusted key installed | verifies | Applied |
| Trusted key installed | wrong | **Refused.** The running agent is untouched |
| Trusted key installed | absent | **Refused** |
| Trusted key installed, but unreadable | any | **Refused**, naming the key |
| No trusted key | any | Applied, with a warning on every update |

A refused update is the safe failure: an agent one version behind still collects, still alerts,
still responds. A refused policy leaves the previous score standing rather than running whatever
arrived.

There is deliberately **no mode where a key is installed and a signature is merely preferred**.
"Verify if convenient" is not verifying, because the attacker picks the circumstances. For the same
reason a key that is present but malformed is an error rather than a fallback to unverified: a typo
must not switch the control off on the day you configure it.

**No key means no verification, and that is on purpose.** Refusing would have bricked self-update
on every agent already deployed the moment this shipped, and an estate that cannot be patched is
its own security problem. The agent says so at warning volume on every update, naming the variable
that fixes it.

## The manager's own binaries are unsigned

The container image **compiles** the agent binaries it serves. Signing them at image build time
would mean shipping the private key into the build, which is the one thing this forbids.

So the api and gateway say at startup whether what they are serving can be accepted:

```
signing: 3 of 3 agent binaries in /agents have NO signature (...). Agents that hold a trusted
release key will REFUSE to self-update from this manager.
```

To serve signed updates, mount the signed release artifacts and their `.sig` files over `/agents`:

```yaml
services:
  api:
    volumes:
      - ./signed-agents:/agents:ro
```

Put the binaries and the matching `.sig` files in `./signed-agents`. The gateway serves self-update
downloads from the same path and needs the same mount.

## Signing in CI

The release workflow signs when the `UPDATE_SIGNING_KEY` secret is set, and skips the step when it
is not, so a fork still publishes. It verifies the signatures it just produced before publishing,
because a release with wrong signatures is worse than one with none: every agent that requires
signatures refuses to update, and the cause is a file nobody thinks to check.

**The trade-off, stated plainly.** A key in a GitHub secret means GitHub, and anyone who can run a
workflow in the repository, can sign a release. That is weaker than signing offline. It is still
far stronger than nothing, because it removes the manager from the set of things that can forge a
release, and the manager is what this is about. If your threat model includes the CI account, leave
the secret unset and sign by hand.

## Rotating the key

There is no key history: an endpoint trusts exactly one key. So rotation is, in order:

1. Generate the new keypair.
2. Sign your current release artifacts and policies with the **new** key.
3. Publish them.
4. Replace `update.pub` on every endpoint.

Doing step 4 first leaves those endpoints refusing everything until step 3 lands. `dwsign -gen`
refuses to overwrite an existing key without `-force` for this reason: regenerating silently
orphans every endpoint holding the old public key, and the symptom is every agent refusing every
update at once with nothing pointing at the cause.

## What this does not cover

**`scripts/update.sh`**, which updates the manager itself, uses `git pull` and is covered by git
and your server's credentials, not by this.

**The enrollment-time trust.** The installer downloads the agent binary from the manager and runs
it as root, before any key exists. A manager that is already compromised when you install an agent
compromises that agent. This protects every update after that, which is the whole lifetime of the
deployment; it cannot protect the first minute of it. Install from a manager you trust.

**The key on the endpoint.** Anyone who can write `/etc/deuswatch/certs/update.pub` as root can
replace the key. That is already root on that host, so it is not a new exposure, but it does mean
this control is worth exactly as much as root on your endpoints is hard to get.
