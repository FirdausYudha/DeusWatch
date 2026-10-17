# Agent groups

One collection policy set once, followed by many agents.

## Why

Config push has worked per agent since the beginning, and at a single site that was enough. It is
the thing that does not survive growth. Five hundred endpoints that should all watch the same
paths are five hundred identical edits, and the five hundred and first is the one nobody did.

## Using them

**Agents page -> Groups.** Create a group, give it sources, then pick it in the **Group** column on
each agent row.

Editing a group's sources reaches every member on its next poll. The save tells you how many
agents were affected, which for a bulk edit is the only feedback there is: a count of zero means
the group has no members, or every member has a policy of its own.

## Precedence

1. A **per-agent policy you set** (Monitoring on that agent row).
2. Its **group**.
3. The **enrollment seed**, the OS default sources written when the agent enrolled.

The seed ranking below the group is the point of the order. Enrollment gives every agent the
default sources for its platform, deliberately, so a new host watches its logs out of the box and
those sources are visible rather than hidden inside the agent binary. If that counted as a policy
you had set, every agent would look customised and a group would apply to nobody.

So assigning a group to a freshly enrolled agent works, and it is only an edit you made on that
specific agent that takes it out of the group's reach.

An agent that is released from a group (the group was deleted, or you set it to none) falls back
to the seed, not to nothing. It keeps watching its logs.

## Why it is not a merge

A per-agent policy **overrides** its group's. It does not merge with it.

Merging two source lists means deciding what happens when both name the same path with different
settings, and every answer to that is a rule an operator has to hold in their head to predict what
an endpoint is collecting. One config wins, and the screen says which.

The **Config** column labels it:

| Badge | Meaning |
|---|---|
| `own` | This agent has a policy of its own. Group edits do not reach it |
| `from <group>` | It is following that group |
| neither | No policy at all: the agent collects its built-in defaults |

`own` is the one to look for. An operator who edits a group and sees nothing change on one
endpoint has no other way to find out why.

**Use group** on the agent row drops its own policy so the group's applies again. Opening
**Monitoring** on an agent that is following a group and saving does the reverse: it gives that
agent a policy of its own, and the dialog says so before you save.

Deleting a group releases its members. They fall back to their own policy, or to the agent
defaults if they have none.

## The version an agent is told

Worth knowing, because it is where the obvious implementation is wrong.

An agent re-applies its config only when the version it is handed is **strictly greater** than the
one it is running. So the number has to be monotonic per agent, and it cannot be read out of
whichever config won.

Take an agent with a personal config edited seven times, moved onto a newly created group whose
own version is 2. Serving the group's version hands the agent a lower number than it is running,
and the agent then ignores the change: not with an error, not once, but permanently, because the
number never catches up.

So each agent carries its own counter, `agents.config_rev`, bumped by anything that changes its
effective policy: its own config, its group assignment, or its group's config. That counter is the
version in the JSON the agent is served, whichever config the content came from.

## Limits

Groups carry collection sources only. They do not carry response policy, FIM whitelists or
anything else: those stay global or per agent.

There is no nesting, and an agent belongs to at most one group. Wazuh allows several per agent and
merges them, which is exactly the merge ambiguity above, multiplied.
