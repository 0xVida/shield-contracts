# Docs live in shield-platform

This repo has no project docs of its own. The single source of truth is
**[shieldzk/shield-platform/docs](https://github.com/shieldzk/shield-platform/tree/main/docs)**.
Read it there, and make doc changes there.

| Doc | What's in it |
|---|---|
| [requirements.md](https://github.com/shieldzk/shield-platform/blob/main/docs/requirements.md) | Scope, privacy guarantees, functional requirements, out of scope |
| [architecture.md](https://github.com/shieldzk/shield-platform/blob/main/docs/architecture.md) | Components, flow, **shared protocol spec**, open decisions (D1–D5) |
| [team.md](https://github.com/shieldzk/shield-platform/blob/main/docs/team.md) | Ownership per person, Person 2 ↔ 3 binding, next steps |
| [decisions/](https://github.com/shieldzk/shield-platform/tree/main/docs/decisions) | Decision records (tech stack, …) |

If you have both repos checked out side by side, the same files are at
`../shield-platform/docs/`.

Before changing circuits or contracts, check the shared protocol spec in
`architecture.md`. Commitments, nullifiers, Merkle tree parameters and public
inputs must match it exactly.
