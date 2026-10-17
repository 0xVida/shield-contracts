# Agent instructions — shield-contracts

Project docs are NOT in this repo. Before planning or changing anything, read the
docs in the shield-platform repo, because they are the source of truth:

- Local (if checked out next to this repo): `../shield-platform/docs/`
- Remote: https://github.com/shieldzk/shield-platform/tree/main/docs

Always read:
- `architecture.md`: shared protocol spec (Poseidon parameters, commitment,
  nullifier, Merkle tree, public inputs) and open decisions. Circuits and
  contracts here must match the spec exactly. Don't invent values for anything
  marked "proposed" or "TBD"; flag it instead.
- `team.md`: who owns which circuit and contract functions.

Don't create or edit project docs in this repo. Propose doc changes for
shield-platform/docs instead.
