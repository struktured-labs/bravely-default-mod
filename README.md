# bs-999k — Bravely Second (3DS) 999k damage-cap

Scaffolding worktree for a Bravely Second: End Layer 999k damage/heal cap mod.
Based on the Bravely Default `release/999k-3ds` tooling lineage.

**Status:** dump-ready pipeline. No game data in git. Scan stops before patching.

See **[BRAVELY_SECOND.md](./BRAVELY_SECOND.md)** for dump steps and the one-command ingest path.

```bash
# After a dump lands on blackmage:
~/projects/bs-999k/scripts/ingest.sh ~/bs-dump/incoming/<dump.cia|dump.3ds|code.bin>
```

Title IDs: USA `000400000017BA00` (preferred), EUR `000400000017BB00`, JPN `00040000000DC800`.
