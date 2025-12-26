# A bravely default editor toolkit

## Quick start

- `make help` for target overview
- Recommended env manager: Pixi

```bash
curl -fsSL https://pixi.sh/install.sh | bash
pixi install
pixi run crowd-unpack
```

## Arcanist (Forked from bravely crowd)

### Description

Extracts a spread sheet of editable values from a bravely default bin file. See arcanist/README.md

## Shell scripts

- Unpack a CIA: `make cia-unpack cia_file=cias/bd.cia`
- Crowd data pipeline: `pixi run crowd-unpack` / `pixi run crowd-pack`
- IPS generation: `make ips-crowd-patch` / `make ips-99k-patch`

## Ghidra

Patch example (99k limit IPS):
```bash
make ghidra-setup   # one-time (if using local script)
make ips-99k-patch  # produces build/dev/patches/99k-limit.ips
```

## Environment: Pixi

Pixi replaces previous micromamba/uv workflow.

Install & bootstrap:
```bash
curl -fsSL https://pixi.sh/install.sh | bash
pixi install
```

Common tasks:
```bash
pixi run crowd-unpack
pixi run crowd-pack
pixi run ips-crowd
pixi run ips-99k
```

Enter shell:
```bash
pixi shell
```

List tasks:
```bash
pixi task list
```

## Legacy

Old micromamba references are deprecated; use Pixi tasks instead.

