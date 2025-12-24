# Bravely Default Mod Toolkit

A comprehensive toolkit for modding Bravely Default, including automated patch generation for the 999k damage limit mod and crowd data editing.

## Features

- **999k Damage Limit Patch**: Increases the damage cap from 9,999 to 999,999
- **IPS Patch Generation**: Creates distributable IPS patches from ROM modifications
- **Crowd Data Editor**: Extract and modify game data via spreadsheets
- **Automated Build Pipeline**: Simple make commands to generate patches
- **Docker Support**: Containerized Ghidra for reproducible builds

## Quick Start

### Prerequisites

- A legally obtained Bravely Default CIA file
- One of the following:
  - [Pixi](https://prefix.dev/docs/pixi/overview) (recommended)
  - Conda/Micromamba
  - Docker (for Ghidra-only workflow)

### Setup

1. Clone the repository:
```bash
git clone <repo-url>
cd bravely-default-mod
```

2. Initialize submodules and set up environment:
```bash
make setup
make pixi-install  # Or 'make environment' for conda
```

3. Place your Bravely Default CIA file in the `cias/` directory

### Generate the 999k Damage Limit Patch

Run the complete workflow to generate an IPS patch:

```bash
make patch-workflow cia_file=cias/bravely-default.cia
```

This will:
1. Extract the CIA file
2. Apply Ghidra patches to code.bin
3. Generate an IPS patch file at `build/patches/bd_999k_limit.ips`

You can now distribute the `.ips` file!

### Apply an IPS Patch

To apply the patch to a ROM:

```bash
make apply-patch
```

Or manually with custom paths:

```bash
python3 scripts/apply_ips_patch.py \
  --patch build/patches/bd_999k_limit.ips \
  --input path/to/code.bin \
  --backup
```

## Manual Build Steps

For more control, you can run individual steps:

1. **Extract CIA file**:
```bash
make cia-unpack cia_file=cias/bravely-default.cia
```

2. **Save original ROM** (required for patch generation):
```bash
make save-original
```

3. **Apply Ghidra patches**:
```bash
make ghidra-patch
# Or with Docker:
make ghidra-patch-docker
```

4. **Generate IPS patch**:
```bash
make generate-patch
```

## Docker Workflow

If you prefer to use Docker for Ghidra (avoids manual Ghidra installation):

```bash
# Build Docker image
docker-compose build

# Run Ghidra patches in Docker
make ghidra-patch-docker
```

## Crowd Data Editing

Extract game data to editable spreadsheets:

```bash
make crowd-unpack
```

Edit the spreadsheets in `build/crowd-dev-unpacked/`, then pack them back:

```bash
make crowd-pack
```

## Development

### Arcanist

The `arcanist` Python package provides tools for:
- Extracting/packing crowd binary data
- Applying code patches with ARM assembly
- Managing memory regions for safe code injection

See [arcanist/README.md](arcanist/README.md) for details.

### Ghidra Scripts

Ghidra scripts are in `ghidra_scripts/`:
- `999k-limit-patch.py` - Changes damage cap from 9999 to 999,999
- `find_empty_addresses.py` - Finds empty memory regions for code injection

### Adding Custom Patches

1. Create a Ghidra script or Python patch in `arcanist/patches/`
2. Update `bin/ghidra-patch.sh` or create a new make target
3. Run the patch workflow to generate an IPS file

## Environment Management

### Using Pixi (Recommended)

```bash
pixi install                    # Install dependencies
pixi run crowd-unpack          # Run a task
pixi shell                     # Enter the environment
```

### Using Conda/Micromamba

```bash
make environment               # Create environment
micromamba activate bd-dev     # Activate environment
```

## Project Structure

```
.
├── arcanist/           # Python tools for ROM modification
│   ├── crowd/         # Crowd data extraction/packing
│   └── patches/       # Code patches
├── bin/               # Shell scripts
├── ghidra_scripts/    # Ghidra headless scripts
├── scripts/           # IPS patch tools
│   ├── generate_ips_patch.py
│   └── apply_ips_patch.py
├── data/              # Game data and schemas
├── build/             # Build output (generated)
└── Makefile           # Build automation
```

## Troubleshooting

### Ghidra not found

If using the native Ghidra workflow (not Docker):
- Set `GHIDRA_HOME` environment variable to your Ghidra installation
- Or use Docker: `make ghidra-patch-docker`

### Submodules not initialized

```bash
git submodule update --init
```

### Missing Python dependencies

```bash
pixi install
# Or for conda:
make environment
```

## Contributing

Pull requests welcome! Please ensure your code passes existing tests.

## License

See LICENSE file for details.

## Credits

- Based on the bravely-crowd project
- Uses Ghidra for reverse engineering
- Built with love for the Bravely Default community

