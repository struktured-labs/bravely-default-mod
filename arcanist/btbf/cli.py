"""CLI interface for BTBF parser."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from arcanist.btbf.parser import BTBFFile, BTBF_MAGIC

BTBF_EXTENSIONS = {".btb", ".mtb", ".tbl", ".txb", ".trb", ".spb", ".subtitles"}


def is_btbf_file(path: Path) -> bool:
    """Check if a file is a BTBF file by magic bytes."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == BTBF_MAGIC
    except (OSError, IOError):
        return False


def cmd_info(args: argparse.Namespace) -> None:
    """Show header info for a BTBF file."""
    path = Path(args.file)
    btbf = BTBFFile.from_file(path)
    print(f"File: {path}")
    print(btbf.info())
    if args.labels:
        print(f"\n  Labels ({len(btbf.labels)}):")
        for i, label in enumerate(btbf.labels):
            print(f"    [{i}] {label}")
    if args.strings:
        print(f"\n  Strings ({len(btbf.strings)}):")
        for off in sorted(btbf.strings):
            print(f"    [0x{off:x}] {btbf.strings[off][:80]}")
    if args.preview:
        n = min(args.preview, len(btbf.rows))
        print(f"\n  First {n} rows (with resolved strings):")
        for ri in range(n):
            row = btbf.get_row_with_strings(ri)
            # Show only non-zero or string fields for readability
            parts = []
            for fi, val in enumerate(row):
                if isinstance(val, str) or val != 0:
                    parts.append(f"[{fi}]={val!r}" if isinstance(val, str) else f"[{fi}]={val}")
            print(f"    Row {ri}: {', '.join(parts)}")


def cmd_dump(args: argparse.Namespace) -> None:
    """Dump a BTBF file to CSV or JSON."""
    path = Path(args.file)
    btbf = BTBFFile.from_file(path)

    fmt = args.format.lower()
    if args.output:
        outpath = Path(args.output)
    else:
        outpath = path.with_suffix(f".{fmt}")

    if fmt == "csv":
        content = btbf.to_csv()
    elif fmt == "json":
        content = btbf.to_json()
    else:
        print(f"Unknown format: {fmt}", file=sys.stderr)
        sys.exit(1)

    outpath.write_text(content, encoding="utf-8")
    print(f"Wrote {outpath} ({len(btbf.rows)} rows, {btbf.header.num_fields} fields)")


def cmd_dump_all(args: argparse.Namespace) -> None:
    """Dump all BTBF files in a directory tree."""
    root = Path(args.directory)
    fmt = args.format.lower()
    count = 0
    errors = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in BTBF_EXTENSIONS:
            continue
        if not is_btbf_file(path):
            continue
        try:
            btbf = BTBFFile.from_file(path)
            if args.output_dir:
                rel = path.relative_to(root)
                outpath = Path(args.output_dir) / rel.with_suffix(f".{fmt}")
                outpath.parent.mkdir(parents=True, exist_ok=True)
            else:
                outpath = path.with_suffix(f".{fmt}")

            if fmt == "csv":
                content = btbf.to_csv()
            else:
                content = btbf.to_json()

            outpath.write_text(content, encoding="utf-8")
            print(f"  {path.name} -> {outpath.name} ({btbf.header.num_rows} rows)")
            count += 1
        except Exception as e:
            print(f"  ERROR {path.name}: {e}", file=sys.stderr)
            errors += 1

    print(f"\nDumped {count} files ({errors} errors)")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="btbf",
        description="BTBF binary table parser for Bravely Default HD",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # info
    p_info = subparsers.add_parser("info", help="Show BTBF file header info")
    p_info.add_argument("file", help="Path to BTBF file")
    p_info.add_argument("--labels", action="store_true", help="Show ASCII labels")
    p_info.add_argument("--strings", action="store_true", help="Show all UTF-16 strings")
    p_info.add_argument("--preview", type=int, metavar="N", help="Preview first N rows")

    # dump
    p_dump = subparsers.add_parser("dump", help="Dump BTBF file to CSV/JSON")
    p_dump.add_argument("file", help="Path to BTBF file")
    p_dump.add_argument("-f", "--format", default="csv", choices=["csv", "json"], help="Output format")
    p_dump.add_argument("-o", "--output", help="Output file path")

    # dump-all
    p_dump_all = subparsers.add_parser("dump-all", help="Dump all BTBF files in directory")
    p_dump_all.add_argument("directory", help="Directory to search")
    p_dump_all.add_argument("-f", "--format", default="csv", choices=["csv", "json"], help="Output format")
    p_dump_all.add_argument("-o", "--output-dir", help="Output directory")

    args = parser.parse_args(argv)

    if args.command == "info":
        cmd_info(args)
    elif args.command == "dump":
        cmd_dump(args)
    elif args.command == "dump-all":
        cmd_dump_all(args)


if __name__ == "__main__":
    main()
