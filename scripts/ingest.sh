#!/usr/bin/env bash
# Ingest a Bravely Second dump: extract decompressed code.bin, verify TID,
# run Ghidra 0x270F scan, STOP (no patch).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DUMP_ROOT="${BS_DUMP_ROOT:-$HOME/bs-dump}"
INCOMING="${DUMP_ROOT}/incoming"
EXTRACTED="${DUMP_ROOT}/extracted"
PYTHON="${BS_PYTHON:-$HOME/.venvs/bs999k/bin/python}"
PATH="$HOME/.local/bin:$PATH"
export PATH

USA_TID="000400000017BA00"
EUR_TID="000400000017BB00"
JPN_TID="00040000000DC800"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options] <file>

Ingest a Bravely Second dump and run a scan-only 0x270F site finder.

Accepted inputs:
  .cia / .3ds / .cci  GodMode9 decrypted dump
  .cxi / .app         Already-extracted NCCH
  code.bin / .code    Already-decompressed ExeFS code (still needs --tid if undetectable)

Options:
  -h, --help          Show this help
  --dry-run           Validate args / detect type only; do not extract or scan
  --tid TID           Force title ID (16 hex chars), e.g. $USA_TID
  --skip-scan         Extract + verify only
  --out-dir DIR       Build output root (default: $ROOT/build)

Env:
  BS_DUMP_ROOT   default $HOME/bs-dump
  BS_PYTHON      default $HOME/.venvs/bs999k/bin/python
  GHIDRA_HOME    default \$HOME/ghidra/ghidra_11.2.1_PUBLIC
USAGE
}

DRY_RUN=0
SKIP_SCAN=0
FORCE_TID=""
OUT_ROOT="$ROOT/build"
INPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --skip-scan) SKIP_SCAN=1; shift ;;
    --tid) FORCE_TID="${2:?}"; shift 2 ;;
    --out-dir) OUT_ROOT="${2:?}"; shift 2 ;;
    --) shift; break ;;
    -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) INPUT="$1"; shift; break ;;
  esac
done
# leftover
[[ $# -gt 0 && -z "$INPUT" ]] && INPUT="$1"

if [[ -z "${INPUT}" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$INPUT" ]]; then
  echo "ERROR: file not found: $INPUT" >&2
  exit 1
fi

INPUT="$(realpath "$INPUT")"
base="$(basename "$INPUT")"
ext="$(echo "${base##*.}" | tr 'A-Z' 'a-z')"
# also accept bare 'code.bin'
name_l="$(echo "$base" | tr 'A-Z' 'a-z')"

detect_type() {
  if [[ "$name_l" == "code.bin" || "$name_l" == ".code" || "$ext" == "code" ]]; then
    echo "code"; return
  fi
  case "$ext" in
    cia) echo "cia" ;;
    3ds|cci) echo "ncsd" ;;
    cxi|app) echo "ncch" ;;
    bin)
      # Heuristic: code.bin often named *.bin
      local sz
      sz=$(stat -c%s "$INPUT")
      if [[ "$name_l" == *code* ]] || [[ $sz -lt 20000000 ]]; then
        echo "code"
      else
        echo "unknown_bin"
      fi
      ;;
    *) echo "unknown" ;;
  esac
}

TYPE="$(detect_type)"
echo "==> Input: $INPUT"
echo "==> Detected type: $TYPE"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run OK (type=$TYPE). Would extract/verify/scan next."
  exit 0
fi

workdir="$EXTRACTED/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$workdir"
meta="$workdir/meta.txt"
sha256sum "$INPUT" | tee "$workdir/input.sha256"
echo "input=$INPUT" > "$meta"
echo "type=$TYPE" >> "$meta"

need_cmd() {
  command -v "$1" >/dev/null || { echo "ERROR: missing command: $1" >&2; exit 1; }
}

extract_tid_from_ctrtool() {
  # Parse "Title ID               : 000400000017ba00"
  local f="$1"
  ctrtool "$f" 2>/dev/null | awk -F: '
    tolower($0) ~ /title id/ {
      gsub(/^[ \t]+|[ \t]+$/, "", $2);
      print toupper($2);
      exit
    }'
}

region_for_tid() {
  case "$1" in
    000400000017BA00) echo "usa" ;;
    000400000017BB00) echo "eur" ;;
    00040000000DC800) echo "jpn" ;;
    *) echo "" ;;
  esac
}

TID=""
CODE_OUT=""

case "$TYPE" in
  code)
    need_cmd sha256sum
    CODE_SRC="$INPUT"
    if [[ -n "$FORCE_TID" ]]; then
      TID="$(echo "$FORCE_TID" | tr 'a-f' 'A-F')"
    else
      echo "WARNING: raw code.bin has no embedded title ID; pass --tid (USA $USA_TID preferred)" >&2
      TID=""
    fi
    ;;
  cia)
    need_cmd ctrtool
    need_cmd 3dstool
    echo "==> Extracting CIA with ctrtool..."
    mkdir -p "$workdir/cia"
    # contents + exefs dir (ctrtool decompresses .code when writing exefsdir)
    ctrtool --contents="$workdir/cia/content" \
            --exefs="$workdir/cia/exefs.bin" \
            --exefsdir="$workdir/cia/exefs_dir" \
            --exheader="$workdir/cia/exheader.bin" \
            "$INPUT" >"$workdir/ctrtool_cia.log" 2>&1 || {
      echo "ctrtool failed; see $workdir/ctrtool_cia.log" >&2
      tail -20 "$workdir/ctrtool_cia.log" >&2
      exit 1
    }
    TID="$(extract_tid_from_ctrtool "$INPUT")"
    # Prefer decompressed .code from exefsdir
    if [[ -f "$workdir/cia/exefs_dir/code.bin" ]]; then
      CODE_SRC="$workdir/cia/exefs_dir/code.bin"
    elif [[ -f "$workdir/cia/exefs_dir/.code" ]]; then
      CODE_SRC="$workdir/cia/exefs_dir/.code"
    else
      # Fallback: 3dstool on first content CXI
      CXI="$(ls "$workdir/cia"/content* 2>/dev/null | sort | head -n1 || true)"
      [[ -n "$CXI" ]] || { echo "ERROR: no CIA content CXI extracted" >&2; exit 1; }
      mkdir -p "$workdir/cxi/exefs_dir"
      3dstool -xv -t cxi -f "$CXI" --header "$workdir/cxi/header.bin" \
        --exefs "$workdir/cxi/exefs.bin" --exefs-dir "$workdir/cxi/exefs_dir" \
        >"$workdir/3dstool.log" 2>&1 || true
      if [[ -f "$workdir/cxi/exefs_dir/code.bin" ]]; then
        CODE_SRC="$workdir/cxi/exefs_dir/code.bin"
      elif [[ -f "$workdir/cxi/exefs_dir/.code" ]]; then
        CODE_SRC="$workdir/cxi/exefs_dir/.code"
      else
        echo "ERROR: could not locate decompressed code.bin" >&2
        exit 1
      fi
    fi
    ;;
  ncsd)
    need_cmd ctrtool
    need_cmd 3dstool
    echo "==> Extracting NCSD (.3ds) ..."
    mkdir -p "$workdir/ncsd" "$workdir/cxi/exefs_dir"
    # Decrypt extract of first partition as CXI via 3dstool
    3dstool -xv -t ncsd -f "$INPUT" --header "$workdir/ncsd/ncsd_header.bin" \
      --partition0 "$workdir/ncsd/part0.cxi" \
      >"$workdir/3dstool_ncsd.log" 2>&1 || {
      # Some dumps want -x without v; retry
      3dstool -x -t ncsd -f "$INPUT" --header "$workdir/ncsd/ncsd_header.bin" \
        --partition0 "$workdir/ncsd/part0.cxi" \
        >"$workdir/3dstool_ncsd.log" 2>&1 || {
        echo "3dstool NCSD extract failed; see $workdir/3dstool_ncsd.log" >&2
        tail -30 "$workdir/3dstool_ncsd.log" >&2
        exit 1
      }
    }
    CXI="$workdir/ncsd/part0.cxi"
    [[ -f "$CXI" ]] || { echo "ERROR: partition0 CXI missing" >&2; exit 1; }
    TID="$(extract_tid_from_ctrtool "$CXI")"
    [[ -n "$TID" ]] || TID="$(extract_tid_from_ctrtool "$INPUT")"
    3dstool -xv -t cxi -f "$CXI" --header "$workdir/cxi/header.bin" \
      --exefs "$workdir/cxi/exefs.bin" --exefs-dir "$workdir/cxi/exefs_dir" \
      >"$workdir/3dstool_cxi.log" 2>&1 || \
    3dstool -x -t cxi -f "$CXI" --header "$workdir/cxi/header.bin" \
      --exefs "$workdir/cxi/exefs.bin" --exefs-dir "$workdir/cxi/exefs_dir" \
      >"$workdir/3dstool_cxi.log" 2>&1 || {
      # ctrtool fallback
      ctrtool --exefsdir="$workdir/cxi/exefs_dir" --exefs="$workdir/cxi/exefs.bin" \
        --exheader="$workdir/cxi/exheader.bin" "$CXI" >"$workdir/ctrtool_cxi.log" 2>&1 || true
    }
    if [[ -f "$workdir/cxi/exefs_dir/code.bin" ]]; then
      CODE_SRC="$workdir/cxi/exefs_dir/code.bin"
    elif [[ -f "$workdir/cxi/exefs_dir/.code" ]]; then
      CODE_SRC="$workdir/cxi/exefs_dir/.code"
    else
      echo "ERROR: could not locate decompressed code.bin from .3ds" >&2
      exit 1
    fi
    ;;
  ncch)
    need_cmd ctrtool
    need_cmd 3dstool
    mkdir -p "$workdir/cxi/exefs_dir"
    TID="$(extract_tid_from_ctrtool "$INPUT")"
    3dstool -xv -t cxi -f "$INPUT" --header "$workdir/cxi/header.bin" \
      --exefs "$workdir/cxi/exefs.bin" --exefs-dir "$workdir/cxi/exefs_dir" \
      >"$workdir/3dstool_cxi.log" 2>&1 || \
    ctrtool --exefsdir="$workdir/cxi/exefs_dir" --exefs="$workdir/cxi/exefs.bin" \
      --exheader="$workdir/cxi/exheader.bin" "$INPUT" >"$workdir/ctrtool_cxi.log" 2>&1 || true
    if [[ -f "$workdir/cxi/exefs_dir/code.bin" ]]; then
      CODE_SRC="$workdir/cxi/exefs_dir/code.bin"
    elif [[ -f "$workdir/cxi/exefs_dir/.code" ]]; then
      CODE_SRC="$workdir/cxi/exefs_dir/.code"
    else
      echo "ERROR: could not locate decompressed code.bin from NCCH" >&2
      exit 1
    fi
    ;;
  *)
    echo "ERROR: unsupported type '$TYPE' for $INPUT" >&2
    exit 1
    ;;
esac

if [[ -n "$FORCE_TID" ]]; then
  TID="$(echo "$FORCE_TID" | tr 'a-f' 'A-F')"
fi
TID="$(echo "${TID:-}" | tr 'a-f' 'A-F' | tr -d ' ')"

echo "==> Title ID: ${TID:-UNKNOWN}"
REGION="$(region_for_tid "${TID:-}")"
if [[ -z "$REGION" ]]; then
  echo "ERROR: title ID '${TID}' is not a known Bravely Second ID." >&2
  echo "  Expected one of:" >&2
  echo "    USA $USA_TID" >&2
  echo "    EUR $EUR_TID" >&2
  echo "    JPN $JPN_TID" >&2
  echo "  Re-run with --tid if this is raw code.bin for one of those." >&2
  exit 1
fi
echo "==> Region: $REGION"

mkdir -p "$OUT_ROOT/$REGION"
CODE_DEST="$OUT_ROOT/$REGION/code.bin"
cp -f "$CODE_SRC" "$CODE_DEST"
sha256sum "$CODE_DEST" | tee "$OUT_ROOT/$REGION/code.bin.sha256"
echo "tid=$TID" > "$OUT_ROOT/$REGION/meta.txt"
echo "region=$REGION" >> "$OUT_ROOT/$REGION/meta.txt"
echo "source=$INPUT" >> "$OUT_ROOT/$REGION/meta.txt"
echo "workdir=$workdir" >> "$OUT_ROOT/$REGION/meta.txt"
echo "==> code.bin -> $CODE_DEST ($(stat -c%s "$CODE_DEST") bytes)"

if [[ "$SKIP_SCAN" -eq 1 ]]; then
  echo "==> --skip-scan: extraction complete. STOP."
  exit 0
fi

echo "==> Running Ghidra headless 0x270F scan (no patch)..."
SCAN_DIR="$OUT_ROOT/$REGION/scan"
PROJECT_NAME="bs-${REGION}-scan" GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra/ghidra_11.2.1_PUBLIC}" \
  "$ROOT/bin/ghidra-scan.sh" "$CODE_DEST" "$SCAN_DIR"

echo
echo "============================================"
echo "STOP — site candidates ready for review:"
echo "  $SCAN_DIR/sites_candidates.md"
echo "  $SCAN_DIR/sites_candidates.json"
echo "Do NOT generate IPS until sites are reviewed"
echo "(skip DateTime year-9999 sites; keep damage/heal)."
echo "============================================"
