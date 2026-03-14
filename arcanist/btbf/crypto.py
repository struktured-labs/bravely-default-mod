"""btb2/tbl2 compressed file support.

.btb2/.tbl2 files are Brotli-compressed game table data.
Format: 4-byte header (0x00 0x01 0x53 0x53) + Brotli stream.

Despite earlier assumptions, these files are NOT encrypted.
The Aesutil class in the binary (key: StringLiteral_16192, IV: StringLiteral_6184)
is only used by UGCfilterImpl (profanity filter), not for game data files.

The decompressed data is the game's native binary table format (NOT BTBF).
It uses a custom serialization with inline ASCII strings and typed fields.

Usage:
    from arcanist.btbf.crypto import Btb2File

    # Decompress
    data = Btb2File.decompress_file("path/to/file.btb2")

    # Recompress (after editing)
    Btb2File.compress_file(data, "path/to/output.btb2")

    # Round-trip check
    raw = Path("file.btb2").read_bytes()
    assert Btb2File.is_btb2(raw)
    plain = Btb2File.decompress(raw)
    recompressed = Btb2File.compress(plain)
"""

from __future__ import annotations

from pathlib import Path

try:
    import brotli
except ImportError:
    brotli = None  # type: ignore


BTB2_MAGIC = b"\x00\x01\x53\x53"
BTB2_HEADER_SIZE = 4


class Btb2Error(Exception):
    pass


class Btb2File:
    """Decompress and recompress .btb2/.tbl2 files (Brotli compression)."""

    @staticmethod
    def _check_brotli() -> None:
        if brotli is None:
            raise ImportError(
                "brotli package required. Install with: uv add brotli"
            )

    @staticmethod
    def decompress(data: bytes) -> bytes:
        """Decompress a btb2 buffer: strip 4-byte header, Brotli decompress."""
        Btb2File._check_brotli()

        if len(data) < BTB2_HEADER_SIZE:
            raise Btb2Error(f"Data too short: {len(data)} < {BTB2_HEADER_SIZE}")

        magic = data[:4]
        if magic != BTB2_MAGIC:
            raise Btb2Error(
                f"Invalid btb2 magic: {magic.hex()}, expected {BTB2_MAGIC.hex()}"
            )

        payload = data[BTB2_HEADER_SIZE:]
        try:
            return brotli.decompress(payload)
        except brotli.error as e:
            raise Btb2Error(f"Brotli decompression failed: {e}") from e

    @staticmethod
    def compress(plaintext: bytes) -> bytes:
        """Compress data to btb2 format: Brotli compress + prepend 4-byte header."""
        Btb2File._check_brotli()
        compressed = brotli.compress(plaintext)
        return BTB2_MAGIC + compressed

    @staticmethod
    def decompress_file(path: str | Path) -> bytes:
        """Read and decompress a .btb2/.tbl2 file."""
        data = Path(path).read_bytes()
        return Btb2File.decompress(data)

    @staticmethod
    def compress_file(
        plaintext: bytes, output_path: str | Path
    ) -> None:
        """Compress data and write to a .btb2/.tbl2 file."""
        compressed = Btb2File.compress(plaintext)
        Path(output_path).write_bytes(compressed)

    @staticmethod
    def is_btb2(data: bytes) -> bool:
        """Check if data starts with the btb2 magic."""
        return len(data) >= 4 and data[:4] == BTB2_MAGIC

    @staticmethod
    def is_btb2_file(path: str | Path) -> bool:
        """Check if a file is btb2 format."""
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == BTB2_MAGIC


# Keep the Aesutil credentials for reference (used by UGCfilterImpl profanity filter)
# These are NOT used for btb2 files but may be useful for other modding.
AESUTIL_KEY = b'9jGQ$#ASDGFma=o%'       # StringLiteral_16192, 16 bytes
AESUTIL_IV  = b'fma8$!%EFSDm0-12TQ#$cqmd9q0-&$20'  # StringLiteral_6184, 32 bytes
