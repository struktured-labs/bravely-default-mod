"""BTBF binary table format parser.

BTBF Header Layout (little-endian, all uint32 unless noted):
  0x00  Magic           char[4] = "BTBF"
  0x04  Total file size
  0x08  Data section offset (always 0x30 = 48)
  0x0C  Data section size (= row_size * num_rows)
  0x10  String offset table start (absolute offset; ASCII null-separated labels)
  0x14  String offset table size
  0x18  String data section start (absolute offset; UTF-16LE strings)
  0x1C  String data section size
  0x20  Row size (bytes per record)
  0x24  Number of rows
  0x28  Padding (8 bytes of zeros)

Data rows are fixed-size records of uint32 values.
String fields in rows store byte offsets into the UTF-16LE string data section.
"""

from __future__ import annotations

import csv
import io
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BTBF_MAGIC = b"BTBF"
HEADER_SIZE = 0x30  # 48 bytes


@dataclass
class BTBFHeader:
    """Parsed BTBF file header."""

    magic: bytes
    total_size: int
    data_offset: int
    data_size: int
    str_table_offset: int
    str_table_size: int
    str_data_offset: int
    str_data_size: int
    row_size: int
    num_rows: int

    @property
    def num_fields(self) -> int:
        return self.row_size // 4

    @classmethod
    def from_bytes(cls, data: bytes) -> BTBFHeader:
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Data too short for BTBF header: {len(data)} < {HEADER_SIZE}")
        magic = data[0:4]
        if magic != BTBF_MAGIC:
            raise ValueError(f"Invalid magic: {magic!r}, expected {BTBF_MAGIC!r}")
        fields = struct.unpack_from("<IIIIIIIII", data, 4)
        return cls(
            magic=magic,
            total_size=fields[0],
            data_offset=fields[1],
            data_size=fields[2],
            str_table_offset=fields[3],
            str_table_size=fields[4],
            str_data_offset=fields[5],
            str_data_size=fields[6],
            row_size=fields[7],
            num_rows=fields[8],
        )

    def to_bytes(self) -> bytes:
        return BTBF_MAGIC + struct.pack(
            "<IIIIIIIII",
            self.total_size,
            self.data_offset,
            self.data_size,
            self.str_table_offset,
            self.str_table_size,
            self.str_data_offset,
            self.str_data_size,
            self.row_size,
            self.num_rows,
        ) + b"\x00" * 8  # padding at 0x28..0x30


@dataclass
class BTBFFile:
    """A parsed BTBF file with rows, labels, and string data."""

    header: BTBFHeader
    rows: list[list[int]]  # each row is a list of uint32 values
    labels: list[str]  # ASCII labels from string offset table
    strings: dict[int, str]  # offset -> UTF-16LE string from string data section
    string_field_indices: set[int]  # which field indices are detected as string offsets
    _raw_str_table: bytes = field(default=b"", repr=False)
    _raw_str_data: bytes = field(default=b"", repr=False)

    @classmethod
    def from_bytes(cls, data: bytes) -> BTBFFile:
        header = BTBFHeader.from_bytes(data)

        # Parse data rows
        rows: list[list[int]] = []
        nf = header.num_fields
        for i in range(header.num_rows):
            offset = header.data_offset + i * header.row_size
            row = list(struct.unpack_from(f"<{nf}I", data, offset))
            rows.append(row)

        # Parse ASCII labels (null-separated)
        raw_str_table = data[header.str_table_offset : header.str_table_offset + header.str_table_size]
        labels = [s.decode("ascii", errors="replace") for s in raw_str_table.split(b"\x00") if s]

        # Parse UTF-16LE strings
        raw_str_data = data[header.str_data_offset : header.str_data_offset + header.str_data_size]
        strings = cls._parse_utf16_strings(raw_str_data)

        # Detect string fields
        string_field_indices = cls._detect_string_fields(rows, strings, header.str_data_size)

        return cls(
            header=header,
            rows=rows,
            labels=labels,
            strings=strings,
            string_field_indices=string_field_indices,
            _raw_str_table=raw_str_table,
            _raw_str_data=raw_str_data,
        )

    @classmethod
    def from_file(cls, path: str | Path) -> BTBFFile:
        path = Path(path)
        data = path.read_bytes()
        return cls.from_bytes(data)

    @staticmethod
    def _parse_utf16_strings(raw: bytes) -> dict[int, str]:
        """Parse all null-terminated UTF-16LE strings, keyed by byte offset."""
        strings: dict[int, str] = {}
        pos = 0
        while pos < len(raw) - 1:
            # Find end of string (double-null terminator)
            end = pos
            while end < len(raw) - 1:
                if raw[end : end + 2] == b"\x00\x00":
                    break
                end += 2
            if end > pos:
                try:
                    strings[pos] = raw[pos:end].decode("utf-16-le")
                except UnicodeDecodeError:
                    strings[pos] = raw[pos:end].decode("utf-16-le", errors="replace")
            pos = end + 2
        return strings

    @staticmethod
    def _detect_string_fields(
        rows: list[list[int]], strings: dict[int, str], str_data_size: int
    ) -> set[int]:
        """Detect which field indices are string offsets.

        A field is considered a string offset if for a significant fraction of
        non-zero values across all rows, the value is a valid offset into the
        string data section (i.e., it appears as a key in the strings dict).
        """
        if not rows:
            return set()

        nf = len(rows[0])
        valid_offsets = set(strings.keys())
        string_fields: set[int] = set()

        for fi in range(nf):
            total_nonzero = 0
            matches = 0
            for row in rows:
                v = row[fi]
                if v == 0:
                    # offset 0 is ambiguous (could be first string or integer 0)
                    continue
                total_nonzero += 1
                if v < str_data_size and v in valid_offsets:
                    matches += 1

            # If at least 50% of non-zero values are valid string offsets
            # and there are at least 2 matches, classify as string field.
            # Also include fields where ALL values are 0 if they are adjacent
            # to a confirmed string field (handled later).
            if total_nonzero > 0 and matches >= max(1, total_nonzero * 0.5):
                string_fields.add(fi)

        return string_fields

    def resolve_string(self, offset: int) -> str | None:
        """Look up a string by its byte offset in the string data section."""
        return self.strings.get(offset)

    def get_row_with_strings(self, row_idx: int) -> list[Any]:
        """Return a row with string offsets resolved to actual strings."""
        row = self.rows[row_idx]
        result: list[Any] = []
        for fi, val in enumerate(row):
            if fi in self.string_field_indices:
                s = self.resolve_string(val)
                result.append(s if s is not None else f"@{val}")
            else:
                result.append(val)
        return result

    def to_dicts(self) -> list[dict[str, Any]]:
        """Convert all rows to dicts with field indices as keys, strings resolved."""
        results = []
        for ri in range(len(self.rows)):
            row = self.get_row_with_strings(ri)
            d = {f"field_{fi:03d}": val for fi, val in enumerate(row)}
            results.append(d)
        return results

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "header": {
                    "total_size": self.header.total_size,
                    "data_offset": self.header.data_offset,
                    "data_size": self.header.data_size,
                    "str_table_offset": self.header.str_table_offset,
                    "str_table_size": self.header.str_table_size,
                    "str_data_offset": self.header.str_data_offset,
                    "str_data_size": self.header.str_data_size,
                    "row_size": self.header.row_size,
                    "num_rows": self.header.num_rows,
                    "num_fields": self.header.num_fields,
                },
                "labels": self.labels[:50],  # first 50 labels for context
                "string_fields": sorted(self.string_field_indices),
                "rows": self.to_dicts(),
            },
            indent=indent,
            ensure_ascii=False,
        )

    def to_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        nf = self.header.num_fields
        writer.writerow([f"field_{i:03d}" for i in range(nf)])
        for ri in range(len(self.rows)):
            writer.writerow(self.get_row_with_strings(ri))
        return buf.getvalue()

    def _rebuild_string_data(self) -> tuple[bytes, dict[int, int]]:
        """Rebuild the UTF-16LE string data section from the strings dict.

        Returns (raw_bytes, old_offset_to_new_offset_map).
        Preserves leading nulls and original byte layout by writing strings
        at their original offsets when possible.
        """
        if not self.strings:
            return b"", {}

        sorted_strings = sorted(self.strings.items())
        # Calculate total size needed
        max_end = 0
        for off, s in sorted_strings:
            end = off + len(s.encode("utf-16-le")) + 2  # +2 for null terminator
            max_end = max(max_end, end)

        # Build buffer preserving original offsets
        str_data = bytearray(max_end)
        offset_map: dict[int, int] = {}
        for off, s in sorted_strings:
            offset_map[off] = off  # identity mapping when preserving layout
            encoded = s.encode("utf-16-le") + b"\x00\x00"
            str_data[off : off + len(encoded)] = encoded

        return bytes(str_data), offset_map

    def to_bytes(self) -> bytes:
        """Serialize back to BTBF binary format (round-trip support).

        Uses the raw string data and label table when possible to ensure
        byte-perfect round-trips. Only rebuilds sections when strings have
        been modified.
        """
        # Use raw string data and label table directly (preserves exact layout)
        str_data = self._raw_str_data
        str_table = self._raw_str_table

        # Build data section from rows (offsets unchanged since we preserve layout)
        nf = self.header.num_fields
        data_section = bytearray()
        for row in self.rows:
            data_section.extend(struct.pack(f"<{nf}I", *row))

        # Calculate offsets, preserving any padding gap between label table and string data
        data_offset = HEADER_SIZE
        data_size = len(data_section)
        str_table_offset = data_offset + data_size
        str_table_size = len(str_table)

        # Preserve the original gap between label table end and string data start
        orig_gap = self.header.str_data_offset - (self.header.str_table_offset + self.header.str_table_size)
        if orig_gap < 0:
            orig_gap = 0
        padding = b"\x00" * orig_gap

        str_data_offset = str_table_offset + str_table_size + orig_gap
        str_data_size = len(str_data)
        total_size = str_data_offset + str_data_size

        # Build header
        header = BTBFHeader(
            magic=BTBF_MAGIC,
            total_size=total_size,
            data_offset=data_offset,
            data_size=data_size,
            str_table_offset=str_table_offset,
            str_table_size=str_table_size,
            str_data_offset=str_data_offset,
            str_data_size=str_data_size,
            row_size=self.header.row_size,
            num_rows=len(self.rows),
        )

        return header.to_bytes() + bytes(data_section) + bytes(str_table) + padding + bytes(str_data)

    def set_string(self, offset: int, new_value: str) -> int:
        """Update a string in the string data section.

        If the new string fits in the same space, it replaces in-place.
        Otherwise, appends to the end and returns the new offset.
        Updates _raw_str_data accordingly.
        """
        old_value = self.strings.get(offset)
        old_encoded = old_value.encode("utf-16-le") + b"\x00\x00" if old_value else b"\x00\x00"
        new_encoded = new_value.encode("utf-16-le") + b"\x00\x00"

        raw = bytearray(self._raw_str_data)

        if len(new_encoded) <= len(old_encoded):
            # Fits in place -- write and pad remainder with nulls
            raw[offset : offset + len(old_encoded)] = new_encoded + b"\x00" * (len(old_encoded) - len(new_encoded))
            self._raw_str_data = bytes(raw)
            self.strings[offset] = new_value
            return offset
        else:
            # Append to end
            new_offset = len(raw)
            raw.extend(new_encoded)
            self._raw_str_data = bytes(raw)
            # Remove old entry, add new
            if offset in self.strings:
                del self.strings[offset]
            self.strings[new_offset] = new_value
            return new_offset

    def info(self) -> str:
        """Return a human-readable summary of the file."""
        lines = [
            f"BTBF File Info",
            f"  Total size:       {self.header.total_size} bytes",
            f"  Data offset:      0x{self.header.data_offset:x}",
            f"  Data size:        {self.header.data_size} bytes",
            f"  Row size:         {self.header.row_size} bytes ({self.header.num_fields} fields)",
            f"  Number of rows:   {self.header.num_rows}",
            f"  String table:     0x{self.header.str_table_offset:x} ({self.header.str_table_size} bytes, {len(self.labels)} labels)",
            f"  String data:      0x{self.header.str_data_offset:x} ({self.header.str_data_size} bytes, {len(self.strings)} strings)",
            f"  String fields:    {sorted(self.string_field_indices)}",
        ]
        return "\n".join(lines)
