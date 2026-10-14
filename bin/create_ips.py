#!/usr/bin/env python3
"""
Create IPS (Internal Patching System) patch files.
IPS format specification: https://zerosoft.zophar.net/ips.php
"""

import argparse
import struct
from pathlib import Path


def create_ips_patch(original_file: Path, modified_file: Path, output_file: Path):
    """
    Create an IPS patch from original and modified files.
    
    IPS Format:
    - Header: "PATCH" (5 bytes)
    - Records: [offset (3 bytes BE), size (2 bytes BE), data (size bytes)]
    - Footer: "EOF" (3 bytes)
    """
    
    with open(original_file, 'rb') as f:
        original_data = f.read()
    
    with open(modified_file, 'rb') as f:
        modified_data = f.read()
    
    if len(original_data) != len(modified_data):
        raise ValueError(
            f"File sizes must match: original={len(original_data)}, "
            f"modified={len(modified_data)}"
        )
    
    # Find differences and create records
    records = []
    i = 0
    while i < len(original_data):
        if original_data[i] != modified_data[i]:
            # Found a difference, find the extent
            start = i
            chunk = bytearray()
            
            # Collect consecutive differences (up to 65535 bytes per record)
            while i < len(original_data) and len(chunk) < 65535:
                if original_data[i] != modified_data[i]:
                    chunk.append(modified_data[i])
                    i += 1
                else:
                    # Check if there are more differences nearby (within 4 bytes)
                    lookahead = 0
                    for j in range(i, min(i + 4, len(original_data))):
                        if original_data[j] != modified_data[j]:
                            lookahead = j - i + 1
                            break
                    
                    if lookahead > 0:
                        # Include the matching bytes and continue
                        for j in range(lookahead):
                            if i < len(original_data):
                                chunk.append(modified_data[i])
                                i += 1
                    else:
                        # No more differences nearby, end this record
                        break
            
            records.append((start, bytes(chunk)))
        else:
            i += 1
    
    # Write IPS file
    with open(output_file, 'wb') as f:
        # Header
        f.write(b'PATCH')
        
        # Records
        for offset, data in records:
            if offset > 0xFFFFFF:
                raise ValueError(f"Offset {offset} exceeds IPS maximum (16MB)")
            
            # Offset (3 bytes, big-endian)
            f.write(struct.pack('>I', offset)[1:])  # Skip first byte to get 3 bytes
            
            # Size (2 bytes, big-endian)
            f.write(struct.pack('>H', len(data)))
            
            # Data
            f.write(data)
        
        # Footer
        f.write(b'EOF')
    
    print(f"Created IPS patch: {output_file}")
    print(f"  Records: {len(records)}")
    print(f"  Total changed bytes: {sum(len(data) for _, data in records)}")
    
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Create IPS patch files from original and modified binaries"
    )
    parser.add_argument(
        "original",
        type=Path,
        help="Original file"
    )
    parser.add_argument(
        "modified",
        type=Path,
        help="Modified file"
    )
    parser.add_argument(
        "output",
        type=Path,
        help="Output IPS patch file"
    )
    
    args = parser.parse_args()
    
    if not args.original.exists():
        print(f"Error: Original file not found: {args.original}")
        return 1
    
    if not args.modified.exists():
        print(f"Error: Modified file not found: {args.modified}")
        return 1
    
    try:
        create_ips_patch(args.original, args.modified, args.output)
        return 0
    except Exception as e:
        print(f"Error creating IPS patch: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
