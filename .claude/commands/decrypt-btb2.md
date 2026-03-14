Decompress a .btb2 or .tbl2 file and optionally parse it.

Usage: /decrypt-btb2 <filename or path>

If the argument is just a filename (e.g., "MonsterData.btb2"), search for it under:
`~/.steam/debian-installation/steamapps/common/BDFFHD/BDFFHD_Data/StreamingAssets/Common_en/`

Steps:
1. Find the file
2. Decompress using `uv run python -c "from arcanist.btbf.crypto import Btb2File; ..."`
3. Show the decompressed size and first 64 bytes hex
4. If the decompressed data starts with BTBF magic, parse it with BTBFFile and show summary
5. Save decompressed output to `tmp/<original_name>.dec` for inspection

$ARGUMENTS
