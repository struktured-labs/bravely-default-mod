#@author struktured and ChatGPT
#@category BravelyDefault 
#@keybinding
#@menupath
#@toolbar
"""
Finds empty (0x00 or 0xFF) regions in memory, useful for ROM patch injection.
"""

from ghidra.program.model.mem import MemoryAccessException
import json
min_len = 16  # Minimum number of consecutive 0x00 or 0xFF to consider
scan_all = True  # Set False to only scan .text

memory = currentProgram.getMemory()
listing = currentProgram.getListing()

def is_empty_byte(byte):
    return byte == 0x00 or byte == 0xFF

def find_empty_regions(start, end, min_len):
    monitor.setMessage("Scanning for empty regions...")
    empty_regions = []

    curr = start
    region_start = None
    region_len = 0

    while curr < end:
        try:
            byte = memory.getByte(curr) & 0xFF
        except MemoryAccessException:
            curr = curr.add(1)
            continue

        if is_empty_byte(byte):
            if region_start is None:
                region_start = curr
                region_len = 1
            else:
                region_len += 1
        else:
            if region_start and region_len >= min_len:
                empty_regions.append((region_start, region_len))
            region_start = None
            region_len = 0

        curr = curr.add(1)

    if region_start and region_len >= min_len:
        empty_regions.append((region_start, region_len))

    return empty_regions

# Choose memory blocks to scan
blocks = memory.getBlocks()
results = []

for block in blocks:
    name = block.getName()
    if not scan_all and ".text" not in name.lower():
        continue
    start = block.getStart()
    end = block.getEnd()
    results += find_empty_regions(start, end, min_len)

# Print results
if results:
    print("Found ", len(results),  "empty region(s) >=", {min_len}, "bytes:")

    
    results_dict = [{'addr': str(addr), 'len': int(length)} for addr, length in results]

    with open("empty_regions.json", "w") as f:
        json.dump(results_dict, f, indent=4)
    print(json.dumps(results_dict, indent=4))
else:
    print("No empty regions found with length >=", min_len, "bytes.")
