#@author struktured
#@category BravelyDefault
#@keybinding
#@menupath
#@toolbar

# Patches the 9999 everything cap in Bravely Default to 999,999
# Includes at least damage and heal caps, possibly more.

# Requires current program to be a Bravely Default "code.bin" ROM loaded in Ghidra
from ghidra.program.model.data import DWordDataType
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.symbol import SourceType

target_value = 0x270F      # 9999
new_value = 0x0F423F       # 999,999

listing = currentProgram.getListing()
mem = currentProgram.getMemory()

patched = 0
added_bookmarks = 0

data_iter = listing.getDefinedData(True)

print("Scanning for referenced 9999 caps...")

while data_iter.hasNext() and not monitor.isCancelled():
    data = data_iter.next()
    
    # Only patch 4-byte defined values
    if data.getDataType().getLength() != 4:
        continue

    addr = data.getMinAddress()

    try:
        # Must be value 0x270F (9999)
        if not data.getValue():
            continue

        v = data.getValue()
        # Convert value like '0000270F' to int
        if not v:
            continue
        v = int(str(v), 16)

        if v != target_value:
            print("v not target: %d vs %d" % (v, target_value))
            continue

        # Check it's referenced
        if len(getReferencesTo(addr)) == 0:
            continue

        # Patch it
        mem.setInt(addr, new_value)

        # Comment it
        setPlateComment(addr, "Patched: raised cap from 9999 -> 999999")

        # Bookmark it (optional)
        createBookmark(addr, "9999 Patch", "Clamping constant raised")
        added_bookmarks += 1

        print("[x] Patched %s" % str(addr))
        patched += 1

    except MemoryAccessException as e:
        print("[!] Memory access error at %s: %s" % (addr, str(e)))
        continue
    except Exception as e:
        print("[!] Unexpected error at %s: %s" % (addr, str(e)))
        continue

print("\n Done! Patched %d constants. Bookmarks added: %d" % (patched, added_bookmarks))
