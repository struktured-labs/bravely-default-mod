#@category BravelyDefault
# Writes the current program's (possibly patched) bytes back out as a raw binary.
# Usage: -postScript export_code_bin.py <output_path>
from java.io import FileOutputStream
out = getScriptArgs()[0]
mem = currentProgram.getMemory()
fos = FileOutputStream(out)
total = 0
for blk in sorted(mem.getBlocks(), key=lambda b: b.getStart().getOffset()):
    if not blk.isInitialized():
        continue
    if blk.getStart().getOffset() != total:
        raise Exception("non-contiguous block at %s (expected offset %x)" % (blk.getStart(), total))

    import jarray
    jb = jarray.zeros(int(blk.getSize()), 'b')
    blk.getBytes(blk.getStart(), jb)
    fos.write(jb)
    total += blk.getSize()
fos.close()
print("Exported %d bytes to %s" % (total, out))
