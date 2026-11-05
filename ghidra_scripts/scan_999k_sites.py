# -*- coding: utf-8 -*-
#@author struktured
#@category BravelySecond
#@keybinding
#@menupath
#@toolbar

# Scan-only: find referenced literal-pool 0x270F (9999) sites.
# Writes a candidate list for review. Does NOT patch.
#
# Usage (headless):
#   -postScript scan_999k_sites.py <out.json> [out.md]

from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.data import DWordDataType
import json
import jarray

TARGET = 0x270F  # 9999

args = getScriptArgs()
out_json = args[0] if args else "sites_candidates.json"
out_md = args[1] if len(args) > 1 else None

listing = currentProgram.getListing()
mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory()
space = af.getDefaultAddressSpace()

raw_hits = []
for blk in mem.getBlocks():
    if not blk.isInitialized():
        continue
    start = blk.getStart()
    size = int(blk.getSize())
    chunk = 0x100000
    off = 0
    while off + 4 <= size:
        n = min(chunk, size - off)
        try:
            buf = jarray.zeros(n, 'b')
            addr = start.add(off)
            blk.getBytes(addr, buf)
            i = 0
            while i + 4 <= n:
                b0 = buf[i] & 0xFF
                b1 = buf[i + 1] & 0xFF
                b2 = buf[i + 2] & 0xFF
                b3 = buf[i + 3] & 0xFF
                val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
                if val == TARGET:
                    a = start.add(off + i)
                    raw_hits.append(a)
                    if listing.getDefinedDataAt(a) is None:
                        try:
                            listing.createData(a, DWordDataType())
                        except Exception:
                            pass
                i += 4
        except Exception as e:
            print("[!] read error at +%x: %s" % (off, e))
        off += n

print("Raw LE 0x270F dword-aligned hits: %d" % len(raw_hits))

sites = []
seen = set()
for addr in raw_hits:
    off = addr.getOffset()
    if off in seen:
        continue
    seen.add(off)
    refs = list(getReferencesTo(addr))
    if len(refs) == 0:
        continue

    ref_infos = []
    funcs = []
    func_names = set()
    strings = []
    string_set = set()
    datetime_like = False

    for r in refs:
        fa = r.getFromAddress()
        f = fm.getFunctionContaining(fa)
        fname = f.getName() if f else None
        fentry = "%x" % f.getEntryPoint().getOffset() if f else None
        ref_infos.append({"from": "%x" % fa.getOffset(), "func": fname, "entry": fentry})
        if f and fname not in func_names:
            func_names.add(fname)
            funcs.append({"name": fname, "entry": fentry})

        imm_hits = set()
        try:
            if f is not None:
                for ins in listing.getInstructions(f.getBody(), True):
                    for oi in range(ins.getNumOperands()):
                        for o in ins.getOpObjects(oi):
                            if hasattr(o, "getValue") and o.__class__.__name__ == "Scalar":
                                sv = o.getValue()
                                if sv in (12, 31, 23, 59):
                                    imm_hits.add(sv)
                    for rr in ins.getReferencesFrom():
                        d = listing.getDataAt(rr.getToAddress())
                        if d is not None and d.hasStringValue():
                            s = str(d.getValue())[:80]
                            if s not in string_set:
                                string_set.add(s)
                                strings.append(s)
            if 12 in imm_hits and 31 in imm_hits and (23 in imm_hits or 59 in imm_hits):
                datetime_like = True
        except Exception:
            pass

    sites.append({
        "site": "%x" % off,
        "nrefs": len(refs),
        "refs": ref_infos[:20],
        "funcs": funcs,
        "strings": strings[:15],
        "datetime_suspect": datetime_like,
    })

sites.sort(key=lambda s: int(s["site"], 16))
n_dt = 0
for s in sites:
    if s["datetime_suspect"]:
        n_dt += 1

payload = {
    "target": TARGET,
    "target_name": "9999",
    "program": currentProgram.getName(),
    "nsites_referenced": len(sites),
    "ndatetime_suspect": n_dt,
    "nraw_hits": len(raw_hits),
    "sites": sites,
}
f = open(out_json, "w")
json.dump(payload, f, indent=1)
f.close()
print("WROTE %s (%d referenced sites, %d datetime-suspect)" % (out_json, len(sites), n_dt))

if out_md:
    lines = []
    lines.append("# 0x270F (9999) literal-pool candidates")
    lines.append("")
    lines.append("Program: `%s`" % currentProgram.getName())
    lines.append("Referenced sites: **%d** (raw aligned hits: %d; datetime-suspect: %d)" % (
        len(sites), len(raw_hits), n_dt))
    lines.append("")
    lines.append("Scan only -- no patches applied. Review before generating IPS.")
    lines.append("")
    lines.append("| Site | Refs | DateTime? | Functions | Sample strings |")
    lines.append("|---|---|---|---|---|")
    for s in sites:
        fn_parts = []
        for f in s["funcs"]:
            fn_parts.append("%s@%s" % (f["name"], f["entry"]))
        fn = ", ".join(fn_parts) if fn_parts else "(none)"
        st_parts = []
        for x in s["strings"][:3]:
            st_parts.append("`%s`" % x)
        st = ", ".join(st_parts)
        lines.append("| `0x%s` | %d | %s | %s | %s |" % (
            s["site"], s["nrefs"], "yes" if s["datetime_suspect"] else "", fn, st))
    f = open(out_md, "w")
    f.write("\n".join(lines) + "\n")
    f.close()
    print("WROTE %s" % out_md)
