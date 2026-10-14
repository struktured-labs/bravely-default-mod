#@category BravelyDefault
# Dumps, for each patched site, referencing functions, callers, strings, constants, decompiled excerpt.
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import StringDataType
args = getScriptArgs()
sites = [int(l.strip(),16) for l in open(args[0]) if l.strip()]
out = args[1]
af = currentProgram.getAddressFactory()
fm = currentProgram.getFunctionManager(); listing = currentProgram.getListing()
di = DecompInterface(); di.openProgram(currentProgram)
cache = {}
def fninfo(f):
    k = f.getEntryPoint().getOffset()
    if k in cache: return cache[k]
    callers = []
    for r in getReferencesTo(f.getEntryPoint()):
        cf = fm.getFunctionContaining(r.getFromAddress())
        if cf: callers.append("%s@%x" % (cf.getName(), cf.getEntryPoint().getOffset()))
    strs = []; consts = set(); callees = []
    for ins in listing.getInstructions(f.getBody(), True):
        for r in ins.getReferencesFrom():
            d = listing.getDataAt(r.getToAddress())
            if d and d.hasStringValue(): strs.append(str(d.getValue())[:60])
            elif d and d.getDataType().getLength()==4:
                try: consts.add(int(str(d.getValue()),16))
                except: pass
            tf = fm.getFunctionAt(r.getToAddress())
            if tf and ins.getFlowType().isCall(): callees.append(tf.getName())
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                if hasattr(o,'getValue') and o.__class__.__name__=='Scalar':
                    v=o.getValue()
                    if v>255: consts.add(v)
    dec = ""
    try:
        res = di.decompileFunction(f, 60, monitor)
        if res.decompileCompleted(): dec = res.getDecompiledFunction().getC()
    except: pass
    info = {"name": f.getName(), "entry": "%x"%k, "size": f.getBody().getNumAddresses(),
            "callers": sorted(set(callers))[:15], "ncallers": len(set(callers)),
            "callees": sorted(set(callees))[:25], "strings": sorted(set(strs))[:20],
            "consts": sorted(consts)[:60], "decomp": dec[:6000]}
    cache[k] = info; return info
res = []
for s in sites:
    a = af.getDefaultAddressSpace().getAddress(s)
    refs = []
    for r in getReferencesTo(a):
        f = fm.getFunctionContaining(r.getFromAddress())
        refs.append({"from": "%x" % r.getFromAddress().getOffset(), "func": fninfo(f)["entry"] if f else None})
    res.append({"site": "%x"%s, "refs": refs})
json.dump({"sites": res, "funcs": cache}, open(out,"w"), indent=1)
print("WROTE %d sites %d funcs" % (len(res), len(cache)))
