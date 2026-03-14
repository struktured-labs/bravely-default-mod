# -*- coding: utf-8 -*-
"""
Headless-compatible IL2CPP label importer for Ghidra.
Reads script.json from Il2CppDumper and labels all functions/strings/metadata.

Usage (headless): pass script.json path via -scriptPath or hardcode below.
"""
import json
import os

SCRIPT_JSON = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(sourceFile.absolutePath))),
    "data", "il2cpp_dump", "script.json"
)

processFields = [
    "ScriptMethod",
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
    "Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED


def get_addr(addr):
    return baseAddress.add(addr)


def set_name(addr, name):
    name = name.replace(' ', '-')
    createLabel(addr, name, True, USER_DEFINED)


def make_function(start):
    func = getFunctionAt(start)
    if func is None:
        createFunction(start, None)


print("Loading script.json from: %s" % SCRIPT_JSON)
data = json.loads(open(SCRIPT_JSON, 'rb').read().decode('utf-8'))
print("Loaded script.json successfully")

if "ScriptMethod" in data and "ScriptMethod" in processFields:
    scriptMethods = data["ScriptMethod"]
    monitor.initialize(len(scriptMethods))
    monitor.setMessage("Labeling %d methods" % len(scriptMethods))
    print("Processing %d methods..." % len(scriptMethods))
    for scriptMethod in scriptMethods:
        addr = get_addr(scriptMethod["Address"])
        name = scriptMethod["Name"].encode("utf-8")
        set_name(addr, name)
        make_function(addr)
        monitor.incrementProgress(1)
    print("Methods done")

if "ScriptString" in data and "ScriptString" in processFields:
    index = 1
    scriptStrings = data["ScriptString"]
    monitor.initialize(len(scriptStrings))
    monitor.setMessage("Labeling %d strings" % len(scriptStrings))
    print("Processing %d strings..." % len(scriptStrings))
    for scriptString in scriptStrings:
        addr = get_addr(scriptString["Address"])
        value = scriptString["Value"].encode("utf-8")
        name = "StringLiteral_" + str(index)
        createLabel(addr, name, True, USER_DEFINED)
        setEOLComment(addr, value)
        index += 1
        monitor.incrementProgress(1)
    print("Strings done")

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
    scriptMetadatas = data["ScriptMetadata"]
    monitor.initialize(len(scriptMetadatas))
    monitor.setMessage("Labeling %d metadata entries" % len(scriptMetadatas))
    print("Processing %d metadata..." % len(scriptMetadatas))
    for scriptMetadata in scriptMetadatas:
        addr = get_addr(scriptMetadata["Address"])
        name = scriptMetadata["Name"].encode("utf-8")
        set_name(addr, name)
        setEOLComment(addr, name)
        monitor.incrementProgress(1)
    print("Metadata done")

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
    scriptMetadataMethods = data["ScriptMetadataMethod"]
    monitor.initialize(len(scriptMetadataMethods))
    monitor.setMessage("Labeling %d metadata methods" % len(scriptMetadataMethods))
    print("Processing %d metadata methods..." % len(scriptMetadataMethods))
    for scriptMetadataMethod in scriptMetadataMethods:
        addr = get_addr(scriptMetadataMethod["Address"])
        name = scriptMetadataMethod["Name"].encode("utf-8")
        methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
        set_name(addr, name)
        setEOLComment(addr, name)
        monitor.incrementProgress(1)
    print("Metadata methods done")

if "Addresses" in data and "Addresses" in processFields:
    addresses = data["Addresses"]
    monitor.initialize(len(addresses))
    monitor.setMessage("Creating %d functions" % len(addresses))
    print("Creating %d functions..." % len(addresses))
    for index in range(len(addresses) - 1):
        start = get_addr(addresses[index])
        make_function(start)
        monitor.incrementProgress(1)
    print("Functions done")

print("IL2CPP label import complete!")
