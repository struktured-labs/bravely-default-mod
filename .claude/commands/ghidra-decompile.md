Decompile a function from the BDFFHD binary using Ghidra MCP.

Usage: /ghidra-decompile <function_name or address>

Steps:
1. If given a name, use `mcp__ghidra__ghidra_find_functions` to search for it in project "bdffhd"
2. If given an address (starts with 0x), decompile directly
3. Use `mcp__ghidra__ghidra_decompile` to get the decompiled output
4. Present the decompiled C code with notes on what the function does
5. If relevant, show cross-references using `mcp__ghidra__ghidra_get_xrefs`

$ARGUMENTS
