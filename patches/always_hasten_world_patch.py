from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB # type: ignore

import json
import argparse

parser = argparse.ArgumentParser(description="Patch always_hasten_world")
parser.add_argument("--code", type=str, required=True, help="Path to code.bin")
parser.add_argument("--regions", type=str, default="../data/empty_regions.json", 
                    required=False, help="Path to code.bin")
parser.add_argument("--disable-region-reserve", action="store_true", help="Disable region reserve")

code_bin = (opts :=parser.parse_args()).code
regions = opts.regions
disable_region_reserve = opts.disable_region_reserve

def reserve_empty_region(*, used_by:str|None=None, len:int|None=None) -> int|None:
    empty_regions = json.load(open(regions))
    for i, region in enumerate(empty_regions):
        if (region_used_by := region.get('used_by')):
            if used_by and used_by == region_used_by:
                return int(f"0x{region['addr']}")
            print(f"Empty region {i} at {region['addr']} is used by {region_used_by}.")
            continue
        elif (region_len := region.get("len", 0)) >= len:
            print(f"Empty region {i} at {region['addr']} with length {region_len} is not used by anything")
            if used_by:
                region['used_by'] = used_by
                if not disable_region_reserve:
                    with open(regions, "w") as f:
                        json.dump(empty_regions, f, indent=4)
            return int(f"0x{region['addr']}")
        else:
            print(f"Empty region {i} at {region['addr']} with length {region_len} is not long enough (at least {len} bytes)")

    raise ValueError("No empty region found in file ../data/empty_regions.json")

# Patch target offset in code.bin (adjust for your actual location)
patch_offset = reserve_empty_region(used_by="always_hasten_world_patch")
if patch_offset is None:
    raise ValueError("No empty region found in file ../data/empty_regions.json")
fake_struct_addr = reserve_empty_region(used_by="always_hasten_world_patch_fake_struct")
if fake_struct_addr is None:
    raise ValueError("No empty region found in file ../data/empty_regions.json")

handler_addr = 0x00103e58  # DAT_00103e58
trampoline_addr = 0x00103d98          # Where to insert a hook
trampoline_return = 0x00103da0        # Where to return after your code


trampoline_asm = f"""
    b #{patch_offset}        ; jump to patch code
"""
trampoline_bytes, _ = ks.asm(trampoline_asm, trampoline_addr | 1)  # type: ignore # | 1 = Thumb mode

# Suggested from chatgpt, here as a reference 
_="""
    LDR     R0, =0x0065A000        ; address of your static fake struct
    LDR     R1, =DAT_00103e58      ; function pointer / effect handler
    STR     R1, [R0]               ; fake->handler_or_vtable = handler
    MOV     R1, #1
    STRB    R1, [R0, #4]           ; fake->flag = 1
    LDR     R2, [SP, #0x18]        ; local_18
    STR     R2, [R0, #8]           ; fake->context = local_18
    STR     R0, [SP, #0x20]        ; inject into local_20
"""

# Initialize Keystone for ARM Thumb
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

asm = f"""
    ldr r0, ={fake_struct_addr}
    ldr r1, ={handler_addr}
    str r1, [r0]
    mov r1, #1
    strb r1, [r0, #4]
    ldr r2, [sp, #0x18]
    str r2, [r0, #8]
    str r0, [sp, #0x20]
"""

encoding, _ = ks.asm(asm) # type: ignore
patch_bytes = bytes(encoding) # type: ignore

return_asm = f"""
    b #{trampoline_return}   ; go back to original flow
"""
return_bytes, _ = ks.asm(return_asm, patch_offset + len(patch_bytes) | 1) # type: ignore
trampoline_bytes = bytes(return_bytes) # type: ignore
# Inject into code.bin
with open(code_bin, "r+b") as f:
    f.seek(patch_offset)
    f.write(patch_bytes)
    # Inject trampoline
    f.seek(trampoline_addr)
    f.write(trampoline_bytes)
print(f"Patched {len(patch_bytes)} bytes at offset {hex(patch_offset)}")

