from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB # type: ignore

import argparse
from .common import reserve_empty_region

handler_addr = 0x00103e58  # DAT_00103e58
trampoline_addr = 0x00103d98          # Where to insert a hook
trampoline_return = 0x00103da0        # Where to return after your code

return_asm = f"""
    b #{trampoline_return}   ; go back to original flow
"""

def patch(*, code_bin: str, patch_offset: int, fake_struct_addr: int):
    trampoline_asm = f"""
        b #{patch_offset}        ; jump to patch code
    """

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

    # Initialize Keystone for ARM Thumb
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    encoding, _ = ks.asm(asm) # type: ignore
    patch_bytes = bytes(encoding) # type: ignore

    return_bytes, _ = ks.asm(return_asm, patch_offset + len(patch_bytes) | 1) # type: ignore

    trampoline_bytes, _ = ks.asm(trampoline_asm, trampoline_addr | 1)  # type: ignore # | 1 = Thumb mode
    trampoline_bytes = bytes(trampoline_bytes)  # type: ignore

    # Inject into code.bin
    with open(code_bin, "r+b") as f:
        f.seek(patch_offset)
        f.write(patch_bytes)
        # Inject trampoline
        f.seek(trampoline_addr)
        f.write(trampoline_bytes)
    print(f"Patched {len(patch_bytes)} bytes at offset {hex(patch_offset)}")


def main():
    parser = argparse.ArgumentParser(description="Patch always_hasten_world")
    parser.add_argument("--code", type=str, required=True, help="Path to code.bin")
    parser.add_argument("--regions", type=str, default="data/empty_regions.json",
                    required=False,
                    help="Path to empty memory regions JSON file. Defaults to 'data/empty_regions.json'")
    parser.add_argument("--disable-region-reserve", action="store_true", 
                    help="Disable region reservation (will not edit the regions file.")

    opts = parser.parse_args()
    code_bin = opts.code
    regions = opts.regions
    disable_region_reserve = opts.disable_region_reserve

    patch_offset = reserve_empty_region(regions=regions, used_by="always_hasten_world_patch",
                                        disable_region_reserve=disable_region_reserve)
    fake_struct_addr = reserve_empty_region(regions=regions, used_by="always_hasten_world_patch_fake_struct", 
                                            disable_region_reserve=disable_region_reserve)

    # Patch target offset in code.bin (adjust for your actual location)
    patch(code_bin=code_bin, patch_offset=patch_offset, fake_struct_addr=fake_struct_addr,)


if __name__ == "__main__":
    main()