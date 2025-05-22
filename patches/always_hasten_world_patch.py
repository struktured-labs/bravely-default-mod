from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

# Patch target offset in code.bin (adjust for your actual location)
patch_offset = 0x00103d98
fake_struct_addr = 0x0065A000
handler_addr = 0x00103e58

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

encoding, _ = ks.asm(asm)
patch_bytes = bytes(encoding)

# Inject into code.bin
with open("code.bin", "r+b") as f:
    f.seek(patch_offset)
    f.write(patch_bytes)

print(f"Patched {len(patch_bytes)} bytes at offset {hex(patch_offset)}")

