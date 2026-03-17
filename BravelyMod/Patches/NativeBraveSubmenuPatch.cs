using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Allows Brave from submenus (spell/ability/item lists).
/// Hooks BtlTopMenuLayout.Update — when in Phase 3 (SubMenuPhase),
/// also calls MainWndProc._updateShortcutKeys() so the Brave button
/// is checked even while a submenu is open.
///
/// Phase machine: 1=MainPhase (brave works), 3=SubMenuPhase (brave blocked by default)
/// m_Phase is a static field on BtlTopMenuLayout_TypeInfo+0xB8 offset +0x28
/// m_mainWndProc is at BtlTopMenuLayout+0x20
/// </summary>
public static unsafe class NativeBraveSubmenuPatch
{
    // void Update(this BtlTopMenuLayout, float time, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_Update(nint instance, float time, nint methodInfo);

    // void _updateShortcutKeys(this MainWndProc, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_UpdateShortcutKeys(nint instance, nint methodInfo);

    private static NativeHook<d_Update> _updateHook;
    private static d_Update _pinnedUpdate;

    private static nint _shortcutKeysPtr;
    private static nint _shortcutKeysMethodInfo;

    public static void Apply()
    {
        try
        {
            // Hook BtlTopMenuLayout.Update
            var field = typeof(Il2Cpp.BtlTopMenuLayout).GetField(
                "NativeMethodInfoPtr_Update_Public_Virtual_Void_Single_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning("BraveSubmenu: Update field not found"); return; }

            var mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;

            _pinnedUpdate = Update_Hook;
            _updateHook = new NativeHook<d_Update>(native, Marshal.GetFunctionPointerForDelegate(_pinnedUpdate));
            _updateHook.Attach();
            Melon<Core>.Logger.Msg($"BraveSubmenu: Update hook @ 0x{native:X}");

            // Resolve _updateShortcutKeys on MainWndProc
            // MainWndProc is a nested class — try BtlTopMenuLayout+MainWndProc
            var wndType = typeof(Il2Cpp.BtlTopMenuLayout).GetNestedType("MainWndProc");
            if (wndType == null)
            {
                // Try finding it as a separate type
                wndType = System.Type.GetType("Il2Cpp.BtlTopMenuLayout.MainWndProc, Assembly-CSharp");
            }

            if (wndType != null)
            {
                var skField = wndType.GetField(
                    "NativeMethodInfoPtr__updateShortcutKeys_Public_Void_0",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
                if (skField != null)
                {
                    var skMi = (nint)skField.GetValue(null);
                    if (skMi != 0)
                    {
                        _shortcutKeysPtr = *(nint*)skMi;
                        _shortcutKeysMethodInfo = skMi;
                        Melon<Core>.Logger.Msg($"BraveSubmenu: _updateShortcutKeys @ 0x{_shortcutKeysPtr:X}");
                    }
                }
                else
                {
                    Melon<Core>.Logger.Warning("BraveSubmenu: _updateShortcutKeys field not found");
                }
            }
            else
            {
                Melon<Core>.Logger.Warning("BraveSubmenu: MainWndProc type not found");
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"BraveSubmenu: {ex.Message}");
        }
    }

    private static void Update_Hook(nint instance, float time, nint methodInfo)
    {
        try
        {
            // Call original Update
            _updateHook.Trampoline(instance, time, methodInfo);

            if (_shortcutKeysPtr == 0) return;

            // Check if we're in Phase 3 (SubMenuPhase)
            // m_Phase is at static fields: BtlTopMenuLayout_TypeInfo -> +0xB8 -> +0x28
            // Simpler: read from instance. Phase might be at a field offset.
            // From dump: m_Phase is a static int. Let's try reading it from TypeInfo.
            // Actually, easier: just read the MainWndProc and call _updateShortcutKeys
            // every frame during submenu. The function itself checks if Brave button is pressed.

            // Read m_Phase — it's a static field on BtlTopMenuLayout
            // Access via TypeInfo: BtlTopMenuLayout_TypeInfo+0xB8 -> +0x28
            // But we don't have TypeInfo easily. Instead, check if SubWndProc is active.
            // SubWndProc is at instance+0x28 — if non-null and the submenu is open, we're in Phase 3
            nint subWndProc = *(nint*)(instance + 0x28);
            if (subWndProc == 0) return; // not in submenu

            // Get MainWndProc at instance+0x20
            nint mainWndProc = *(nint*)(instance + 0x20);
            if (mainWndProc == 0) return;

            // Check if Brave button is pressed (Pad.BR = 0x100 or Pad.BL = 0x200)
            // Read from PadSampler — but simpler: just call _updateShortcutKeys
            // and then force the phase back to SubMenuPhase (3)

            // Read phase before
            // m_Phase is static — try reading from the TypeInfo static fields
            var typeInfo = typeof(Il2Cpp.BtlTopMenuLayout).TypeHandle.Value;
            // Can't easily get static fields this way in IL2CPP...

            // Alternative: just call _updateShortcutKeys and accept the phase change,
            // then write phase back to 3
            // Phase is stored at BtlTopMenuLayout static offset +0x28 in the static field area

            // Read m_Phase (static field at TypeInfo+0xB8 -> +0x28)
            nint typeInfoPtr = *(nint*)(*(nint*)instance); // instance->klass
            nint staticFields = *(nint*)(typeInfoPtr + 0xB8);
            if (staticFields == 0) return;
            int phaseBefore = *(int*)(staticFields + 0x28);

            // Only act during SubMenuPhase (3)
            if (phaseBefore != 3) return;

            // Call _updateShortcutKeys — may call _pushCmdBrave and change phase
            var fn = Marshal.GetDelegateForFunctionPointer<d_UpdateShortcutKeys>(_shortcutKeysPtr);
            fn(mainWndProc, _shortcutKeysMethodInfo);

            // Restore phase to 3 (SubMenuPhase) so submenu stays open
            int phaseAfter = *(int*)(staticFields + 0x28);
            if (phaseAfter != phaseBefore)
            {
                *(int*)(staticFields + 0x28) = 3; // force back to submenu
            }
        }
        catch { }
    }
}
