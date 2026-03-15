using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

public static unsafe class NativeSceneSkipPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_EventSkipLock(nint instance, byte b, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsEventSkipEnable(nint instance, nint methodInfo);

    private static NativeHook<d_EventSkipLock> _lockHook;
    private static NativeHook<d_IsEventSkipEnable> _enableHook;
    private static d_EventSkipLock _pLock;
    private static d_IsEventSkipEnable _pEnable;

    public static void Apply()
    {
        var t = typeof(Il2Cpp.MB_EventGuide);

        try
        {
            var f = t.GetField("NativeMethodInfoPtr_EventSkipLock_Public_Void_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (f != null)
            {
                var mi = (nint)f.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pLock = (nint inst, byte b, nint meth) =>
                    {
                        if (Core.ForceSceneSkip.Value) return; // skip the lock
                        try { _lockHook.Trampoline(inst, b, meth); } catch { }
                    };
                    _lockHook = new NativeHook<d_EventSkipLock>(native, Marshal.GetFunctionPointerForDelegate(_pLock));
                    _lockHook.Attach();
                    Melon<Core>.Logger.Msg($"SceneSkip: EventSkipLock hook @ 0x{native:X}");
                }
            }
        }
        catch (System.Exception ex) { Melon<Core>.Logger.Warning($"SceneSkip Lock: {ex.Message}"); }

        try
        {
            var f = t.GetField("NativeMethodInfoPtr_IsEventSkipEnable_Public_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (f != null)
            {
                var mi = (nint)f.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pEnable = (nint inst, nint meth) =>
                    {
                        if (Core.ForceSceneSkip.Value) return 1;
                        try { return _enableHook.Trampoline(inst, meth); } catch { return 1; }
                    };
                    _enableHook = new NativeHook<d_IsEventSkipEnable>(native, Marshal.GetFunctionPointerForDelegate(_pEnable));
                    _enableHook.Attach();
                    Melon<Core>.Logger.Msg($"SceneSkip: IsEventSkipEnable hook @ 0x{native:X}");
                }
            }
        }
        catch (System.Exception ex) { Melon<Core>.Logger.Warning($"SceneSkip Enable: {ex.Message}"); }
    }
}
