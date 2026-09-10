using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Input;

namespace WardogsTacticalRadio.Input;

// Push-to-talk needs both a key-down and a key-up while the app may not have focus (it's meant
// to run alongside a game). Win32's RegisterHotKey only reports "pressed", not release, so a
// low-level keyboard hook is used instead - the same mechanism Discord/TeamSpeak/Mumble use for
// PTT. This also sidesteps a WPF quirk where F10 arrives via KeyEventArgs.SystemKey rather than
// .Key (a holdover from F10 historically activating the menu bar), since here we read the raw
// virtual-key code directly instead of going through WPF's routed key events at all.
public sealed class GlobalPttHotkeys : IDisposable
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const int WM_KEYUP = 0x0101;
    private const int WM_SYSKEYDOWN = 0x0104;
    private const int WM_SYSKEYUP = 0x0105;

    private delegate nint LowLevelKeyboardProc(int nCode, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT
    {
        public int vkCode;
        public int scanCode;
        public int flags;
        public int time;
        public nint dwExtraInfo;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, nint hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(nint hhk);

    [DllImport("user32.dll")]
    private static extern nint CallNextHookEx(nint hhk, int nCode, nint wParam, nint lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern nint GetModuleHandle(string? lpModuleName);

    // Kept as a field: if this delegate is only referenced locally, the GC can collect it
    // while native code still holds the function pointer, crashing the process.
    private readonly LowLevelKeyboardProc _proc;
    private readonly HashSet<Key> _watchedKeys;
    private readonly HashSet<Key> _keysDown = new();
    private nint _hookHandle;

    public event Action<Key>? KeyDown;
    public event Action<Key>? KeyUp;

    public GlobalPttHotkeys(IEnumerable<Key> watchedKeys)
    {
        _watchedKeys = new HashSet<Key>(watchedKeys);
        _proc = HookCallback;
    }

    public void Start()
    {
        if (_hookHandle != 0) return;
        using var currentProcess = Process.GetCurrentProcess();
        using var currentModule = currentProcess.MainModule;
        var moduleHandle = currentModule is null ? 0 : GetModuleHandle(currentModule.ModuleName);
        _hookHandle = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, moduleHandle, 0);
        if (_hookHandle == 0)
            throw new InvalidOperationException($"Failed to install global PTT hotkey hook (Win32 error {Marshal.GetLastWin32Error()}).");
    }

    private nint HookCallback(int nCode, nint wParam, nint lParam)
    {
        if (nCode >= 0)
        {
            var message = wParam.ToInt32();
            var data = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
            var key = KeyInterop.KeyFromVirtualKey(data.vkCode);

            if (_watchedKeys.Contains(key))
            {
                if (message is WM_KEYDOWN or WM_SYSKEYDOWN)
                {
                    if (_keysDown.Add(key)) KeyDown?.Invoke(key);
                }
                else if (message is WM_KEYUP or WM_SYSKEYUP)
                {
                    if (_keysDown.Remove(key)) KeyUp?.Invoke(key);
                }
            }
        }

        // Always pass the keystroke along so other apps/games with the same binding
        // still see it; this hook only observes, it never swallows input.
        return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
    }

    public void Dispose()
    {
        if (_hookHandle != 0)
        {
            UnhookWindowsHookEx(_hookHandle);
            _hookHandle = 0;
        }
    }
}
