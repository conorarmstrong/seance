# Launcher search rules for a bare program name

Which extensions each Windows launcher tries when an autostart entry names a bare program
(`h249svcexe`, not `C:\Windows\System32\h249svcexe.exe`). Established by running the launchers,
not from documentation: Microsoft documents only `CreateProcess` (`.exe` appended) and says a
service `ImagePath` must be fully qualified.

These files are **evidence of a live test**, not test fixtures: no unit test reads them. The
unit tests in `src/tests.rs` pin the rules the code applies; this directory is what those
rules rest on.

## The machine

* Windows 11 Enterprise evaluation, 25H2, build **26200.6584**, x64 — the `win11-lab` corpus
  VM (`~/win11-lab/vm/seance-w11.qcow2`), booted under KVM from a copy-on-write overlay so the
  corpus disk was not changed. One machine, one build; no other Windows version was tested.
* Run 2026-09-27, 22:20–22:34 guest local time, as the local administrator `analyst`.
* `PATHEXT` on the machine was the Windows default:
  `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL`.

## Method

`setup.ps1` turns on process-creation auditing with command lines (Security event 4688) and
plants, in `C:\Windows\System32`, one set of files per launcher and variant: `h249<src><v>`
with `<v>` naming which extensions exist (`com`, `exe`, `bat`, `cmd`, `all` = all four).
`.com`/`.exe`/`.pif` copies are `whoami.exe`; `.bat`/`.cmd` append their own path to
`C:\h249\hits.txt`; `.vbs`/`.js`/`.ps1` do the same through their hosts.
`phase1.ps1` (services, scheduled tasks, IFEO debugger), `phase2.ps1` (Run, RunOnce, HKCU Run,
Winlogon Userinit, Startup-folder shortcuts, App Paths, script extensions) and `phase3.ps1`
(precedence pairs, `.pif`, `.lnk`) set the entries; phases 2 and 3 were followed by a reboot
and logon. `ev.ps1` prints every 4688 event naming `h249` and the hits file. The transcripts
are `phase*-events.txt`; `phase2-winlogon-4006.txt` holds Winlogon's "failed to spawn" events.

Results printed by the phase scripts, not otherwise in the transcripts:

    SVC com  StartService FAILED 2: The system cannot find the file specified.
    SVC exe  StartService FAILED 1053 (the process started; whoami is not a service)
    SVC bat  StartService FAILED 2
    SVC cmd  StartService FAILED 2
    SVC all  StartService FAILED 1053 (h249svcall.exe started)
    SVC vbs  StartService FAILED 2
    TSK com/exe/bat/cmd/all/vbs/js/exebat/batcmd/exevbs  LastTaskResult=0x00000000
    TSK ps1/pif/lnk/none/apx (App Paths only)            LastTaskResult=0x80070002
    DBG com/bat/cmd  CreateProcess: The system cannot find the file specified
    DBG exe/all      CreateProcess ok; h249dbg<v>.exe started with the target as argument

## What was observed

| Launcher (entry) | Ran | Did not run | Precedence seen |
|---|---|---|---|
| Service control manager (`ImagePath`, own-process service) | `.exe` | `.com` `.bat` `.cmd` `.vbs` | — |
| IFEO `Debugger` (target started by `CreateProcess`) | `.exe` | `.com` `.bat` `.cmd` | — |
| Winlogon `Userinit` list element | `.exe` | `.com` `.bat` `.cmd` `.vbs` `.js` `.ps1` (event 4006) | — |
| Explorer, HKLM `Run` | `.com` `.exe` `.bat` `.cmd` `.pif`, App Paths | `.vbs` `.js` `.lnk` | `.com` > `.exe` > `.bat` > `.cmd` |
| Explorer, HKCU `Run` | `.com` `.exe` `.bat` `.cmd` | `.vbs` `.js` | `.com` first |
| `runonce.exe`, HKLM `RunOnce` | `.com` `.exe` `.bat` `.cmd` | `.vbs` `.js` | `.com` first |
| Task Scheduler `Exec` action | `.com` `.exe` `.bat` `.cmd` `.vbs` `.js` | `.ps1` `.pif` `.lnk`, App Paths | `.com` > `.exe` > `.bat` > `.cmd`; `.exe` > `.vbs` |

Not tested: `.pif`'s place in the Run order, `.pif` for RunOnce, HKCU `RunOnce`, the
`Wow6432Node`, `Policies\Explorer\Run`, `RunOnceEx` and `RunServices` keys, Winlogon `Shell`,
a debugger started through `ShellExecute`, `.vbe`/`.jse`/`.wsf`/`.wsh`/`.msc`/`.cpl` for tasks
individually, a task's `WorkingDirectory`, and a Startup-folder shortcut whose target is bare —
the shell API resolved every bare target to a full path when the shortcut was saved, so such a
shortcut has to be crafted and was not.
