# win11_tamper_plant

Planter for the user-mode tamper technique graded in `documentation/VALIDATION.md`
section `MEM-W11-TAMPER`. **Synthetic**: the tamper is planted by `plant.ps1` in
processes it owns, on the Windows 11 25H2 corpus VM (`FORENSIC-W11`, build 26200,
user `analyst`). It grades whether the check can fire on the technique, never how
often a real attacker uses it.

Roles, one process each:

| Role | What it plants | Group graded |
|------|----------------|--------------|
| `etw` | `C3` (ret) over `ntdll!EtwEventWrite` | `etw_patch`, modal route |
| `etwxor` | `33 C0 C3` (xor eax,eax; ret) over the same | `etw_patch`, modal route |
| `debugreg` | `Dr0` = a function address, `Dr7` = 1 on a sleeping thread | `debug_registers` |
| `suspended` | a thread left suspended | `suspended_threads` |
| `etwall` | `C3` over `ntdll!EtwEventWrite` in **every** 64-bit process the account can open (`WriteProcessMemory`) | `etw_patch`, classification route (the mode is the patch), `VALIDATION.md` `MEM-W11-TAMPER-2` |

Each role writes its ground truth (pid, tid, address, original bytes) to the path
given by `-Out`, then sleeps so the state is live at capture time. The capture and
truth live in `~/forensic_corpora/win11_tamper_plant/` (not committed,
about 10 GiB).
