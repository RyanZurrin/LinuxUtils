## Purpose
This repository is a single PowerShell module (LinuxUtils) that implements a small collection of GNU/Linux-like utilities for Windows PowerShell (5.1). These instructions give an AI coding agent the minimal, concrete knowledge needed to be productive here.

## Big picture / architecture
- Root files:
  - `LinuxUtils.psm1` — the entire module implementation (all functions live here).
  - `LinuxUtils.psd1` — module manifest (version, metadata, and `FunctionsToExport`).
  - `LinuxUtils.psm1.bak.txt` — backup copy with historic notes.
- The module is intentionally small and single-file: functions are lightweight PowerShell functions that wrap common filesystem and text operations (wc, grep, df, touch, head, tail, rm, which, cd stack helpers, etc.).
- Data flow is simple: user input -> function (Get-Content / pipeline / ReadLine) -> formatted Write-Host/Output. There are no network calls or external services except for a couple of explicit integration points listed below.

## Key exported commands (manifest-driven)
Check `FunctionsToExport` in `LinuxUtils.psd1`. Important names:
- `wc`, `ls`, `touch`, `grep`, `head`, `tail`, `rm`, `which`, `df`, `tree`, `cd`, `go`, `dirs`

Note: `tree` is listed in the manifest but there's no `tree` function implemented in `LinuxUtils.psm1` — treat that as an existing mismatch to resolve if implementing new features.

## Project-specific patterns & conventions
- Single-file implementation: add new utilities to `LinuxUtils.psm1` and then add the symbol to `FunctionsToExport` in `LinuxUtils.psd1`.
- Global state: the module uses a global variable `$global:DirStack` to implement directory stack helpers (`cd`, `go`, `dirs`). Modifying or removing this global will change behavior across multiple functions.
- Output style: user-facing outputs are implemented with `Write-Host` (colored, formatted) and errors use `Write-Error` — functions typically don't throw exceptions.
- Parameter style: functions use `param()`; some use `[CmdletBinding()]` and Parameter attributes, but not consistently. Keep PowerShell 5.1 compatibility in mind (avoid PowerShell Core-only APIs unless guarded).
- Input handling: functions read from pipeline/input (`Get-Content`, `[Console]::In.ReadLine()`, `$input`) rather than structured objects; many functions accept file path arguments directly.

## Integration points & environment assumptions
- `ls` is a thin shim that forwards to an external tool: `lsd --long @Args $Path`. The `lsd` binary (Rust ls replacement) is an external dependency — it may be available on the developer machine or configured as an alias. If `lsd` is not present, `ls` will fail.
- `df` uses WMI/CIM (`Get-CimInstance Win32_LogicalDisk`) and `Get-PSDrive` — this code expects to run on Windows where these providers exist.
- Module manifest targets PowerShell 5.1 (see `PowerShellVersion` in `LinuxUtils.psd1`). Be cautious when running under PowerShell Core; test behavior there.

## Developer workflows (important commands)
- Import the module for development (from the module folder):
```powershell
Remove-Module LinuxUtils -ErrorAction SilentlyContinue; Import-Module -Force .\LinuxUtils.psm1
```
- If the module is installed in a PowerShell `Modules` path, import by name:
```powershell
Remove-Module LinuxUtils -ErrorAction SilentlyContinue; Import-Module -Force LinuxUtils
```
- Quick manual smoke tests (examples):
```powershell
# wc from stdin
"one two three" | wc

# grep file
grep 'pattern' .\README.md

# df view (windows)
df --human-readable

# cd stack
cd ..; cd C:\; dirs; go 2
```
- Static analysis: use PSScriptAnalyzer to lint the module (recommended):
```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path .\LinuxUtils.psm1
```
- Tests: there are no tests in the repo. If adding tests, use Pester (place tests under a `tests` folder). Example quick-start:
```powershell
Install-Module -Name Pester -Scope CurrentUser -Force
# create tests\LinuxUtils.Tests.ps1 and run
Invoke-Pester -Script .\tests\LinuxUtils.Tests.ps1
```

## Editing guidance / common PR touchpoints
- When adding or renaming a function, keep `LinuxUtils.psd1` in sync (FunctionsToExport).
- Avoid breaking the global `cd` alias behavior unless intentional: `cd` replaces the built-in alias and updates `$global:DirStack`.
- Prefer reloading the module after changes (see import command above). Many functions read files and the console directly — unit tests should validate typical CLI flows.

## Known gaps & safe assumptions for an AI agent
- Missing `tree` implementation in `LinuxUtils.psm1` while exported in the manifest — either implement `tree` or remove it from `FunctionsToExport`.
- `ls` depends on `lsd`; if not present, add a fallback or detect and warn.
- No CI, tests, or linter config present — assume manual, local testing.

## Example code pointers (where to look in the code)
- `cd`, `go`, `dirs` — directory stack logic and use of `$global:DirStack` (lines near the bottom of `LinuxUtils.psm1`).
- `df` — formatting, WMI usage, and human-readable size logic (search for `Get-CimInstance Win32_LogicalDisk`).
- `wc`, `grep` — text-processing idioms using `Get-Content`, `-split`, and `$input`.

If anything in this file is unclear or you'd like me to add more examples (small unit tests, a `tree` implementation, or a fallback for `ls`), tell me which area to expand and I will iterate.
