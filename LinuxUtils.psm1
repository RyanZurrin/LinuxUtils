# ==========================
# LinuxUtils.psm1
# A PowerShell module to emulate common GNU/Linux utilities in Windows
# Author: Ryan + ChatGPT
# ==========================

# --------------------------
# wc
# --------------------------
function wc {
    param ([string[]]$args)

    if ($args -contains '-h' -or $args -contains '--help') {
@"
Usage: wc [OPTION]... [FILE]...
Print newline, word, and byte counts for each FILE, and a total line if
more than one FILE is specified. With no FILE, or when FILE is -, read
standard input.

Options:
  -c            print the byte counts
  -m            print the character counts
  -l            print the newline counts
  -w            print the word counts
  -h, --help    display this help and exit
"@
        return
    }

    $showLines = $false
    $showWords = $false
    $showChars = $false
    $showBytes = $false
    $files = @()

    foreach ($arg in $args) {
        switch ($arg) {
            '-l' { $showLines = $true }
            '-w' { $showWords = $true }
            '-m' { $showChars = $true }
            '-c' { $showBytes = $true }
            default { $files += $arg }
        }
    }

    if (-not ($showLines -or $showWords -or $showChars -or $showBytes)) {
        $showLines = $true
        $showWords = $true
        $showBytes = $true
    }

    function Process-Text($text, $path) {
        $lineCount = ($text | Measure-Object -Line).Lines
        $wordCount = ($text -split '\s+' | Where-Object { $_ -ne '' }).Count
        $charCount = ($text | Out-String).Length
        $byteCount = [System.Text.Encoding]::UTF8.GetByteCount(($text | Out-String))

        $cols = @()
        if ($showLines) { $cols += $lineCount }
        if ($showWords) { $cols += $wordCount }
        if ($showChars) { $cols += $charCount }
        if ($showBytes) { $cols += $byteCount }
        if ($path)      { $cols += $path }

        ($cols | ForEach-Object { "{0,8}" -f $_ }) -join " "
    }

    $results = @()
    $totals = @{ Lines = 0; Words = 0; Chars = 0; Bytes = 0 }

    if ($files.Count -gt 0) {
        foreach ($file in $files) {
            if (Test-Path $file) {
                $text = Get-Content $file
                $results += Process-Text $text $file

                if ($showLines) { $totals.Lines += ($text | Measure-Object -Line).Lines }
                if ($showWords) { $totals.Words += (($text -split '\s+' | Where-Object { $_ -ne '' }).Count) }
                if ($showChars) { $totals.Chars += (($text | Out-String).Length) }
                if ($showBytes) { $totals.Bytes += ([System.Text.Encoding]::UTF8.GetByteCount(($text | Out-String))) }
            } else {
                Write-Error ("wc: {0}: No such file" -f $file)
            }
        }

        $results
        if ($files.Count -gt 1) {
            $cols = @()
            if ($showLines) { $cols += $totals.Lines }
            if ($showWords) { $cols += $totals.Words }
            if ($showChars) { $cols += $totals.Chars }
            if ($showBytes) { $cols += $totals.Bytes }
            $cols += "total"
            ($cols | ForEach-Object { "{0,8}" -f $_ }) -join " "
        }
    } else {
        $text = @()
        if ($input) { $text = $input }
        Process-Text $text $null
    }
}

# --------------------------
# ls (uses lsd if present, else falls back)
# --------------------------
function ls {
    param(
        [string]$Path = ".",
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    if (Get-Command lsd -ErrorAction SilentlyContinue) {
        lsd --long @Args $Path
    } else {
        Get-ChildItem @Args $Path
    }
}

# --------------------------
# touch
# --------------------------
function touch {
    param([string[]]$Files)
    foreach ($file in $Files) {
        if (Test-Path $file) {
            (Get-Item $file).LastWriteTime = Get-Date
        } else {
            New-Item -ItemType File -Path $file | Out-Null
        }
    }
}

# --------------------------
# grep (simple)
# --------------------------
function grep {
    param(
        [string]$Pattern,
        [string[]]$Files,
        [switch]$i,
        [switch]$v,
        [int]$A = 0,
        [int]$B = 0,
        [int]$C = 0
    )

    $contextBefore = if ($C -gt 0) { $C } else { $B }
    $contextAfter  = if ($C -gt 0) { $C } else { $A }

    function Match-Line($lines, $index) {
        $start = [Math]::Max(0, $index - $contextBefore)
        $end   = [Math]::Min($lines.Count - 1, $index + $contextAfter)
        for ($j = $start; $j -le $end; $j++) {
            if ($j -eq $index) { Write-Output $lines[$j] }
            else { Write-Output ("-" + $lines[$j]) }
        }
    }

    function Process-Lines($lines) {
        for ($k = 0; $k -lt $lines.Count; $k++) {
            $match = if ($i) { $lines[$k] -imatch $Pattern } else { $lines[$k] -match $Pattern }
            if ($v) { $match = -not $match }
            if ($match) { Match-Line $lines $k }
        }
    }

    if ($Files) {
        foreach ($file in $Files) {
            if (-not (Test-Path $file)) { Write-Error "grep: ${file}: No such file"; continue }
            $lines = Get-Content $file
            Process-Lines $lines
        }
    } else {
        $lines = @()
        while ($line = [Console]::In.ReadLine()) { $lines += $line }
        Process-Lines $lines
    }
}

# --------------------------
# head
# --------------------------
function head {
    param([string]$File, [int]$n = 10)
    if (-not (Test-Path $File)) { Write-Error "head: cannot open '$File'"; return }
    Get-Content $File | Select-Object -First $n
}

# --------------------------
# tail
# --------------------------
function tail {
    param([string]$File, [int]$n = 10)
    if (-not (Test-Path $File)) { Write-Error "tail: cannot open '$File'"; return }
    Get-Content $File -Tail $n
}

# --------------------------
# rm
# --------------------------
function rm {
    param([string[]]$Files, [switch]$r, [switch]$f)
    foreach ($file in $Files) {
        if (-not (Test-Path $file)) {
            if (-not $f) { Write-Error "rm: cannot remove '$file': No such file" }
            continue
        }
        Remove-Item $file -Recurse:$r -Force:$f
    }
}

# --------------------------
# which
# --------------------------
function which {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Command
    )

    $cmd = Get-Command $Command -ErrorAction SilentlyContinue
    if (-not $cmd) { Write-Error "which: '$Command' not found"; return }

    switch ($cmd.CommandType) {
        'Alias'          { Write-Output "$($cmd.Name): alias for '$($cmd.Definition)'" }
        'Function'       {
            $file = if ($cmd.ScriptBlock -and $cmd.ScriptBlock.File) { $cmd.ScriptBlock.File } else { 'profile or current session' }
            Write-Output "$($cmd.Name): function defined in $file"
        }
        'Cmdlet'         { if ($cmd.Source) { Write-Output "$($cmd.Name): cmdlet from module '$($cmd.Source)'" } else { Write-Output "$($cmd.Name): built-in cmdlet" } }
        'ExternalScript' { Write-Output "$($cmd.Name): script at $($cmd.Source)" }
        'Application'    { Write-Output "$($cmd.Name): executable at $($cmd.Source)" }
        default          { Write-Output "$($cmd.Name): $($cmd.CommandType) - $($cmd.Source)" }
    }
}

# --------------------------
# df  (Phase 2A)
# --------------------------
function df {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    # Parse flags
    $opts = @{
        Human        = $false  # -H / --si (base 1000)
        Human1024    = $false  # -h / --human-readable (base 1024)
        ShowType     = $false  # -T / --print-type
        ShowTotal    = $false  # --total
        LocalOnly    = $false  # -l / --local
        TypeFilter   = @()     # -t=NTFS,FAT32
        ExcludeType  = @()     # -x=FAT32
    }

    foreach ($arg in $Args) {
        switch -regex ($arg) {
            '^(-H|--si)$'                 { $opts.Human     = $true }
            '^(-h|--human-readable)$'     { $opts.Human1024 = $true }
            '^(-T|--print-type)$'         { $opts.ShowType  = $true }
            '^--total$'                   { $opts.ShowTotal = $true }
            '^(-l|--local)$'              { $opts.LocalOnly = $true }
            '^(--type|-t)=(.+)$'          { $opts.TypeFilter  += $matches[2].Split(',') }
            '^(--exclude-type|-x)=(.+)$'  { $opts.ExcludeType += $matches[2].Split(',') }
'^--help$' {
@"
Usage: df [OPTION]... [FILE]...
Display file system disk space usage.

Options:
  -H, --si              use powers of 1000 (e.g., 1.1G)
  -h, --human-readable  use powers of 1024 (e.g., 1.1Gi)
  -T, --print-type      show filesystem type
  -t, --type=TYPE       show only file systems of type TYPE
  -x, --exclude-type=T  exclude file systems of type TYPE
  -l, --local           limit listing to local file systems
      --total           show grand total
      --help            display this help and exit
      --version         output version information and exit
"@ | Write-Host
    return
}
'^--version$' {
    Write-Host "df (LinuxUtils) PowerShell version 2.0 — Phase 2A"
    return
}
        }  # end switch
    }      # end foreach

    # Collect drive + filesystem info
    $drives = Get-PSDrive -PSProvider FileSystem | Sort-Object Name
    $volInfo = @{}
    foreach ($v in (Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue)) {
        $volInfo[$v.DeviceID] = [PSCustomObject]@{
            FileSystem = $v.FileSystem
            DriveType  = $v.DriveType
        }
    }

    $base  = if ($opts.Human) { 1000 } else { 1024 }
    $human = $opts.Human -or $opts.Human1024

    # Size formatting (no thousands separators; PS5-safe)
    function Format-Size {
        param([double]$bytes, [bool]$human, [int]$base)

        if (-not $human) {
            $txt = "{0:0}" -f [math]::Round($bytes)
            return $txt.PadLeft(14)
        }

        if ($bytes -lt $base) {
            $val = "{0:0}"   -f [double]$bytes;      return ($val + 'B').PadLeft(8)
        } elseif ($bytes -lt [math]::Pow($base,2)) {
            $val = "{0:0.0}" -f ([double]$bytes / $base);             return ($val + 'K').PadLeft(8)
        } elseif ($bytes -lt [math]::Pow($base,3)) {
            $val = "{0:0.0}" -f ([double]$bytes / [math]::Pow($base,2)); return ($val + 'M').PadLeft(8)
        } elseif ($bytes -lt [math]::Pow($base,4)) {
            $val = "{0:0.0}" -f ([double]$bytes / [math]::Pow($base,3)); return ($val + 'G').PadLeft(8)
        } else {
            $val = "{0:0.0}" -f ([double]$bytes / [math]::Pow($base,4)); return ($val + 'T').PadLeft(8)
        }
    }

    # Filtering
    $drives = $drives | Where-Object {
        $v = $volInfo[$_.Name.TrimEnd(':')]
        if (-not $v) { return $true }

        $include = $true
        if ($opts.LocalOnly -and $v.DriveType -ne 3) { $include = $false }
        if ($opts.TypeFilter.Count   -gt 0 -and ($opts.TypeFilter  -notcontains $v.FileSystem)) { $include = $false }
        if ($opts.ExcludeType.Count  -gt 0 -and ($opts.ExcludeType -contains    $v.FileSystem)) { $include = $false }
        return $include
    }

    # Header
    if ($opts.ShowType) {
        Write-Host ("Filesystem".PadRight(12) + "Type".PadRight(8) + "Size".PadLeft(14) + "Used".PadLeft(14) + "Avail".PadLeft(14) + "Use%".PadLeft(6) + "  Mounted on") -ForegroundColor Cyan
    } else {
        Write-Host ("Filesystem".PadRight(12) + "Size".PadLeft(14) + "Used".PadLeft(14) + "Avail".PadLeft(14) + "Use%".PadLeft(6) + "  Mounted on") -ForegroundColor Cyan
    }

    [double]$tSize = 0; [double]$tUsed = 0; [double]$tFree = 0
    $consoleWidth = $Host.UI.RawUI.WindowSize.Width
    if (-not $consoleWidth -or $consoleWidth -lt 60) { $consoleWidth = 120 }

    # Rows
    foreach ($d in $drives) {
        try {
            $v = $volInfo[$d.Name.TrimEnd(':')]
            $fsType = if ($v) { $v.FileSystem } else { "N/A" }

            $size = [double]($d.Used + $d.Free)
            $used = [double]$d.Used
            $free = [double]$d.Free
            $pctVal = if ($size -gt 0) { $used / $size } else { 0 }

            $pct = ("{0:0}%" -f ([math]::Round($pctVal * 100, 0))).PadLeft(6)
            $sizeStr = Format-Size $size $human $base
            $usedStr = Format-Size $used $human $base
            $freeStr = Format-Size $free $human $base

            $color = if ($pctVal -ge 0.9) { 'Red' } elseif ($pctVal -ge 0.7) { 'Yellow' } else { 'Green' }

            $mount = $d.Root
            $maxMountWidth = [Math]::Max(5, $consoleWidth - 85)
            if ($mount.Length -gt $maxMountWidth) { $mount = $mount.Substring(0, $maxMountWidth - 3) + "..." }

            $line = if ($opts.ShowType) {
                $d.Name.PadRight(12) + $fsType.PadRight(8) + $sizeStr + $usedStr + $freeStr
            } else {
                $d.Name.PadRight(12) + $sizeStr + $usedStr + $freeStr
            }

            Write-Host -NoNewline $line
            Write-Host -NoNewline $pct -ForegroundColor $color
            Write-Host ("  " + $mount)

            $tSize += $size; $tUsed += $used; $tFree += $free
        }
        catch {
            Write-Host ($d.Name.PadRight(12) + "N/A".PadLeft(14) + "N/A".PadLeft(14) + "N/A".PadLeft(14) + "N/A".PadLeft(6) + "  " + $d.Root) -ForegroundColor DarkGray
        }
    }

    # Totals
    if ($opts.ShowTotal) {
        $pctVal = if ($tSize -gt 0) { $tUsed / $tSize } else { 0 }
        $pct = ("{0:0}%" -f ([math]::Round($pctVal * 100, 0))).PadLeft(6)
        $sizeStr = Format-Size $tSize $human $base
        $usedStr = Format-Size $tUsed $human $base
        $freeStr = Format-Size $tFree $human $base
        $color = if ($pctVal -ge 0.9) { 'Red' } elseif ($pctVal -ge 0.7) { 'Yellow' } else { 'Green' }

        $line = if ($opts.ShowType) {
            "total".PadRight(12) + "-".PadRight(8) + $sizeStr + $usedStr + $freeStr
        } else {
            "total".PadRight(12) + $sizeStr + $usedStr + $freeStr
        }

        Write-Host -NoNewline $line
        Write-Host -NoNewline $pct -ForegroundColor $color
        Write-Host ""
    }
}

# --------------------------
# Directory stack utilities
# --------------------------
if (-not (Test-Path Variable:\DirStack)) { $global:DirStack = @() }

if (Get-Alias cd -ErrorAction SilentlyContinue) { Remove-Item Alias:cd }

function cd {
    param([string]$Path)
    $current = (Get-Location).Path
    if (-not $Path) {
        Set-Location $HOME
    } elseif (Test-Path $Path) {
        $resolvedPath = (Resolve-Path $Path).Path
        if ($current -ne $resolvedPath) { $global:DirStack += $current }
        Set-Location $resolvedPath
    } else {
        Write-Error ("cd: {0}: No such file or directory" -f $Path)
    }
}

# Go back to a previous directory in the stack by index (Bash/Oh-My-Bash style)
function go {
    param([int]$Index = 1)

    if ($global:DirStack.Count -eq 0) {
        Write-Error "Directory stack is empty"
        return
    }

    if ($Index -lt 1 -or $Index -gt $global:DirStack.Count) {
        Write-Error ("Index out of range 1–{0}" -f $global:DirStack.Count)
        return
    }

    # Bash-style: 1 = last directory
    $Target = $global:DirStack[-$Index]
    $current = (Get-Location).Path

    # Move to target directory
    Set-Location $Target

    # Push current location onto stack before removing target
    $global:DirStack += $current

    # Remove the target directory from the stack
    $global:DirStack = $global:DirStack[0..($global:DirStack.Count - $Index - 1)]
}

# Show directory stack with Bash-style numbering
function dirs {
    if ($global:DirStack.Count -eq 0) {
        Write-Output "Directory stack is empty"
        return
    }

    for ($i = 0; $i -lt $global:DirStack.Count; $i++) {
        $idx = $global:DirStack.Count - $i
        Write-Output ("{0}: {1}" -f $idx, $global:DirStack[$i])
    }
}
# End of LinuxUtils.psm1
