# ==========================
# LinuxUtils.psm1
# A PowerShell module to emulate common GNU/Linux utilities in Windows
# Author: Ryan + ChatGPT
# ==========================\

# --------------------------
# Helper: Measure-LinuxUtil
# --------------------------
function Measure-LinuxUtil {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ScriptBlock]$Script,
        [string]$Label = "Execution"
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Script
    }
    finally {
        $sw.Stop()
        $elapsed = "{0:N2}" -f $sw.Elapsed.TotalSeconds
        Write-Host "$Label completed in $elapsed seconds" -ForegroundColor Cyan
    }
}

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

    # ---------------- Flag parsing ----------------
    $opts = @{
        Human        = $false
        Human1024    = $false
        ShowType     = $false
        ShowTotal    = $false
        LocalOnly    = $false
        TypeFilter   = @()
        ExcludeType  = @()
        Strict       = $false
    }

    foreach ($arg in $Args) {
        switch -regex ($arg) {
            '^--si$'                       { $opts.Human = $true }
            '^(-h|--human-readable)$'      { $opts.Human1024 = $true }
            '^(-T|--print-type)$'          { $opts.ShowType  = $true }
            '^--total$'                    { $opts.ShowTotal = $true }
            '^(-l|--local)$'               { $opts.LocalOnly = $true }
            '^(--type|-t)=(.+)$'           { $opts.TypeFilter  += $matches[2].Split(',') }
            '^(--exclude-type|-x)=(.+)$'   { $opts.ExcludeType += $matches[2].Split(',') }
            '^--strict$'                   { $opts.Strict = $true }
            '^--help$' {
@"
Usage: df [OPTION]... [FILE]...
Display file system disk space usage.

Options:
  --si                 use powers of 1000 (e.g., 1.1G)
  -h, --human-readable use powers of 1024 (e.g., 1.1Gi)
  -T, --print-type     show filesystem type
  -t, --type=TYPE      show only file systems of type TYPE
  -x, --exclude-type=T exclude file systems of type TYPE
  -l, --local          limit listing to local file systems
      --total          show grand total
      --strict         use high-precision volume data (slower)
      --help           display this help and exit
      --version        output version information and exit

Note:
    PowerShell automatically converts all flags to lowercase, so '-H' cannot be used.
    Use '--si' instead to select base-1000 human-readable units.
    
"@ | Write-Host
                return
            }
            '^--version$' {
                Write-Host "df (LinuxUtils) PowerShell version 2.8"
                return
            }
        }
    }

    # ---------------- Base selection ----------------
    if ($opts.Human -and $opts.Human1024) { $opts.Human = $false }

    if ($opts.Human1024) { $base = 1024; $human = $true }
    elseif ($opts.Human) { $base = 1000; $human = $true }
    else { $base = 1024; $human = $false }

    # ---------------- Drive collection ----------------
    $drives = Get-PSDrive -PSProvider FileSystem |
              Where-Object { $_.Used -ne $null -and $_.Free -ne $null } |
              Sort-Object Name

    # ---------------- Filesystem info ----------------
    $volInfo = @{}
    try {
        $cims = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.Size -ne $null }
        foreach ($v in $cims) {
            $volInfo[$v.DeviceID.ToUpper()] = [PSCustomObject]@{
                FileSystem = $v.FileSystem
                DriveType  = $v.DriveType
                Capacity   = $v.Size
                FreeSpace  = $v.FreeSpace
                Encrypted  = $null
                Health     = $null
            }
        }
    } catch {
        Write-Warning "Warning: Unable to query logical disks. Some drive types may be missing."
    }

    # ---------------- Strict mode ----------------
    if ($opts.Strict) {
        Write-Host "Strict mode: Gathering detailed volume info..." -ForegroundColor Yellow
        try {
            $vols = Get-CimInstance Win32_Volume -ErrorAction Stop |
                    Where-Object { $_.DriveLetter -ne $null -and $_.Capacity -ne $null }
            foreach ($v in $vols) {
                $key = $v.DriveLetter.ToUpper()
                $volInfo[$key] = [PSCustomObject]@{
                    FileSystem = $v.FileSystem
                    DriveType  = "Volume"
                    Capacity   = $v.Capacity
                    FreeSpace  = $v.FreeSpace
                    Encrypted  = $null
                    Health     = $null
                }
            }

            # BitLocker + Health
            $volState = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter }
            foreach ($v in $volState) {
                $key = ($v.DriveLetter + ":").ToUpper()
                if ($volInfo.ContainsKey($key)) {
                    $volInfo[$key].Health = $v.HealthStatus
                    if ($v.BitLockerProtection -match 'On|Enabled|Encrypted') {
                        $volInfo[$key].Encrypted = 'Yes'
                    } else {
                        $volInfo[$key].Encrypted = 'No'
                    }
                }
            }

            Write-Host "Strict mode applied successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Strict mode failed or incomplete. Falling back to standard info."
        }
    }

    # ---------------- Size formatter ----------------
    function Format-Size {
        param([double]$bytes, [bool]$human, [int]$base)
        if (-not $human) { return ("{0,14:0}" -f [math]::Round($bytes)) }
        if ($base -eq 1024) { $suffixes = "B","Ki","Mi","Gi","Ti","Pi" }
        else { $suffixes = "B","K","M","G","T","P" }
        $i = 0
        while ($bytes -ge $base -and $i -lt $suffixes.Length - 1) { $bytes /= $base; $i++ }
        return ("{0,8:0.1}{1}" -f $bytes, $suffixes[$i])
    }

    # ---------------- Header setup ----------------
    $showHealth = $opts.Strict
    $rows = @()
    foreach ($d in $drives) {
        $v = $volInfo["$($d.Name.ToUpper()):"]
        $fsType = if ($v) { $v.FileSystem } else { "Unknown" }
        $rows += [PSCustomObject]@{
            Filesystem = $d.Name
            Type       = $fsType
            Mount      = $d.Root
        }
    }

    $fsWidth   = [Math]::Max(12, ($rows | ForEach-Object { $_.Filesystem.Length } | Measure-Object -Maximum).Maximum)
    $typeWidth = if ($opts.ShowType) { [Math]::Max(8, ($rows | ForEach-Object { $_.Type.Length } | Measure-Object -Maximum).Maximum) } else { 0 }
    $mountWidth = [Math]::Max(10, ($rows | ForEach-Object { $_.Mount.Length } | Measure-Object -Maximum).Maximum)

    if ($opts.ShowType -and $showHealth) {
        $fmt = "{0,-$fsWidth} {1,-$typeWidth} {2,14} {3,14} {4,14} {5,6} {6,10} {7,8}  {8,-$mountWidth}"
        Write-Host ($fmt -f "Filesystem","Type","Size","Used","Avail","Use%","Health","Encrypted","Mounted on") -ForegroundColor Cyan
    } elseif ($opts.ShowType) {
        $fmt = "{0,-$fsWidth} {1,-$typeWidth} {2,14} {3,14} {4,14} {5,6}  {6,-$mountWidth}"
        Write-Host ($fmt -f "Filesystem","Type","Size","Used","Avail","Use%","Mounted on") -ForegroundColor Cyan
    } else {
        $fmt = "{0,-$fsWidth} {1,14} {2,14} {3,14} {4,6}  {5,-$mountWidth}"
        Write-Host ($fmt -f "Filesystem","Size","Used","Avail","Use%","Mounted on") -ForegroundColor Cyan
    }

    # ---------------- Main loop ----------------
    [double]$tSize = 0; [double]$tUsed = 0; [double]$tFree = 0
    foreach ($d in $drives) {
        try {
            $v = $volInfo["$($d.Name.ToUpper()):"]
            if (-not $v) { continue }

            $size = [double]$v.Capacity
            $free = [double]$v.FreeSpace
            $used = $size - $free
            if ($size -eq 0) { continue }

            $pctVal = if ($size -gt 0) { $used / $size } else { 0 }
            $pct = ("{0,5:P0}" -f $pctVal)
            $sizeStr = Format-Size $size $human $base
            $usedStr = Format-Size $used $human $base
            $freeStr = Format-Size $free $human $base
            $color = if ($pctVal -ge 0.9) { 'Red' } elseif ($pctVal -ge 0.7) { 'Yellow' } else { 'Green' }

            $healthVal = if ($null -ne $v.Health) { $v.Health } else { "N/A" }
            $encVal = if ($null -ne $v.Encrypted) { $v.Encrypted } else { "N/A" }

            if ($opts.ShowType -and $showHealth) {
                Write-Host ($fmt -f $d.Name, $v.FileSystem, $sizeStr, $usedStr, $freeStr, $pct, $healthVal, $encVal, $d.Root) -ForegroundColor $color
            } elseif ($opts.ShowType) {
                Write-Host ($fmt -f $d.Name, $v.FileSystem, $sizeStr, $usedStr, $freeStr, $pct, $d.Root) -ForegroundColor $color
            } else {
                Write-Host ($fmt -f $d.Name, $sizeStr, $usedStr, $freeStr, $pct, $d.Root) -ForegroundColor $color
            }

            $tSize += $size; $tUsed += $used; $tFree += $free
        } catch {
            Write-Host ($fmt -f $d.Name,"N/A","N/A","N/A","N/A","N/A",$d.Root) -ForegroundColor DarkGray
        }
    }

    # ---------------- Totals ----------------
    if ($opts.ShowTotal) {
        $pctVal = if ($tSize -gt 0) { $tUsed / $tSize } else { 0 }
        $pct = ("{0,5:P0}" -f $pctVal)
        $sizeStr = Format-Size $tSize $human $base
        $usedStr = Format-Size $tUsed $human $base
        $freeStr = Format-Size $tFree $human $base
        $color = if ($pctVal -ge 0.9) { 'Red' } elseif ($pctVal -ge 0.7) { 'Yellow' } else { 'Green' }

        if ($opts.ShowType -and $showHealth) {
            Write-Host ($fmt -f "total","-",$sizeStr,$usedStr,$freeStr,$pct,"-","-","") -ForegroundColor $color
        } elseif ($opts.ShowType) {
            Write-Host ($fmt -f "total","-",$sizeStr,$usedStr,$freeStr,$pct,"") -ForegroundColor $color
        } else {
            Write-Host ($fmt -f "total",$sizeStr,$usedStr,$freeStr,$pct,"") -ForegroundColor $color
        }
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
        Write-Error ("Index out of range 1-{0}" -f $global:DirStack.Count)
        return
    }

    # Bash-style: 1 = last directory
    $Target = $global:DirStack[-$Index]
    $current = (Get-Location).Path

    # Move to target directory
    Set-Location $Target

    # Push current location onto stack before removing target
    $global:DirStack += $current

    # Remove the target directory from the stackyt-dlp 
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

# --------------------------
# tree
# --------------------------
function tree {
    [CmdletBinding()]
    param(
        [string]$Path = ".",
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

        $showHelp = $false; $treePath = $null

    # -------- argument parsing --------
    $allArgs = @(); if ($Path -and $Path -ne '.') { $allArgs += $Path }; if ($Args) { $allArgs += $Args }
    for ($i = 0; $i -lt $allArgs.Count; $i++) {
        $arg = $allArgs[$i]
        switch ($arg) {
            '-d' { $dirOnly = $true; continue }
            '-s' { $showSize = $true; continue }
            '-n' { $noColor = $true; continue }
            '--ascii' { $useAscii = $true; continue }
            '-L' {
                if ($i + 1 -lt $allArgs.Count -and $allArgs[$i + 1] -match '^\d+$') {
                    $maxDepth = [int]$allArgs[$i + 1]; $i++
                }
                continue
            }
            '--help' { $showHelp = $true; continue }
        }
        if (-not $treePath) { $treePath = $arg }
    }

    if ($showHelp) {
@"
Usage: tree [options] [path]
Options:
  -L level     Descend only level directories deep
  -d           List directories only
  -s           Show file size
  -n           Turn colorization off
  --ascii      Use ASCII tree characters
  --help       Print this help message
"@; return }

    if (-not $treePath -or $treePath -match '^-') { $treePath = "." }

    # -------- Unicode/ASCII detection --------
    if (-not $useAscii) {
        $enc = [Console]::OutputEncoding
        if ($enc.WebName -notin @('utf-8','utf-16','unicode','unicodeFFFE') -or -not $env:WT_SESSION) {
            $useAscii = $true
        }
    }

    $script:dirCount = 0; $script:fileCount = 0

    function Get-FormattedSize {
        param([long]$bytes)
        if ($bytes -lt 1KB) { return "$bytes`tB" }
        elseif ($bytes -lt 1MB) { return "$([math]::Round($bytes/1KB,1))K" }
        elseif ($bytes -lt 1GB) { return "$([math]::Round($bytes/1MB,1))M" }
        else { return "$([math]::Round($bytes/1GB,1))G" }
    }

    function Write-TreeItem {
        param(
            [string]$name,[string]$prefix,[bool]$isLast,[bool]$isDir,[long]$size=0
        )
        $tee = if ($useAscii) { if ($isLast) { '+-- ' } else { '|-- ' } }
               else { if ($isLast) { '??? ' } else { '??? ' } }
        $displayName = $name
        if ($showSize -and -not $isDir) {
            $sizeStr = Get-FormattedSize $size
            $displayName = "{0}`t[{1}]" -f $name, $sizeStr
        }
        if (-not $noColor) {
            if ($isDir) { Write-Host -NoNewline ($prefix + $tee); Write-Host $displayName -ForegroundColor Blue }
            else { Write-Host ($prefix + $tee + $displayName) }
        } else {
            Write-Host ($prefix + $tee + $displayName)
        }
    }

    function Show-Tree {
        param([string]$dir,[string]$prefix="",[int]$depth=0)
        if ($depth -ge $maxDepth) { return }

        $items = @()
        try {
            # Filter directories only if -d is active
            if ($dirOnly) {
                $items = Get-ChildItem -Directory -Path $dir -ErrorAction SilentlyContinue | Sort-Object Name
            } else {
                $items = Get-ChildItem -Path $dir -ErrorAction SilentlyContinue | Sort-Object Name
            }
        } catch {}

        if (-not $items -or $items.Count -eq 0) { return }

        $itemCount = $items.Count; $i = 0
        foreach ($item in $items) {
            $i++; $isLast = ($i -eq $itemCount)

            # Prefix generation
            if ($useAscii) {
                if ($isLast) { $newPrefix = "$prefix    " }
                else         { $newPrefix = "$prefix|   " }
            } else {
                if ($isLast) { $newPrefix = "$prefix    " }
                else         { $newPrefix = "$prefix?   " }
            }

            if ($item.PSIsContainer) {
                $script:dirCount++
                Write-TreeItem -name $item.Name -prefix $prefix -isLast $isLast -isDir $true
                Show-Tree -dir $item.FullName -prefix $newPrefix -depth ($depth + 1)
            } elseif (-not $dirOnly) {
                $script:fileCount++
                Write-TreeItem -name $item.Name -prefix $prefix -isLast $isLast -isDir $false -size $item.Length
            }
        }
    }

    $root = Resolve-Path $treePath -ErrorAction SilentlyContinue
    if (-not $root) { Write-Error "tree: cannot access '$treePath': No such file or directory"; return }

    Write-Host $root.Path
    Show-Tree -dir $root.Path

    $summary = @()
    $summary += "$script:dirCount director$(if ($script:dirCount -ne 1){'ies'}else{'y'})"
    if (-not $dirOnly) { $summary += "$script:fileCount file$(if ($script:fileCount -ne 1){'s'}else{''})" }
    Write-Host "`n$($summary -join ', ')"
}

# End of LinuxUtils.psm1