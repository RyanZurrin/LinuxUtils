# ==========================
# LinuxUtils.psm1
# A PowerShell module to emulate common GNU/Linux utilities in Windows
# Author: Ryan + ChatGPT
# ==========================\

# --------------------------
# Helper: Measure-LinuxUtil
# --------------------------
function Get-DiskHealth {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    # -------------------- Flag parsing --------------------
    $DriveLetters = @()
    $DebugMode = $false
    $ShowHelp = $false
    $ListOnly = $false

    foreach ($arg in $Args) {
        switch -regex ($arg) {
            '^--help$'   { $ShowHelp = $true; continue }
            '^--debug$'  { $DebugMode = $true; continue }
            '^--list$'   { $ListOnly = $true; continue }
            '^[A-Za-z]$' { $DriveLetters += $arg; continue }
            default      { $DriveLetters += $arg }
        }
    }

    if ($ShowHelp) {
@"
Usage: Get-DiskHealth [DriveLetter(s)] [--list] [--debug] [--help]

Description:
    Displays detailed health and SMART diagnostic information for one or more drives.
    Automatically correlates logical volumes, partitions, and physical disks.

Examples:
    Get-DiskHealth
        Show info for all mounted volumes.

    Get-DiskHealth C,D
        Show detailed health for drives C and D.

    Get-DiskHealth G --debug
        Include extra internal debug traces for troubleshooting.

    Get-DiskHealth --list
        Show a concise table of all detected drives and volumes.

Options:
    --list     Show all currently detected volumes and their key properties.
    --debug    Print detailed internal operations and variable traces.
    --help     Show this help message.

Outputs:
    Displays:
        • Health status (Healthy, Warning, Unhealthy)
        • Operational status (OK, Full Repair Needed, etc.)
        • File system type and free/used space
        • Disk model, bus, firmware version
        • SMART metrics (if available)
        • Recommendations for repair or replacement

Notes:
    Some drives (especially USB and exFAT) may not expose SMART data.
    Run as Administrator for full access to SMART and hardware info.
"@ | Write-Host
        return
    }

    # -------------------- --list mode --------------------
    if ($ListOnly) {
        Write-Host "Detected Volumes and Drives" -ForegroundColor Cyan
        Write-Host "---------------------------"
        try {
            $vols = Get-Volume | Where-Object { $_.DriveLetter }
            $disks = Get-Disk
            $mapped = @()

            foreach ($v in $vols) {
                $disk = $null
                try {
                    $part = Get-Partition -DriveLetter $v.DriveLetter -ErrorAction SilentlyContinue
                    if ($part) {
                        $disk = $disks | Where-Object { $_.Number -eq $part.DiskNumber }
                    }
                } catch {}
                $mapped += [PSCustomObject]@{
                    Drive = "$($v.DriveLetter):"
                    Label = $v.FriendlyName
                    FileSystem = $v.FileSystemType
                    Health = $v.HealthStatus
                    Type = if ($disk) { $disk.BusType } else { "Unknown" }
                    SizeGB = [math]::Round($v.Size/1GB,1)
                    FreeGB = [math]::Round($v.SizeRemaining/1GB,1)
                }
            }

            $mapped | Format-Table Drive,Label,FileSystem,Type,Health,SizeGB,FreeGB
        } catch {
            Write-Host "Error retrieving volume information: $_" -ForegroundColor Red
        }
        return
    }

    # -------------------- Default behavior --------------------
    if (-not $DriveLetters -or $DriveLetters.Count -eq 0) {
        $DriveLetters = (Get-Volume | Where-Object DriveLetter | Select-Object -ExpandProperty DriveLetter)
    }

    function Write-DebugMsg($msg) {
        if ($DebugMode) { Write-Host "[DEBUG] $msg" -ForegroundColor DarkGray }
    }

    foreach ($dl in $DriveLetters) {
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host " Drive ${dl}:" -ForegroundColor Cyan
        Write-Host "===============================" -ForegroundColor Cyan

        try {
            $vol = Get-Volume -DriveLetter $dl -ErrorAction Stop
            $part = Get-Partition -DriveLetter $dl -ErrorAction SilentlyContinue
            $disk = if ($part) { Get-Disk -Number $part.DiskNumber -ErrorAction SilentlyContinue }
            $phys = if ($disk) { Get-PhysicalDisk | Where-Object { $_.FriendlyName -eq $disk.FriendlyName } }

            Write-DebugMsg "Volume: $($vol.FriendlyName) | FileSystem=$($vol.FileSystemType) | Size=$([math]::Round($vol.Size/1GB,1)) GB"
            Write-DebugMsg "Partition=$($part.PartitionNumber) Disk=$($disk.Number) Physical=$($phys.FriendlyName)"

            Write-Host "Health Status     : $($vol.HealthStatus)"
            Write-Host "Operational Status: $($vol.OperationalStatus)"
            Write-Host "File System       : $($vol.FileSystemType)"
            Write-Host "Size / Free       : $([math]::Round($vol.Size/1GB,1)) GB / $([math]::Round($vol.SizeRemaining/1GB,1)) GB"
            Write-Host "Drive Type        : $($vol.DriveType)"
            Write-Host ""

            if ($disk) {
                Write-Host "Disk Model        : $($disk.FriendlyName)"
                Write-Host "Media Type        : $($disk.MediaType)"
                Write-Host "Bus Type          : $($disk.BusType)"
                Write-Host "Health Status     : $($disk.HealthStatus)"
                Write-Host "Operational Status: $($disk.OperationalStatus)"
                Write-Host "Firmware Version  : $($disk.FirmwareVersion)"
                Write-Host ""
            }

            try {
                $smart = Get-StorageReliabilityCounter -PhysicalDisk $phys -ErrorAction Stop
                Write-Host "SMART Data:"
                Write-Host ("  Power-On Hours   : {0}" -f $smart.PowerOnHours)
                Write-Host ("  Temperature (°C) : {0}" -f $smart.Temperature)
                Write-Host ("  Wear Percentage  : {0}" -f $smart.Wear)
                Write-Host ("  Read Errors      : {0}" -f $smart.ReadErrorsTotal)
                Write-Host ("  Write Errors     : {0}" -f $smart.WriteErrorsTotal)
                Write-Host ("  Realloc Sectors  : {0}" -f $smart.ReallocatedSectors)
            } catch {
                Write-Host "SMART Data         : Not available (not all drives expose it)" -ForegroundColor DarkGray
            }

            Write-Host ""
            if ($vol.HealthStatus -ne "Healthy" -or ($disk -and $disk.HealthStatus -ne "Healthy")) {
                Write-Host "?  Recommendation:" -ForegroundColor Yellow
                if ($vol.OperationalStatus -match "Repair") {
                    Write-Host "   Run 'chkdsk ${dl}: /f' and back up your data." -ForegroundColor Yellow
                } elseif ($disk -and $disk.HealthStatus -eq "Warning") {
                    Write-Host "   Check SMART data and consider replacing the drive." -ForegroundColor Yellow
                } else {
                    Write-Host "   Inspect event logs or use vendor diagnostic tools." -ForegroundColor Yellow
                }
                Write-Host ""
            }
        } catch {
            Write-Host "Error retrieving info for ${dl}: $_" -ForegroundColor Red
        }
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
        Human        = $false     # --si  (base 1000)
        Human1024    = $false     # -h    (base 1024)
        ShowType     = $false
        ShowTotal    = $false
        LocalOnly    = $false
        TypeFilter   = @()
        ExcludeType  = @()
        Strict       = $false
        Debug        = $false
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
            '^--debug$'                    { $opts.Debug  = $true }
            '^--help$' {
@"
Usage: df [OPTION]... [FILE]...
Display file system disk space usage.

Options:
  -h, --human-readable  show sizes in powers of 1024 (e.g. 1.1G)
      --si              show sizes in powers of 1000 (e.g. 1.1G)
  -T, --print-type      show filesystem type
  -t, --type=TYPE       show only file systems of type TYPE
  -x, --exclude-type=T  exclude file systems of type TYPE
  -l, --local           limit listing to local file systems
      --total           show grand total
      --strict          include health/encryption info (slower)
      --debug           verbose internal info for troubleshooting
      --help            display this help and exit
      --version         output version information and exit

Note:
  PowerShell lowercases short flags, so '-H' can't be distinguished.
  Use '--si' to force base-1000 output (same as GNU df -H).
"@ | Write-Host
                return
            }
            '^--version$' {
                Write-Host "df (LinuxUtils) PowerShell version 3.2-debug"
                return
            }
        }
    }

    # ---------------- Base selection ----------------
    if ($opts.Human -and $opts.Human1024) { $opts.Human = $false }

    if ($opts.Human1024) {
        $base  = 1024
        $human = $true
        $modeDesc = "binary (1024)"
    }
    elseif ($opts.Human) {
        $base  = 1000
        $human = $true
        $modeDesc = "decimal (1000)"
    }
    else {
        $base  = 1024
        $human = $false
        $modeDesc = "raw bytes"
    }

    if ($opts.Debug) {
        Write-Host "[DEBUG] human=$human base=$base mode=$modeDesc" -ForegroundColor Yellow
    }

    # ---------------- Collect drives ----------------
    $drives = Get-PSDrive -PSProvider FileSystem |
              Where-Object { $_.Used -ne $null -and $_.Free -ne $null } |
              Sort-Object Name

    # ---------------- Core volume info ----------------
    $volInfo = @{}
    try {
        $cims = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
                Where-Object { $_.Size -ne $null }
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
        Write-Warning "Warning: Unable to query logical disks. Some drive info may be missing."
    }

    # ---------------- Strict mode extras ----------------
    if ($opts.Strict) {
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

            $volState = Get-Volume -ErrorAction SilentlyContinue |
                        Where-Object { $_.DriveLetter }
            foreach ($vs in $volState) {
                $key2 = ($vs.DriveLetter + ":").ToUpper()
                if ($volInfo.ContainsKey($key2)) {
                    $volInfo[$key2].Health = $vs.HealthStatus
                    if ($vs.BitLockerProtection -match 'On|Enabled|Encrypted') {
                        $volInfo[$key2].Encrypted = 'Yes'
                    } else {
                        $volInfo[$key2].Encrypted = 'No'
                    }
                }
            }
        } catch {
            Write-Warning "Strict mode: extended volume info not fully available."
        }
    }

    # ---------------- Human size formatter ----------------
    function Format-Size {
        param(
            [double]$bytes,
            [bool]$humanMode,
            [int]$unitBase,
            [bool]$dbg
        )

        if (-not $humanMode) {
            $rawOut = [string][math]::Round($bytes)
            if ($dbg) { Write-Host "[DEBUG] Format-Size raw $bytes -> $rawOut" -ForegroundColor DarkCyan }
            return $rawOut
        }

        $suffixes = @('B','K','M','G','T','P','E','Z','Y')
        $i = 0
        $scaled = $bytes
        while (($scaled -ge $unitBase) -and ($i -lt ($suffixes.Length - 1))) {
            $scaled = $scaled / $unitBase
            $i++
        }

        # string with 1 decimal
        $valStr = ("{0:N1}" -f $scaled)  # e.g. "932.1"
        # trim trailing .0 specifically
        if ($valStr -match '\.0$') {
            $valStr = $valStr -replace '\.0$', ''
        }

        $final = $valStr + $suffixes[$i]

        if ($dbg) {
            Write-Host "[DEBUG] Format-Size $bytes base=$unitBase -> $final (scaled=$scaled index=$i)" -ForegroundColor DarkCyan
        }

        return $final
    }

    # ---------------- Build rows ----------------
    $showHealth = $opts.Strict
    $rows = @()

    foreach ($d in $drives) {
        $key = ($d.Name + ":").ToUpper()
        $v = $volInfo[$key]

        if (-not $v) { continue }

        $sizeBytes = [double]$v.Capacity
        $freeBytes = [double]$v.FreeSpace
        $usedBytes = $sizeBytes - $freeBytes

        if ($opts.Debug) {
            Write-Host "[DEBUG] Drive $($d.Name): sizeBytes=$sizeBytes freeBytes=$freeBytes usedBytes=$usedBytes" -ForegroundColor Yellow
        }

        $sizeStr = Format-Size $sizeBytes $human $base $opts.Debug
        $usedStr = Format-Size $usedBytes $human $base $opts.Debug
        $freeStr = Format-Size $freeBytes $human $base $opts.Debug

        $pctVal = if ($sizeBytes -gt 0) { $usedBytes / $sizeBytes } else { 0 }
        $pctStr = ("{0:P0}" -f $pctVal).Trim()

        $typeOut   = if ($v.FileSystem) { $v.FileSystem } else { "Unknown" }
        $healthOut = if ($v.Health)     { $v.Health     } else { "N/A" }
        $encOut    = if ($v.Encrypted)  { $v.Encrypted  } else { "N/A" }

        $rows += [PSCustomObject]@{
            FS        = $d.Name
            Type      = $typeOut
            SizeStr   = $sizeStr
            UsedStr   = $usedStr
            FreeStr   = $freeStr
            PctStr    = $pctStr
            Mount     = $d.Root
            Health    = $healthOut
            Enc       = $encOut
            RawSize   = $sizeBytes
            RawUsed   = $usedBytes
            RawFree   = $freeBytes
        }
    }

    # ---------------- Totals row (if --total) ----------------
    if ($opts.ShowTotal) {
        $totalSize = ($rows | Measure-Object RawSize -Sum).Sum
        $totalUsed = ($rows | Measure-Object RawUsed -Sum).Sum
        $totalFree = ($rows | Measure-Object RawFree -Sum).Sum
        $totalPct  = if ($totalSize -gt 0) { $totalUsed / $totalSize } else { 0 }

        $rows += [PSCustomObject]@{
            FS        = 'total'
            Type      = '-'
            SizeStr   = Format-Size $totalSize $human $base $opts.Debug
            UsedStr   = Format-Size $totalUsed $human $base $opts.Debug
            FreeStr   = Format-Size $totalFree $human $base $opts.Debug
            PctStr    = ("{0:P0}" -f $totalPct).Trim()
            Mount     = ''
            Health    = if ($showHealth) { '-' } else { "N/A" }
            Enc       = if ($showHealth) { '-' } else { "N/A" }
        }
    }

    # ---------------- Column widths ----------------
    $fsWidth     = [Math]::Max(10, ($rows | ForEach-Object { $_.FS.Length }      | Measure-Object -Maximum).Maximum)
    $typeWidth   = if ($opts.ShowType) {
        [Math]::Max(4, ($rows | ForEach-Object { $_.Type.Length }    | Measure-Object -Maximum).Maximum)
    } else { 0 }
    $sizeWidth   = [Math]::Max(4, ($rows | ForEach-Object { $_.SizeStr.Length }  | Measure-Object -Maximum).Maximum)
    $usedWidth   = [Math]::Max(4, ($rows | ForEach-Object { $_.UsedStr.Length }  | Measure-Object -Maximum).Maximum)
    $freeWidth   = [Math]::Max(4, ($rows | ForEach-Object { $_.FreeStr.Length }  | Measure-Object -Maximum).Maximum)
    $pctWidth    = [Math]::Max(4, ($rows | ForEach-Object { $_.PctStr.Length }   | Measure-Object -Maximum).Maximum)
    $healthWidth = if ($showHealth) {
        [Math]::Max(6, ($rows | ForEach-Object { $_.Health.Length }  | Measure-Object -Maximum).Maximum)
    } else { 0 }
    $encWidth    = if ($showHealth) {
        [Math]::Max(3, ($rows | ForEach-Object { $_.Enc.Length }     | Measure-Object -Maximum).Maximum)
    } else { 0 }
    $mountWidth  = [Math]::Max(8, ($rows | ForEach-Object { $_.Mount.Length }    | Measure-Object -Maximum).Maximum)

    # ---------------- Header + row format ----------------
    if ($opts.ShowType -and $showHealth) {
        $fmtRow = "{0,-$fsWidth} {1,-$typeWidth} {2,$sizeWidth} {3,$usedWidth} {4,$freeWidth} {5,$pctWidth} {6,-$healthWidth} {7,-$encWidth}  {8,-$mountWidth}"
        Write-Host ($fmtRow -f "Filesystem","Type","Size","Used","Avail","Use%","Health","Enc","Mounted on") -ForegroundColor Cyan
    }
    elseif ($opts.ShowType) {
        $fmtRow = "{0,-$fsWidth} {1,-$typeWidth} {2,$sizeWidth} {3,$usedWidth} {4,$freeWidth} {5,$pctWidth}  {6,-$mountWidth}"
        Write-Host ($fmtRow -f "Filesystem","Type","Size","Used","Avail","Use%","Mounted on") -ForegroundColor Cyan
    }
    else {
        $fmtRow = "{0,-$fsWidth} {1,$sizeWidth} {2,$usedWidth} {3,$freeWidth} {4,$pctWidth}  {5,-$mountWidth}"
        Write-Host ($fmtRow -f "Filesystem","Size","Used","Avail","Use%","Mounted on") -ForegroundColor Cyan
    }

    # ---------------- Emit rows ----------------
    foreach ($r in $rows) {
        $pctNum = 0
        if ($r.PctStr -match '(\d+)%') { $pctNum = [int]$matches[1] }
        $color = if ($pctNum -ge 90) { 'Red' }
                 elseif ($pctNum -ge 70) { 'Yellow' }
                 else { 'Green' }

        if ($opts.ShowType -and $showHealth) {
            Write-Host ($fmtRow -f $r.FS,$r.Type,$r.SizeStr,$r.UsedStr,$r.FreeStr,$r.PctStr,$r.Health,$r.Enc,$r.Mount) -ForegroundColor $color
        }
        elseif ($opts.ShowType) {
            Write-Host ($fmtRow -f $r.FS,$r.Type,$r.SizeStr,$r.UsedStr,$r.FreeStr,$r.PctStr,$r.Mount) -ForegroundColor $color
        }
        else {
            Write-Host ($fmtRow -f $r.FS,$r.SizeStr,$r.UsedStr,$r.FreeStr,$r.PctStr,$r.Mount) -ForegroundColor $color
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