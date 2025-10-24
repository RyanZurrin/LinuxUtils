function df {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    # Parse flags
    $opts = @{
        Human        = $false
        Human1024    = $false
        ShowType     = $false
        ShowTotal    = $false
        LocalOnly    = $false
        TypeFilter   = @()
        ExcludeType  = @()
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
                Write-Host "df (LinuxUtils) PowerShell version 2.4"
                return
            }
        }
    }

    # Handle -h (1024) vs -H (1000)
    if ($opts.Human -and $opts.Human1024) { $opts.Human = $false }
    if ($opts.Human1024) {
        $base  = 1024
        $human = $true
    }
    elseif ($opts.Human) {
        $base  = 1000
        $human = $true
    }
    else {
        $base  = 1024
        $human = $false
    }

    # Collect drive list
    $drives = Get-PSDrive -PSProvider FileSystem | Sort-Object Name

    # Filter out phantom drives before CIM queries (prevents WMI hang)
    $drives = $drives | Where-Object { $_.Used -ne $null -and $_.Free -ne $null }

    # Collect filesystem info (safe mode)
    $volInfo = @{}
    try {
        $cims = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.Size -ne $null }
        foreach ($v in $cims) {
            $volInfo[$v.DeviceID] = [PSCustomObject]@{
                FileSystem = $v.FileSystem
                DriveType  = $v.DriveType
            }
        }
    } catch {
        Write-Warning "Warning: Unable to query all logical disks. Skipping some drives."
    }

    # Formatter
    function Format-Size {
        param([double]$bytes, [bool]$human, [int]$base)
        if (-not $human) {
            return ("{0,14:0}" -f [math]::Round($bytes))
        }
        $suffixes = "B","K","M","G","T","P"
        $i = 0
        while ($bytes -ge $base -and $i -lt $suffixes.Length - 1) {
            $bytes /= $base
            $i++
        }
        return ("{0,8:0.1}{1}" -f $bytes, $suffixes[$i])
    }

    # Header setup
    $rows = @()
    foreach ($d in $drives) {
        $v = $volInfo["$($d.Name):"]
        $fsType = if ($v) { $v.FileSystem } else { "N/A" }
        $rows += [PSCustomObject]@{
            Filesystem = $d.Name
            Type       = $fsType
            Mount      = $d.Root
        }
    }

    $fsWidth   = [Math]::Max(12, ($rows | ForEach-Object { $_.Filesystem.Length } | Measure-Object -Maximum).Maximum)
    $typeWidth = if ($opts.ShowType) { [Math]::Max(8, ($rows | ForEach-Object { $_.Type.Length } | Measure-Object -Maximum).Maximum) } else { 0 }
    $mountWidth = [Math]::Max(10, ($rows | ForEach-Object { $_.Mount.Length } | Measure-Object -Maximum).Maximum)

    if ($opts.ShowType) {
        $fmt = "{0,-$fsWidth} {1,-$typeWidth} {2,14} {3,14} {4,14} {5,6}  {6,-$mountWidth}"
        Write-Host ($fmt -f "Filesystem","Type","Size","Used","Avail","Use%","Mounted on") -ForegroundColor Cyan
    } else {
        $fmt = "{0,-$fsWidth} {1,14} {2,14} {3,14} {4,6}  {5,-$mountWidth}"
        Write-Host ($fmt -f "Filesystem","Size","Used","Avail","Use%","Mounted on") -ForegroundColor Cyan
    }

    [double]$tSize = 0; [double]$tUsed = 0; [double]$tFree = 0

    foreach ($d in $drives) {
        try {
            # Skip inaccessible or zero-sized drives
            if (-not $d.Free -and -not $d.Used) { continue }

            $v = $volInfo["$($d.Name):"]
            $fsType = if ($v) { $v.FileSystem } else { "N/A" }

            $size = [double]($d.Used + $d.Free)
            if ($size -eq 0) { continue }

            $used = [double]$d.Used
            $free = [double]$d.Free
            $pctVal = if ($size -gt 0) { $used / $size } else { 0 }
            $pct = ("{0,5:P0}" -f $pctVal)

            $sizeStr = Format-Size $size $human $base
            $usedStr = Format-Size $used $human $base
            $freeStr = Format-Size $free $human $base
            $color = if ($pctVal -ge 0.9) { 'Red' } elseif ($pctVal -ge 0.7) { 'Yellow' } else { 'Green' }

            if ($opts.ShowType) {
                Write-Host ($fmt -f $d.Name, $fsType, $sizeStr, $usedStr, $freeStr, $pct, $d.Root) -ForegroundColor $color
            } else {
                Write-Host ($fmt -f $d.Name, $sizeStr, $usedStr, $freeStr, $pct, $d.Root) -ForegroundColor $color
            }

            $tSize += $size; $tUsed += $used; $tFree += $free
        }
        catch {
            Write-Host ($fmt -f $d.Name,"N/A","N/A","N/A","N/A","N/A",$d.Root) -ForegroundColor DarkGray
        }
    }

    if ($opts.ShowTotal) {
        $pctVal = if ($tSize -gt 0) { $tUsed / $tSize } else { 0 }
        $pct = ("{0,5:P0}" -f $pctVal)
        $sizeStr = Format-Size $tSize $human $base
        $usedStr = Format-Size $tUsed $human $base
        $freeStr = Format-Size $tFree $human $base
        $color = if ($pctVal -ge 0.9) { 'Red' } elseif ($pctVal -ge 0.7) { 'Yellow' } else { 'Green' }

        if ($opts.ShowType) {
            Write-Host ($fmt -f "total","-",$sizeStr,$usedStr,$freeStr,$pct,"") -ForegroundColor $color
        } else {
            Write-Host ($fmt -f "total",$sizeStr,$usedStr,$freeStr,$pct,"") -ForegroundColor $color
        }
    }
}
