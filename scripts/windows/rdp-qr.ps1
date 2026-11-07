<#
.SYNOPSIS
Minimal QR code encoder: byte mode, error correction level L, versions 1-20.

.DESCRIPTION
New-QrMatrix builds the module matrix per ISO/IEC 18004, Write-QrCode prints it to the
console, and Get-QrConsoleSize returns the console size that needs. enable-rdp.ps1 dot-sources this file from its own folder to show the Mac connection
command as a QR code. Dot-sourcing defines only functions and constants.
#>

# Level L block structure per version 1-20 (ISO/IEC 18004 Table 9): EC codewords per block,
# group 1 blocks, data codewords per group 1 block, group 2 blocks, data codewords per group 2 block.
$QrBlocksL = @(
    @(7, 1, 19, 0, 0),
    @(10, 1, 34, 0, 0),
    @(15, 1, 55, 0, 0),
    @(20, 1, 80, 0, 0),
    @(26, 1, 108, 0, 0),
    @(18, 2, 68, 0, 0),
    @(20, 2, 78, 0, 0),
    @(24, 2, 97, 0, 0),
    @(30, 2, 116, 0, 0),
    @(18, 2, 68, 2, 69),
    @(20, 4, 81, 0, 0),
    @(24, 2, 92, 2, 93),
    @(26, 4, 107, 0, 0),
    @(30, 3, 115, 1, 116),
    @(22, 5, 87, 1, 88),
    @(24, 5, 98, 1, 99),
    @(28, 1, 107, 5, 108),
    @(30, 5, 120, 1, 121),
    @(28, 3, 113, 4, 114),
    @(28, 3, 107, 5, 108)
)

# Alignment pattern center coordinates per version 1-20 (ISO/IEC 18004 Annex E).
$QrAlignmentPositions = @(
    @(),
    @(6, 18),
    @(6, 22),
    @(6, 26),
    @(6, 30),
    @(6, 34),
    @(6, 22, 38),
    @(6, 24, 42),
    @(6, 26, 46),
    @(6, 28, 50),
    @(6, 30, 54),
    @(6, 32, 58),
    @(6, 34, 62),
    @(6, 26, 46, 66),
    @(6, 26, 48, 70),
    @(6, 26, 50, 74),
    @(6, 30, 54, 78),
    @(6, 30, 56, 82),
    @(6, 30, 58, 86),
    @(6, 34, 62, 90)
)

# Remainder bits after the final codeword, per version 1-20.
$QrRemainderBits = @(0, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3)

function Get-QrErrorCorrection {
    # Reed-Solomon EC codewords for one block, over GF(256) with polynomial 0x11D.
    [OutputType([int[]])]
    param(
        [Parameter(Mandatory)][int[]]$Data,
        [Parameter(Mandatory)][int]$Count
    )

    $exp = [int[]]::new(512)
    $log = [int[]]::new(256)
    $x = 1
    for ($i = 0; $i -lt 255; $i++) {
        $exp[$i] = $x
        $log[$x] = $i
        $x = $x -shl 1
        if ($x -band 0x100) { $x = $x -bxor 0x11D }
    }
    for ($i = 255; $i -lt 512; $i++) { $exp[$i] = $exp[$i - 255] }

    # Generator (x - a^0)(x - a^1)...(x - a^(Count-1)), highest degree first; gen[0] = 1.
    $gen = [int[]]::new($Count + 1)
    $gen[0] = 1
    for ($i = 0; $i -lt $Count; $i++) {
        for ($j = $i + 1; $j -ge 1; $j--) {
            if ($gen[$j - 1] -ne 0) {
                $gen[$j] = $gen[$j] -bxor $exp[$log[$gen[$j - 1]] + $i]
            }
        }
    }

    $remainder = [int[]]::new($Count)
    foreach ($byte in $Data) {
        $factor = $byte -bxor $remainder[0]
        for ($k = 0; $k -lt $Count - 1; $k++) { $remainder[$k] = $remainder[$k + 1] }
        $remainder[$Count - 1] = 0
        if ($factor -ne 0) {
            for ($k = 0; $k -lt $Count; $k++) {
                if ($gen[$k + 1] -ne 0) {
                    $remainder[$k] = $remainder[$k] -bxor $exp[$log[$gen[$k + 1]] + $log[$factor]]
                }
            }
        }
    }
    return ,$remainder
}

function Get-QrBch {
    # Value followed by its BCH check bits: the remainder of (Value << Degree) divided by Poly.
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][int]$Value,
        [Parameter(Mandatory)][int]$Poly,
        [Parameter(Mandatory)][int]$Degree
    )

    $remainder = $Value -shl $Degree
    for ($bit = 30; $bit -ge $Degree; $bit--) {
        if ($remainder -band (1 -shl $bit)) {
            $remainder = $remainder -bxor ($Poly -shl ($bit - $Degree))
        }
    }
    return ($Value -shl $Degree) -bor $remainder
}

function Get-QrMaskedModule {
    # Copy of Module with data mask pattern Mask applied to every non-function module.
    [OutputType([int[]])]
    param(
        [Parameter(Mandatory)][int[]]$Module,
        [Parameter(Mandatory)][bool[]]$IsFunction,
        [Parameter(Mandatory)][int]$Size,
        [Parameter(Mandatory)][int]$Mask
    )

    $result = [int[]]$Module.Clone()
    for ($r = 0; $r -lt $Size; $r++) {
        for ($c = 0; $c -lt $Size; $c++) {
            $index = $r * $Size + $c
            if ($IsFunction[$index]) { continue }
            $flip = switch ($Mask) {
                0 { ($r + $c) % 2 -eq 0 }
                1 { $r % 2 -eq 0 }
                2 { $c % 3 -eq 0 }
                3 { ($r + $c) % 3 -eq 0 }
                4 { ([Math]::Floor($r / 2) + [Math]::Floor($c / 3)) % 2 -eq 0 }
                5 { ($r * $c) % 2 + ($r * $c) % 3 -eq 0 }
                6 { (($r * $c) % 2 + ($r * $c) % 3) % 2 -eq 0 }
                7 { (($r + $c) % 2 + ($r * $c) % 3) % 2 -eq 0 }
            }
            if ($flip) { $result[$index] = 1 - $result[$index] }
        }
    }
    return ,$result
}

function Get-QrFinderPenalty {
    # N3 for one row or column: 40 per dark-light-dark-dark-dark-light-dark run with 4 light
    # modules before or after it. As in segno, the symbol edge counts as light, and the scan
    # resumes after a counted run.
    [OutputType([int])]
    param([Parameter(Mandatory)][int[]]$Line)

    $n = $Line.Length
    $score = 0
    $start = 0
    while ($true) {
        $idx = -1
        for ($k = $start; $k -le $n - 7; $k++) {
            if ($Line[$k] -eq 1 -and $Line[$k + 1] -eq 0 -and $Line[$k + 2] -eq 1 -and $Line[$k + 3] -eq 1 -and
                $Line[$k + 4] -eq 1 -and $Line[$k + 5] -eq 0 -and $Line[$k + 6] -eq 1) {
                $idx = $k
                break
            }
        }
        if ($idx -lt 0) { break }

        $lightBefore = $true
        for ($k = [Math]::Max($idx - 4, 0); $k -lt $idx; $k++) {
            if ($Line[$k] -ne 0) { $lightBefore = $false }
        }
        $lightAfter = $true
        for ($k = $idx + 7; $k -lt [Math]::Min($idx + 11, $n); $k++) {
            if ($Line[$k] -ne 0) { $lightAfter = $false }
        }

        if ($idx -eq 0 -or $idx -eq $n - 7 -or $lightBefore -or $lightAfter) {
            $score += 40
            $start = $idx + 7
        } else {
            $start = $idx + 4
        }
    }
    return $score
}

function Get-QrPenalty {
    # Mask penalty score with N1=3, N2=3, N3=40, N4=10 (ISO/IEC 18004 7.8.3).
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][int[]]$Module,
        [Parameter(Mandatory)][int]$Size
    )

    $score = 0
    $dark = 0
    $row = [int[]]::new($Size)
    $col = [int[]]::new($Size)
    for ($i = 0; $i -lt $Size; $i++) {
        $rowRun = 0
        $colRun = 0
        $rowPrev = -1
        $colPrev = -1
        for ($j = 0; $j -lt $Size; $j++) {
            $rowBit = $Module[$i * $Size + $j]
            $colBit = $Module[$j * $Size + $i]
            $row[$j] = $rowBit
            $col[$j] = $colBit
            $dark += $rowBit

            if ($rowBit -eq $rowPrev) {
                $rowRun++
            } else {
                if ($rowRun -ge 5) { $score += $rowRun - 2 }
                $rowRun = 1
            }
            if ($colBit -eq $colPrev) {
                $colRun++
            } else {
                if ($colRun -ge 5) { $score += $colRun - 2 }
                $colRun = 1
            }

            if ($i -gt 0 -and $j -gt 0 -and $rowBit -eq $rowPrev -and
                $rowBit -eq $Module[($i - 1) * $Size + $j] -and $rowBit -eq $Module[($i - 1) * $Size + $j - 1]) {
                $score += 3
            }

            $rowPrev = $rowBit
            $colPrev = $colBit
        }
        if ($rowRun -ge 5) { $score += $rowRun - 2 }
        if ($colRun -ge 5) { $score += $colRun - 2 }
        $score += Get-QrFinderPenalty -Line $row
        $score += Get-QrFinderPenalty -Line $col
    }

    $percent = [double]$dark / ($Size * $Size)
    $score += 10 * [int][Math]::Floor([Math]::Abs($percent * 100 - 50) / 5)
    return $score
}

function New-QrMatrix {
    # Returns Version, Mask, and Rows ('0'/'1' strings, 1 = dark, no quiet zone).
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateRange(0, 7)][int]$Mask
    )

    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $version = 0
    for ($v = 1; $v -le 20; $v++) {
        $blocks = $QrBlocksL[$v - 1]
        $countBits = if ($v -le 9) { 8 } else { 16 }
        if (4 + $countBits + 8 * $bytes.Length -le 8 * ($blocks[1] * $blocks[2] + $blocks[3] * $blocks[4])) {
            $version = $v
            break
        }
    }
    if ($version -eq 0) {
        throw "Text is $($bytes.Length) bytes in UTF-8; a QR code with version 20 and error correction level L holds at most 858 bytes."
    }

    $blocks = $QrBlocksL[$version - 1]
    $ecCount = $blocks[0]
    $dataCount = $blocks[1] * $blocks[2] + $blocks[3] * $blocks[4]
    $countBits = if ($version -le 9) { 8 } else { 16 }

    $bits = [Collections.Generic.List[int]]::new()
    $append = {
        param([int]$Value, [int]$Length)
        for ($i = $Length - 1; $i -ge 0; $i--) { $bits.Add(($Value -shr $i) -band 1) }
    }
    & $append 4 4
    & $append $bytes.Length $countBits
    foreach ($byte in $bytes) { & $append $byte 8 }
    & $append 0 ([Math]::Min(4, 8 * $dataCount - $bits.Count))
    # Pad to a byte boundary. Like segno, which made the codes verified on the phone, a stream
    # that is already byte aligned gets one 0x00 codeword here. Decoders stop at the terminator.
    & $append 0 (8 - ($bits.Count % 8))

    $codewords = [Collections.Generic.List[int]]::new()
    for ($i = 0; $i -lt $bits.Count -and $codewords.Count -lt $dataCount; $i += 8) {
        $value = 0
        for ($k = 0; $k -lt 8; $k++) { $value = ($value -shl 1) -bor $bits[$i + $k] }
        $codewords.Add($value)
    }
    $pad = 0xEC
    while ($codewords.Count -lt $dataCount) {
        $codewords.Add($pad)
        $pad = if ($pad -eq 0xEC) { 0x11 } else { 0xEC }
    }

    $dataBlocks = [Collections.Generic.List[object]]::new()
    $ecBlocks = [Collections.Generic.List[object]]::new()
    $offset = 0
    foreach ($group in @(@($blocks[1], $blocks[2]), @($blocks[3], $blocks[4]))) {
        for ($b = 0; $b -lt $group[0]; $b++) {
            $block = $codewords.GetRange($offset, $group[1]).ToArray()
            $offset += $group[1]
            $dataBlocks.Add($block)
            $ecBlocks.Add((Get-QrErrorCorrection -Data $block -Count $ecCount))
        }
    }

    $final = [Collections.Generic.List[int]]::new()
    for ($i = 0; $i -lt [Math]::Max($blocks[2], $blocks[4]); $i++) {
        foreach ($block in $dataBlocks) {
            if ($i -lt $block.Length) { $final.Add($block[$i]) }
        }
    }
    for ($i = 0; $i -lt $ecCount; $i++) {
        foreach ($block in $ecBlocks) { $final.Add($block[$i]) }
    }
    $bits.Clear()
    foreach ($codeword in $final) { & $append $codeword 8 }
    & $append 0 $QrRemainderBits[$version - 1]
    $dataBits = $bits.ToArray()

    $size = 17 + 4 * $version
    $modules = [int[]]::new($size * $size)
    $isFunction = [bool[]]::new($size * $size)
    $set = {
        param([int]$Row, [int]$Col, [bool]$Dark)
        $modules[$Row * $size + $Col] = [int]$Dark
        $isFunction[$Row * $size + $Col] = $true
    }

    # Finder patterns with their separators.
    foreach ($corner in @(@(0, 0), @(0, ($size - 7)), @(($size - 7), 0))) {
        for ($dr = -1; $dr -le 7; $dr++) {
            for ($dc = -1; $dc -le 7; $dc++) {
                $r = $corner[0] + $dr
                $c = $corner[1] + $dc
                if ($r -lt 0 -or $r -ge $size -or $c -lt 0 -or $c -ge $size) { continue }
                $ring = [Math]::Max([Math]::Abs($dr - 3), [Math]::Abs($dc - 3))
                & $set $r $c ($ring -ne 2 -and $ring -ne 4)
            }
        }
    }

    # Timing patterns.
    for ($i = 8; $i -lt $size - 8; $i++) {
        & $set 6 $i ($i % 2 -eq 0)
        & $set $i 6 ($i % 2 -eq 0)
    }

    # Alignment patterns, except the three that would overlap the finder patterns.
    $positions = $QrAlignmentPositions[$version - 1]
    $last = $positions.Count - 1
    for ($i = 0; $i -le $last; $i++) {
        for ($j = 0; $j -le $last; $j++) {
            if (($i -eq 0 -and $j -eq 0) -or ($i -eq 0 -and $j -eq $last) -or ($i -eq $last -and $j -eq 0)) { continue }
            for ($dr = -2; $dr -le 2; $dr++) {
                for ($dc = -2; $dc -le 2; $dc++) {
                    & $set ($positions[$i] + $dr) ($positions[$j] + $dc) ([Math]::Max([Math]::Abs($dr), [Math]::Abs($dc)) -ne 1)
                }
            }
        }
    }

    # Format and version areas, and the dark module, stay light while masks are scored (as in segno).
    for ($i = 0; $i -le 8; $i++) {
        if ($i -eq 6) { continue }  # timing pattern
        & $set 8 $i $false
        & $set $i 8 $false
    }
    for ($i = 0; $i -lt 8; $i++) {
        & $set 8 ($size - 1 - $i) $false
        & $set ($size - 1 - $i) 8 $false
    }
    if ($version -ge 7) {
        for ($i = 0; $i -lt 6; $i++) {
            for ($k = 0; $k -lt 3; $k++) {
                & $set $i ($size - 11 + $k) $false
                & $set ($size - 11 + $k) $i $false
            }
        }
    }

    # Data bits in two-module columns, right to left, alternately upward and downward.
    $bitIndex = 0
    for ($right = $size - 1; $right -ge 1; $right -= 2) {
        if ($right -eq 6) { $right = 5 }
        $upward = (($right + 1) -band 2) -eq 0
        for ($vertical = 0; $vertical -lt $size; $vertical++) {
            $r = if ($upward) { $size - 1 - $vertical } else { $vertical }
            for ($z = 0; $z -lt 2; $z++) {
                $index = $r * $size + $right - $z
                if (-not $isFunction[$index] -and $bitIndex -lt $dataBits.Length) {
                    $modules[$index] = $dataBits[$bitIndex]
                    $bitIndex++
                }
            }
        }
    }
    if ($bitIndex -ne $dataBits.Length) {
        throw "Internal error: placed $bitIndex of $($dataBits.Length) data bits in a version $version symbol."
    }

    if ($PSBoundParameters.ContainsKey('Mask')) {
        $bestMask = $Mask
        $best = Get-QrMaskedModule -Module $modules -IsFunction $isFunction -Size $size -Mask $Mask
    } else {
        $bestMask = -1
        $bestScore = [int]::MaxValue
        $best = $null
        for ($m = 0; $m -lt 8; $m++) {
            $candidate = Get-QrMaskedModule -Module $modules -IsFunction $isFunction -Size $size -Mask $m
            $score = Get-QrPenalty -Module $candidate -Size $size
            if ($score -lt $bestScore) {
                $bestScore = $score
                $bestMask = $m
                $best = $candidate
            }
        }
    }

    # Format information (level L = 01, BCH 0x537, XOR 0x5412), two copies, and the dark module.
    $format = (Get-QrBch -Value ((1 -shl 3) -bor $bestMask) -Poly 0x537 -Degree 10) -bxor 0x5412
    for ($i = 0; $i -lt 8; $i++) {
        $low = ($format -shr $i) -band 1
        $high = ($format -shr (14 - $i)) -band 1
        $skip = if ($i -ge 6) { 1 } else { 0 }
        $best[($i + $skip) * $size + 8] = $low
        $best[8 * $size + $i + $skip] = $high
        $best[8 * $size + $size - 1 - $i] = $low
        $best[($size - 1 - $i) * $size + 8] = $high
    }
    $best[($size - 8) * $size + 8] = 1

    # Version information (BCH 0x1F25), two copies.
    if ($version -ge 7) {
        $info = Get-QrBch -Value $version -Poly 0x1F25 -Degree 12
        for ($i = 0; $i -lt 6; $i++) {
            for ($k = 0; $k -lt 3; $k++) {
                $bit = ($info -shr ($i * 3 + $k)) -band 1
                $best[($size - 11 + $k) * $size + $i] = $bit
                $best[$i * $size + $size - 11 + $k] = $bit
            }
        }
    }

    $rows = [string[]]::new($size)
    for ($r = 0; $r -lt $size; $r++) {
        $rows[$r] = -join $best[($r * $size)..($r * $size + $size - 1)]
    }
    return [pscustomobject]@{
        Version = $version
        Mask    = $bestMask
        Rows    = $rows
    }
}

function Get-QrConsoleSize {
    # Columns and lines Write-QrCode prints: a 4-module quiet zone on each side, two module rows per line.
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string[]]$Rows)

    $width = $Rows.Count + 8
    return [pscustomobject]@{
        Width  = $width
        Height = [int][Math]::Ceiling($width / 2)
    }
}

function Write-QrCode {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'The QR code is drawn on the console in fixed colors so it scans on dark terminals; it is not pipeline output.')]
    param([Parameter(Mandatory)][string[]]$Rows)

    $quiet = 4
    $margin = '0' * $quiet
    $light = '0' * ($Rows[0].Length + 2 * $quiet)
    $lines = [Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $quiet; $i++) { $lines.Add($light) }
    foreach ($row in $Rows) { $lines.Add($margin + $row + $margin) }
    for ($i = 0; $i -lt $quiet; $i++) { $lines.Add($light) }
    if ($lines.Count % 2) { $lines.Add($light) }

    $both = [string][char]0x2588
    $upper = [string][char]0x2580
    $lower = [string][char]0x2584
    for ($i = 0; $i -lt $lines.Count; $i += 2) {
        $text = [Text.StringBuilder]::new()
        for ($c = 0; $c -lt $light.Length; $c++) {
            $top = $lines[$i][$c] -eq [char]'1'
            $bottom = $lines[$i + 1][$c] -eq [char]'1'
            $glyph = if ($top -and $bottom) { $both } elseif ($top) { $upper } elseif ($bottom) { $lower } else { ' ' }
            [void]$text.Append($glyph)
        }
        Write-Host $text.ToString() -ForegroundColor Black -BackgroundColor White
    }
}
