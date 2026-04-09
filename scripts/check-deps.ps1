$results = @()

function Test-Binary {
    param(
        [string]$Name,
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if ($candidate -and (Test-Path $candidate)) {
            return @{ name = $Name; found = $true; path = $candidate }
        }

        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) {
            return @{ name = $Name; found = $true; path = $cmd.Source }
        }
    }

    return @{ name = $Name; found = $false; path = $null }
}

$results += Test-Binary -Name 'tshark' -Candidates @(
    $env:TSHARK_PATH,
    'tshark',
    'C:\Program Files\Wireshark\tshark.exe',
    'C:\Program Files (x86)\Wireshark\tshark.exe'
)

$results += Test-Binary -Name 'stratoshark' -Candidates @(
    $env:STRATOSHARK_PATH,
    'stratoshark',
    'stratoshark.exe',
    'C:\Program Files\Stratoshark\stratoshark.exe',
    'C:\Program Files (x86)\Stratoshark\stratoshark.exe'
)

$results += Test-Binary -Name 'python' -Candidates @(
    $env:PYTHON_PATH,
    'python',
    'python3'
)

$results | ConvertTo-Json -Depth 3
