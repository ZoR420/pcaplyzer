# Windows Local Setup for pcaplyzer

## Goal
Run pcaplyzer locally on Windows with PCAP + SCAP case ingestion, local summaries, and optional Stratoshark CLI support.

## Required software
1. **Node.js 20+**
2. **npm**
3. **Python 3** (needed for legacy parser/chat path)
4. **Wireshark / tshark**
5. **Stratoshark** (optional but recommended for real SCAP extraction)

## Install checklist
### 1. Clone and install
```powershell
git clone https://github.com/ZoR420/pcaplyzer.git
cd pcaplyzer
npm install
```

### 2. Install Wireshark/tshark
- Install Wireshark from: <https://www.wireshark.org/download.html>
- Ensure `tshark.exe` is available in PATH, or set:
```powershell
$env:TSHARK_PATH = 'C:\Program Files\Wireshark\tshark.exe'
```

### 3. Install Stratoshark (optional but preferred)
- If installed outside PATH, set:
```powershell
$env:STRATOSHARK_PATH = 'C:\Program Files\Stratoshark\stratoshark.exe'
```

### 4. Verify dependencies
PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-deps.ps1
```

Node cross-platform check:
```powershell
node .\scripts\check-deps.js
```

## Start locally
```powershell
npm run dev
```

## What works after Phases 0-5
- local upload of `.pcap`, `.pcapng`, `.scap`
- case management
- SCAP summary generation
- Stratoshark CLI first, fallback parser second
- export route
- correlation + guided triage

## Current limitations
- no live capture
- fallback SCAP parsing is heuristic when Stratoshark CLI is absent
- Windows packaging is documented/setup-oriented, not yet an installer/exe bundle

## Recommended environment variables
```powershell
$env:TSHARK_PATH='C:\Program Files\Wireshark\tshark.exe'
$env:STRATOSHARK_PATH='C:\Program Files\Stratoshark\stratoshark.exe'
$env:PYTHON_PATH='python'
```
