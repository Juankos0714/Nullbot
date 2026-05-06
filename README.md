# NullBot — Open Source Anti-Botnet for Windows 11

![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2011-0078D4)
![Status](https://img.shields.io/badge/status-alpha-orange)

> Community-driven antivirus focused on botnet detection and C2 communication blocking for Windows 11.

---

## Features

- 🔍 **Signature-based scanning** — YARA rules + hash database (SHA-256/MD5)
- 🤖 **Anti-botnet engine** — C2 communication detection, DGA detection, beaconing analysis
- 🧠 **Heuristic analysis** — PE header inspection, entropy analysis, suspicious import detection
- 🛡️ **Real-time protection** — AMSI integration + directory monitoring
- 🌐 **Network monitoring** — DNS monitoring, IP reputation, traffic pattern analysis
- 🔒 **Quarantine system** — AES-256 encrypted quarantine with restore capability
- 📡 **Threat intelligence** — Auto-updated feeds from Abuse.ch, AlienVault OTX
- 🖥️ **Native UI** — WPF dashboard with system tray support

---

## Architecture

```
nullbot/
├── core/               # Scan engine (C/C++)
│   ├── scanner/        # File scanner + YARA integration
│   ├── heuristic/      # PE analysis + entropy
│   └── quarantine/     # Quarantine management
├── network/            # Network monitoring module
│   ├── monitor/        # WinDivert-based packet capture
│   ├── c2_detection/   # C2 pattern detection
│   └── dga/            # Domain Generation Algorithm detection
├── signatures/         # Threat signatures and rules
│   ├── rules/          # YARA rules
│   └── updater/        # Signature update service
├── ui/                 # C# WPF frontend
├── driver/             # Optional: Minifilter kernel driver
├── tests/              # Unit + integration tests
└── docs/               # Technical documentation
```

---

## Getting Started

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Windows 11 x64 | 22H2+ | Build and target platform |
| Visual Studio 2022 Build Tools | 17.x | Install "Desktop development with C++" workload |
| Windows SDK | 10.0.22621+ | Included with VS Build Tools |
| CMake | 3.25+ | [cmake.org/download](https://cmake.org/download/) |
| Python | 3.11+ | For signature updater (`python` must be in PATH) |
| Ninja | any | Bundled with VS Build Tools |

### Build from source (step by step)

```powershell
# 1. Clone the repository
git clone https://github.com/Juankos0714/nullbot.git
cd nullbot

# 2. Open a VS 2022 x64 developer prompt, then:
#    (or run vcvars64.bat manually before the steps below)

# 3. Configure — Release build, Ninja generator
cmake -B build -S . -G Ninja -DCMAKE_BUILD_TYPE=Release

# 4. Compile all targets
cmake --build build --parallel

# Outputs:
#   build\bin\nullbot_cli.exe          — command-line tool
#   build\bin\nullbot_amsi_provider.dll — AMSI COM provider
#   build\bin\nullbot_tests.exe         — test runner
```

If CMake cannot find the Ninja executable, use the VS generator instead:

```powershell
cmake -B build -S . -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### Install Python signature tools

```powershell
cd signatures\updater
pip install -r requirements.txt
```

### Run the test suite

```powershell
# Quick: run the test binary directly
build\bin\nullbot_tests.exe

# Via CTest (shows pass/fail summary)
ctest --test-dir build --output-on-failure

# Expected output: 51/51 tests passed  (unit + integration)
```

> **Windows Defender note**: `FullScan_DetectsEicar_ByHash` and
> `FullScan_RealTimeDetection_CallbackFired` create the EICAR test string on disk.
> Add a Defender exclusion on `%TEMP%` before running, otherwise Defender removes
> the file before NullBot's scanner sees it:
> ```powershell
> Add-MpPreference -ExclusionPath $env:TEMP   # requires admin
> ```

### Quick scan

```powershell
# Scan %TEMP%, %APPDATA%, and Startup folder (common infection points)
build\bin\nullbot_cli.exe --scan --quick

# Scan a specific directory
build\bin\nullbot_cli.exe --scan --path "C:\Users\$env:USERNAME\Downloads"

# Scan and auto-quarantine threats
build\bin\nullbot_cli.exe --scan --quick --auto-quarantine
```

### Update threat signatures

```powershell
# Download latest feeds from Abuse.ch, AlienVault OTX, Emerging Threats
build\bin\nullbot_cli.exe --update

# Dry run — show what would be inserted without writing to DB
build\bin\nullbot_cli.exe --update --dry-run

# Schedule automatic updates every 6 hours (requires admin)
powershell -ExecutionPolicy Bypass -File scripts\install_scheduler.ps1
```

### Real-time protection

```powershell
# Start real-time protection (filesystem watcher + network monitor)
# Watches: %TEMP%, %APPDATA%, Startup folder
# Press Ctrl+C to stop
build\bin\nullbot_cli.exe --watch

# Show current protection status
build\bin\nullbot_cli.exe --status
```

### Install AMSI provider (script scanning)

```powershell
# Registers NullBot as a Windows AMSI provider — scans PowerShell, VBScript, etc.
# Requires Administrator
regsvr32 build\bin\nullbot_amsi_provider.dll

# Uninstall
regsvr32 /u build\bin\nullbot_amsi_provider.dll
```

### Quarantine management

```powershell
# List quarantined files
build\bin\nullbot_cli.exe --quarantine list

# Restore a file by ID
build\bin\nullbot_cli.exe --quarantine restore 3
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Areas where we need help:

- YARA rules for new malware families
- DGA ML model improvements
- UI/UX improvements
- Kernel driver (WDK experience needed)
- Documentation and translations

---

## License

GPL-3.0 — see [LICENSE](LICENSE)

## Disclaimer

This software is provided for educational and defensive purposes only. Use in controlled environments when testing with malware samples. The authors are not responsible for misuse.
