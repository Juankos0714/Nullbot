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

- Windows 11 (x64)
- Visual Studio 2022 with C++ and C# workloads
- Windows SDK 10.0.22621+
- Python 3.11+ (for signature tooling)
- CMake 3.25+

### Build

```bash
# Clone
git clone https://github.com/your-org/nullbot.git
cd nullbot

# Build core engine (C++)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Build UI (C#)
cd ui
dotnet build NullBot.UI.csproj

# Install Python tools
cd ../signatures
pip install -r requirements.txt
```

### Running (Development)

```bash
# Run with Windows Sandbox or VM recommended for testing
.\build\nullbot_core.exe --mode scan --path "C:\Users\%USERNAME%\Downloads"

# Start UI
cd ui && dotnet run
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
