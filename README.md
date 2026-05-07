<div align="center">
  <img src="docs/assets/nullbot-hero.png" alt="NullBot shield" width="100%"/>
</div>

# NullBot
### Open source antivirus that hunts botnets.
### Built by the community. Free forever.

<div align="center">

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2011-0078D4)]()
[![Status](https://img.shields.io/badge/status-alpha-orange)]()
[![GitHub Stars](https://img.shields.io/github/stars/Juankos0714/nullbot?style=flat)](https://github.com/Juankos0714/nullbot)

[Download for Windows 11](#quick-install-2-minutes) &nbsp;|&nbsp; [View on GitHub](https://github.com/Juankos0714/nullbot) &nbsp;|&nbsp; [Join Discord](#community)

</div>

---

## Why NullBot?

Tu computadora puede ser parte de una botnet ahora mismo y no saberlo.
Las botnets son redes de computadoras infectadas que se usan para enviar
spam, atacar sitios web, robar datos bancarios, o minar criptomonedas
con tu electricidad. La mayoría de antivirus comerciales se enfocan en
virus tradicionales y dejan pasar el tráfico de comando-y-control que
caracteriza a las botnets modernas.

NullBot está construido específicamente para esto.

---

## What you get

🛡️ &nbsp; Real-time protection contra archivos maliciosos\
🤖 &nbsp; Detección de botnets por su patrón de comunicación\
🌐 &nbsp; Bloqueo de servidores C2 conocidos (Emotet, TrickBot, Dridex...)\
🔍 &nbsp; Detección de dominios DGA (los que las botnets generan al azar)\
📡 &nbsp; Actualización automática cada 6 horas con feeds gratuitos\
🔒 &nbsp; Cuarentena cifrada con AES-256\
💸 &nbsp; 100% gratis. Sin ads, sin telemetría, sin "premium tier"

---

## Quick install (2 minutes)

1. Download the latest installer from the [Releases page](https://github.com/Juankos0714/nullbot/releases):

   [⬇ NullBot-0.1.0-x64.msi](https://github.com/Juankos0714/nullbot/releases/latest)

2. Double-click the installer.
3. Follow the wizard.
4. Done. NullBot is now protecting you.

> [!IMPORTANT]
> Necesitas Windows 11 (también funciona en Windows 10 22H2+).
> Recomendamos desinstalar otros antivirus de terceros para evitar conflictos.
> Windows Defender puede coexistir con NullBot sin problemas.

---

## Screenshots

| Dashboard | Scanner | Network monitoring | Quarantine |
|-----------|---------|-------------------|------------|
| *(0.1.0 screenshots coming soon)* | | | |

---

## Frequently asked

**¿Esto reemplaza a Windows Defender?**\
No, lo complementa. Defender es excelente contra malware tradicional;
NullBot añade una capa específica anti-botnet.

**¿Recolecta mis datos?**\
No. Cero telemetría. El código es público — puedes verificarlo tú mismo.

**¿Por qué es gratis?**\
Porque las botnets son un problema comunitario. Las víctimas no son solo
los infectados: son los sitios web atacados, los buzones inundados, las
redes saturadas. Todos pagamos.

**Encontré un falso positivo. ¿Qué hago?**\
Abre un issue con el hash SHA-256 del archivo y lo arreglamos. Reportes
de falsos positivos tienen prioridad máxima.

**¿Cómo puedo ayudar?**\
Reporta falsos positivos. Comparte el proyecto. Si sabes programar, mira
la sección técnica abajo.

---

## Community

- GitHub Discussions: [github.com/Juankos0714/nullbot/discussions](https://github.com/Juankos0714/nullbot/discussions)
- Issues & bug reports: [github.com/Juankos0714/nullbot/issues](https://github.com/Juankos0714/nullbot/issues)
- Discord: *(link coming soon)*
- Twitter / X: *(link coming soon)*
- Security vulnerabilities: email **security@nullbot.dev** — do not file a public issue

## License

GPL-3.0 — eres libre de usar, modificar y distribuir, siempre que mantengas
el proyecto abierto. Detalles completos en [LICENSE](LICENSE).

---
---

# Technical documentation

Si llegaste hasta aquí, asumo que sabes qué es un PE header y por qué los
C2 hacen beaconing.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          NullBot.exe (WPF)                          │
│                       MVVM, .NET 8, no backend                      │
└────────────────────────┬───────────────────┬───────────────────────┘
                         │ stdout streaming  │ readonly SQLite
                         ▼                   ▼
┌────────────────────────────────────┐  ┌─────────────────────────────┐
│       nullbot_cli.exe (C++20)      │  │   signatures.db (SQLite)    │
│   FileScanner, C2Detector, ...     │  │     hashes/domains/ips      │
└────────────────────┬───────────────┘  └──────────────▲──────────────┘
                     │                                 │
                     ▼                                 │
┌──────────────────────────────────┐  ┌────────────────┴──────────────┐
│ nullbot_amsi_provider.dll (COM)  │  │ update_feeds.py (scheduled)   │
│ Intercepts PowerShell / scripts  │  │ Abuse.ch + OTX + EmergingT.   │
└──────────────────────────────────┘  └───────────────────────────────┘
```

## Build from source

Prerequisites: VS 2022 Build Tools, CMake 3.25+, .NET 8 SDK, Python 3.11+,
WiX Toolset 4+, Windows SDK 10.0.22621+

```powershell
# 1. Backend C++
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# 2. UI WPF
dotnet build ui/NullBot.UI.csproj -c Release

# 3. Updater dependencies
pip install -r signatures/updater/requirements.txt

# 4. MSI Installer
msbuild installer/NullBot.Installer.wixproj /p:Configuration=Release
```

Output:
- `build/bin/nullbot_cli.exe`
- `ui/bin/Release/net8.0-windows/NullBot.exe`
- `installer/bin/Release/NullBot-0.1.0-x64.msi`

> **Windows Defender note**: tests create the EICAR string on disk.
> Add a Defender exclusion before running the suite:
> ```powershell
> Add-MpPreference -ExclusionPath $env:TEMP   # requires admin
> ctest --test-dir build --output-on-failure -j4
> ```

## Detection methodology

### File scanning pipeline

1. SHA-256 lookup against known hash database (O(1) in SQLite with index)
2. YARA rules — family-specific byte patterns and string signatures
3. Heuristic PE analysis: suspicious import clusters, packed sections, anti-debug APIs
4. Shannon entropy per section (> 7.2 = likely packer/crypter)

### Botnet detection

1. **DNS blacklist** — domains from URLhaus + OTX
2. **IP reputation** — Feodo Tracker C2 IPs (Emotet/TrickBot/Dridex)
3. **DGA detection** — entropy + n-gram frequency + vowel ratio scoring
4. **Beaconing** — coefficient of variation < 15% in connection intervals
5. **Direct IP HTTPS** — TLS without SNI to a literal IP address

## Project structure

```
nullbot/
├── core/              C++ engine (scanner, heuristic, quarantine, realtime)
├── network/           C2 detection, DGA detection, network monitor
├── signatures/        YARA rules + Python updater + SQLite schema
├── ui/                C# WPF desktop app
├── installer/         WiX MSI definitions
├── tests/             Unit + integration (51 tests passing)
├── third_party/       sqlite3 amalgamation
└── scripts/           Sign, schedule, dev tools
```

## Threat intelligence sources

| Source           | Type               | Update  | License  |
|------------------|--------------------|---------|----------|
| MalwareBazaar    | SHA-256 hashes     | live    | CC0      |
| URLhaus          | malicious domains  | live    | CC0      |
| Feodo Tracker    | botnet C2 IPs      | live    | CC0      |
| Emerging Threats | compromised IPs    | hourly  | BSD      |
| AlienVault OTX   | mixed IOCs (opt-in)| live    | API key  |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Priorities for contributors:

- YARA rules for new malware families (high impact, low complexity)
- Reducing false positives (audit `tests/integration/test_full_scan.cpp`)
- DGA model improvements (n-gram corpus, ML classifier)
- Kernel-mode minifilter driver (advanced — requires WDK + signed cert)

## Security disclosure

If you find a vulnerability **in NullBot itself** (not a malware sample you
detected), email security@nullbot.dev with a PGP-encrypted message. We
respond within 48 hours and will credit you in the release notes.

Do not file a public GitHub issue for security vulnerabilities.

## Tech specs

- C++20, `/W4 /WX`, ASLR + DEP enabled on all binaries
- .NET 8 LTS, nullable reference types enabled, warnings-as-errors
- SQLite 3.45 amalgamation (zero DLL dependency on sqlite3.dll)
- Quarantine crypto: Windows CNG — `BCryptEncrypt` with AES-256-GCM
- Hash computation: CNG `BCryptHashData` (SHA-256)
- Test suite: 51 tests — CTest (C++) + pytest (Python updater)

## License & ethics

GPL-3.0. NullBot is defensive software. Using it to attack others, evade
legitimate security tools, or assist in developing malware violates both
the license and applicable law (CFAA, GDPR, and local equivalents).

Acknowledgments: the YARA project, the Abuse.ch team, AlienVault OTX,
the SQLite authors, and the .NET WPF team. We stand on giants' shoulders.
