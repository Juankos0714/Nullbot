/*
 * NullBot — YARA Rules: Botnet Agents
 * File: signatures/rules/botnet_agents.yar
 *
 * Rules targeting common botnet agent characteristics.
 * Focus: process injection, C2 communication, persistence, self-replication.
 *
 * References:
 * - https://github.com/Yara-Rules/rules
 * - https://github.com/Neo23x0/signature-base
 */

import "pe"
import "math"

// ─── Generic: Process Injection Combo ─────────────────────────────────────────

rule Botnet_ProcessInjection_Classic {
    meta:
        description = "Detects classic process injection pattern used by botnet agents"
        severity    = "HIGH"
        category    = "botnet"
        author      = "NullBot Community"

    strings:
        $api1 = "VirtualAllocEx"      ascii wide
        $api2 = "WriteProcessMemory"  ascii wide
        $api3 = "CreateRemoteThread"  ascii wide

    condition:
        all of ($api*)
        and pe.is_pe
        and pe.number_of_sections < 10
}

// ─── Generic: Stealth Injection (no CreateRemoteThread) ───────────────────────

rule Botnet_StealthInjection {
    meta:
        description = "Stealth injection using APC or NtCreateThreadEx"
        severity    = "HIGH"
        category    = "botnet"
        author      = "NullBot Community"

    strings:
        $alloc   = "VirtualAllocEx"      ascii wide
        $write   = "WriteProcessMemory"  ascii wide
        $stealth1 = "NtCreateThreadEx"   ascii wide
        $stealth2 = "RtlCreateUserThread" ascii wide
        $stealth3 = "QueueUserAPC"       ascii wide

    condition:
        pe.is_pe
        and $alloc and $write
        and any of ($stealth*)
}

// ─── Generic: Anti-Debug Cluster ──────────────────────────────────────────────

rule Botnet_AntiDebug_Cluster {
    meta:
        description = "Multiple anti-debug techniques — common in botnet loaders"
        severity    = "MEDIUM"
        category    = "evasion"
        author      = "NullBot Community"

    strings:
        $d1 = "IsDebuggerPresent"            ascii wide
        $d2 = "CheckRemoteDebuggerPresent"   ascii wide
        $d3 = "NtQueryInformationProcess"    ascii wide
        $d4 = "NtSetInformationThread"       ascii wide
        $d5 = "ZwQuerySystemInformation"     ascii wide

    condition:
        pe.is_pe and 3 of ($d*)
}

// ─── Generic: HTTP Beaconing Pattern ──────────────────────────────────────────

rule Botnet_HTTP_Beacon {
    meta:
        description = "HTTP beaconing pattern — periodic C2 callback via HTTP"
        severity    = "HIGH"
        category    = "c2_communication"
        author      = "NullBot Community"

    strings:
        // Network initialization
        $net1 = "WSAStartup"          ascii wide
        $net2 = "WinHttpConnect"      ascii wide
        $net3 = "InternetOpenUrlA"    ascii wide
        $net4 = "HttpSendRequestA"    ascii wide

        // Typical beacon user-agents (often hardcoded)
        $ua1  = "Mozilla/4.0 (compatible; MSIE" ascii nocase
        $ua2  = "Windows NT 5.1"   ascii nocase  // Pretending to be WinXP

        // Timing functions (for interval-based beaconing)
        $sleep = "Sleep"            ascii wide

    condition:
        pe.is_pe
        and any of ($net*)
        and $sleep
        and any of ($ua*)
}

// ─── Generic: Registry Persistence ───────────────────────────────────────────

rule Botnet_Persistence_RunKey {
    meta:
        description = "Writes to Run registry key for persistence"
        severity    = "HIGH"
        category    = "persistence"
        author      = "NullBot Community"

    strings:
        $reg_api1 = "RegSetValueExA"  ascii wide
        $reg_api2 = "RegSetValueExW"  ascii wide
        $run_key1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run_key2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase

    condition:
        pe.is_pe
        and any of ($reg_api*)
        and any of ($run_key*)
}

// ─── Generic: Self-Copy Dropper ───────────────────────────────────────────────

rule Botnet_SelfCopy_Dropper {
    meta:
        description = "Self-copies to user/temp folders and executes — dropper behavior"
        severity    = "HIGH"
        category    = "dropper"
        author      = "NullBot Community"

    strings:
        $copy  = "CopyFileA"        ascii wide
        $copy2 = "CopyFileW"        ascii wide
        $appd  = "APPDATA"          ascii wide
        $temp  = "TEMP"             ascii wide
        $exec  = "ShellExecuteA"    ascii wide
        $exec2 = "CreateProcessA"   ascii wide

    condition:
        pe.is_pe
        and any of ($copy*)
        and any of ($appd, $temp)
        and any of ($exec*)
}

// ─── Mirai: IoT-style botnet patterns (Windows variant) ──────────────────────

rule Botnet_Mirai_WindowsVariant {
    meta:
        description = "Mirai-inspired botnet agent for Windows"
        severity    = "CRITICAL"
        category    = "botnet"
        family      = "Mirai"
        author      = "NullBot Community"

    strings:
        // Mirai strings often found in Windows variants
        $str1 = "/proc/net/tcp"       ascii
        $str2 = "SCANNER"             ascii
        $str3 = "HTTPFLOOD"           ascii
        $str4 = "UDPFLOOD"            ascii
        $str5 = "bot_killer"          ascii
        $str6 = "watchdog"            ascii nocase
        $str7 = "tftp "               ascii

        // Default Mirai C2 ports
        $port_str = "23" fullword ascii
        $port_str2 = "2323" fullword ascii

    condition:
        pe.is_pe and 3 of ($str*) and any of ($port_str*)
}

// ─── High entropy packed PE (generic packer) ─────────────────────────────────

rule Generic_HighEntropy_Packed {
    meta:
        description = "Packed or encrypted PE — common in malware to evade static detection"
        severity    = "MEDIUM"
        category    = "packer"
        author      = "NullBot Community"

    condition:
        pe.is_pe
        and pe.number_of_sections >= 2
        and math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) > 7.0
}
