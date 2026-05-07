namespace NullBot.UI.Models;

public enum ConnectionStatus { Clean, Suspicious, Malicious }

public record NetworkConnection(
    string ProcessName,
    int Pid,
    string DestinationIp,
    int DestinationPort,
    string? Sni,
    ConnectionStatus Status,
    string? StatusReason,
    bool IsBeaconing,
    double[]? BeaconingIntervalsSec,
    DateTime FirstSeen
);
