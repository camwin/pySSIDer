from dataclasses import dataclass

@dataclass
class WiFiNetwork:
    ssid: str
    signal: int
    channel: int
    security: str
    channel_width: str
    bssid: str
    rssi: float
    phy_type: str
    frequency: int
    mode: str
    snr: float
    last_seen: str
    vendor: str  # Added for vendor detection