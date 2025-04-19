import platform
import subprocess
import re
from abc import ABC, abstractmethod
from wifi_network import WiFiNetwork
from datetime import datetime
import pywifi
from pywifi import const
from mac_vendor_lookup import MacLookup

class WiFiScanner(ABC):
    @abstractmethod
    def scan(self) -> list[WiFiNetwork]:
        pass

class PyWiFiScanner(WiFiScanner):
    def scan(self) -> list[WiFiNetwork]:
        networks = []
        mac_lookup = MacLookup()
        try:
            mac_lookup.update_vendors()
        except Exception as e:
            print(f"Failed to update OUI database: {e}")
        
        try:
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]  # Use the first interface
            iface.scan()
            import time
            time.sleep(5)  # Wait for scan completion
            scan_results = iface.scan_results()
            
            print(f"Found {len(scan_results)} networks via pywifi")
            for network in scan_results:
                try:
                    ssid = network.ssid or "Hidden Network"
                    signal = network.signal  # RSSI in dBm
                    freq = network.freq // 1000  # Convert kHz to MHz
                    bssid = network.bssid.upper().rstrip(":")  # Remove trailing colon
                    # Validate BSSID format
                    if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", bssid):
                        print(f"Invalid BSSID format '{bssid}' for SSID {ssid}, setting to N/A.")
                        bssid = "N/A"
                    
                    # Simplified security mapping
                    akm = network.akm[0] if network.akm else None
                    print(f"Raw akm for SSID {ssid}: {network.akm}")
                    security_map = {
                        const.AKM_TYPE_WPA: "WPA-Enterprise",
                        const.AKM_TYPE_WPAPSK: "WPA-Personal",
                        const.AKM_TYPE_WPA2: "WPA2-Enterprise",
                        const.AKM_TYPE_WPA2PSK: "WPA2-Personal",
                        const.AKM_TYPE_NONE: "None",
                        const.AKM_TYPE_UNKNOWN: "Unknown"
                    }
                    security = security_map.get(akm, "Unknown")
                    if akm is None:
                        security = "None"
                    elif isinstance(akm, int) and akm not in security_map:
                        security = "WPA3-Personal" if akm >= 8 else "Unknown"
                    elif isinstance(akm, str) and "wpa3" in akm.lower():
                        security = "WPA3-Personal"
                    
                    # Vendor lookup
                    try:
                        vendor = mac_lookup.lookup(bssid) if bssid != "N/A" else "Unknown"
                    except Exception as e:
                        print(f"Vendor lookup failed for BSSID {bssid}: {e}")
                        vendor = "Unknown"
                    
                    # Log attributes for debugging
                    attrs = {k: getattr(network, k, "N/A") for k in dir(network) if not k.startswith("_")}
                    print(f"Profile attributes for SSID {ssid}: {attrs}")
                    
                    # Get channel
                    try:
                        channel = network.channel
                    except AttributeError:
                        print(f"No channel attribute for SSID {ssid}, calculating from freq {freq} MHz")
                        if 2400 <= freq <= 2500:  # 2.4GHz
                            if freq == 2484:
                                channel = 14
                            else:
                                channel = (freq - 2412) // 5 + 1
                        elif 5000 <= freq <= 5900:  # 5GHz
                            channel = (freq - 5000) // 5
                        else:  # 6GHz
                            channel = (freq - 5000) // 5
                        if not (1 <= channel <= 233):
                            print(f"Invalid calculated channel {channel} for SSID {ssid} (Freq: {freq} MHz), skipping.")
                            continue
                    
                    # Determine band, PHY type, and channel width
                    if 2400 <= freq <= 2500:
                        expected_band = "2.4GHz"
                        phy_type = "802.11n"
                        channel_width = "20MHz"  # Adjust to 40MHz if router uses it
                    elif 5000 <= freq <= 5900:
                        expected_band = "5GHz"
                        phy_type = "802.11be" if signal >= -70 else "802.11ac"
                        channel_width = "80MHz"
                    else:
                        expected_band = "6GHz"
                        phy_type = "802.11be"
                        channel_width = "80MHz"

                    # Validate channel
                    valid_5ghz_channels = [
                        36, 40, 44, 48, 52, 56, 60, 64,
                        100, 104, 108, 112, 116, 120, 124, 128,
                        132, 136, 140, 144, 149, 153, 157, 161, 165
                    ]
                    if expected_band == "2.4GHz" and not (1 <= channel <= 14):
                        print(f"Invalid 2.4GHz channel {channel} for SSID {ssid}, skipping.")
                        continue
                    elif expected_band == "5GHz" and channel not in valid_5ghz_channels:
                        print(f"Invalid 5GHz channel {channel} for SSID {ssid}, skipping.")
                        continue
                    elif expected_band == "6GHz" and not (1 <= channel <= 233):
                        print(f"Invalid 6GHz channel {channel} for SSID {ssid}, skipping.")
                        continue

                    rssi = float(signal)
                    signal_percent = int((rssi + 100) * 2)  # Approximate % from RSSI
                    snr = rssi - (-95.0)  # Assume noise floor
                    last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    network_obj = WiFiNetwork(
                        ssid=ssid,
                        signal=signal_percent,
                        channel=channel,
                        security=security,
                        channel_width=channel_width,
                        bssid=bssid,
                        rssi=rssi,
                        phy_type=phy_type,
                        frequency=freq,
                        mode="Infra",
                        snr=snr,
                        last_seen=last_seen,
                        vendor=vendor
                    )
                    networks.append(network_obj)
                    print(f"Added network: SSID {ssid}, Channel: {channel}, Width: {channel_width}, Freq: {freq} MHz, PHY: {phy_type}, Signal: {signal_percent}%, RSSI: {rssi} dBm, Security: {security}, Vendor: {vendor}, BSSID: {bssid}")
                except Exception as e:
                    print(f"Error processing network SSID {ssid}: {e}")
                    continue

            print(f"Total networks added: {len(networks)}")
        except Exception as e:
            print(f"Error scanning with pywifi: {e}")
        return networks

class WindowsWiFiScanner(WiFiScanner):
    def scan(self) -> list[WiFiNetwork]:
        networks = []
        mac_lookup = MacLookup()
        try:
            mac_lookup.update_vendors()
        except Exception as e:
            print(f"Failed to update OUI database: {e}")
        
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, check=True, timeout=10
            )
            output = result.stdout
            print("=== Raw netsh output ===")
            print(output)
            print("=======================")
            current_network = None
            current_bssid = None

            def add_network_if_valid(network_data, bssid_data):
                if not (network_data and bssid_data):
                    print(f"Skipping: Incomplete network or BSSID data. Network={network_data}, BSSID={bssid_data}")
                    return
                ssid = network_data.get("ssid", "").strip()
                if not ssid:
                    print("Skipping network with empty SSID.")
                    return
                if not ("signal" in bssid_data and "channel" in bssid_data and bssid_data["channel"] > 0):
                    print(f"Skipping incomplete BSSID for SSID {ssid}: Signal={bssid_data.get('signal', 'N/A')}, Channel={bssid_data.get('channel', 'N/A')}")
                    return
                channel = bssid_data["channel"]
                phy_type = bssid_data.get("phy_type", "Unknown")
                band = bssid_data.get("band", "Unknown")
                
                print(f"Processing SSID: {ssid}, Channel={channel}, PHY={phy_type}, Band={band}, Signal={bssid_data['signal']}%, Width={bssid_data.get('channel_width', 'Not Reported')}, Security={bssid_data.get('security', 'Unknown')}, BSSID={bssid_data['bssid']}")

                # Vendor lookup
                try:
                    vendor = mac_lookup.lookup(bssid_data["bssid"]) if bssid_data["bssid"] != "N/A" else "Unknown"
                except Exception as e:
                    print(f"Vendor lookup failed for BSSID {bssid_data['bssid']}: {e}")
                    vendor = "Unknown"

                if 1 <= channel <= 14:
                    freq = 2412 + (channel - 1) * 5 if channel < 14 else 2484
                    expected_band = "2.4GHz"
                else:
                    freq = 5000 + channel * 5
                    expected_band = "5GHz" if freq <= 5900 else "6GHz"
                
                if band == "5 GHz":
                    expected_band = "5GHz"
                    freq = 5000 + channel * 5
                elif band == "2.4 GHz":
                    expected_band = "2.4GHz"
                    freq = 2412 + (channel - 1) * 5 if channel < 14 else 2484
                elif band == "6 GHz":
                    expected_band = "6GHz"
                    freq = 5000 + channel * 5

                valid_5ghz_channels = [
                    36, 40, 44, 48, 52, 56, 60, 64,
                    100, 104, 108, 112, 116, 120, 124, 128,
                    132, 136, 140, 144, 149, 153, 157, 161, 165
                ]
                if expected_band == "2.4GHz" and not (1 <= channel <= 14):
                    print(f"Invalid 2.4GHz channel {channel} for SSID {ssid} (Freq: {freq} MHz), skipping.")
                    return
                elif expected_band == "5GHz" and channel not in valid_5ghz_channels:
                    print(f"Invalid 5GHz channel {channel} for SSID {ssid} (Freq: {freq} MHz), skipping.")
                    return
                elif expected_band == "6GHz" and not (1 <= channel <= 233):
                    print(f"Invalid 6GHz channel {channel} for SSID {ssid} (Freq: {freq} MHz), skipping.")
                    return

                if phy_type == "Unknown":
                    phy_type = (
                        "802.11n" if expected_band == "2.4GHz" else
                        "802.11ac" if expected_band == "5GHz" else
                        "802.11ax"
                    )
                    print(f"Inferring PHY type {phy_type} for SSID {ssid} based on band {expected_band}")

                channel_width = bssid_data.get("channel_width", "20MHz")
                if expected_band in ["5GHz", "6GHz"] and phy_type in ["802.11ac", "802.11ax", "802.11be"]:
                    channel_width = "80MHz"
                    print(f"Forcing 80MHz width for SSID {ssid} (PHY: {phy_type}) on channel {channel}")
                elif expected_band == "2.4GHz" and channel_width not in ["20MHz", "40MHz"]:
                    channel_width = "20MHz"

                rssi = -100 + (bssid_data["signal"] * 0.5)
                noise_floor = -95.0
                snr = rssi - noise_floor
                last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                network = WiFiNetwork(
                    ssid=ssid,
                    signal=bssid_data["signal"],
                    channel=channel,
                    security=bssid_data.get("security", "Unknown"),
                    channel_width=channel_width,
                    bssid=bssid_data["bssid"],
                    rssi=rssi,
                    phy_type=phy_type,
                    frequency=freq,
                    mode="Infra",
                    snr=snr,
                    last_seen=last_seen,
                    vendor=vendor
                )
                networks.append(network)
                print(f"Added network: SSID {ssid}, Channel: {channel}, Width: {channel_width}, PHY: {phy_type}, Freq: {freq} MHz, Band: {expected_band}, Security: {bssid_data.get('security', 'Unknown')}, Vendor: {vendor}, BSSID: {bssid_data['bssid']}")

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                print(f"Parsing line: {line}")
                if line.startswith("SSID"):
                    add_network_if_valid(current_network, current_bssid)
                    ssid = line.split(":", 1)[1].strip()
                    current_network = {"ssid": ssid}
                    current_bssid = None
                elif line.startswith("BSSID") and current_network:
                    add_network_if_valid(current_network, current_bssid)
                    bssid_str = line.split(":", 1)[1].strip()
                    bssid = bssid_str.upper().rstrip(":").replace("-", ":")  # Remove trailing colon
                    if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", bssid):
                        print(f"Invalid BSSID format '{bssid}' for SSID {current_network['ssid']}, setting to N/A.")
                        bssid = "N/A"
                    current_bssid = {"bssid": bssid, "signal": 0, "channel": 0, "phy_type": "Unknown", "security": "Unknown", "band": "Unknown"}
                elif line.startswith("Signal") and current_bssid:
                    signal_str = line.split(":", 1)[1].strip().replace("%", "")
                    try:
                        current_bssid["signal"] = int(signal_str)
                    except ValueError:
                        print(f"Invalid signal value '{signal_str}' for BSSID {current_bssid['bssid']} (SSID: {current_network['ssid']}), skipping.")
                        current_bssid["signal"] = 0
                elif line.startswith("Channel ") and current_bssid:
                    channel_str = line.split(":", 1)[1].strip()
                    match = re.match(r"(\d+)\s*(?:\(|$)", channel_str)
                    if match and int(match.group(1)) > 0:
                        current_bssid["channel"] = int(match.group(1))
                        print(f"Set channel to {current_bssid['channel']} for BSSID {current_bssid['bssid']} (SSID: {current_network['ssid']})")
                    else:
                        print(f"Invalid channel '{channel_str}' for BSSID {current_bssid['bssid']} (SSID: {current_network['ssid']}), setting to 0.")
                        current_bssid["channel"] = 0
                elif line.startswith("Authentication") and current_bssid:
                    current_bssid["security"] = line.split(":", 1)[1].strip()
                elif line.startswith("Radio type") and current_bssid:
                    current_bssid["phy_type"] = line.split(":", 1)[1].strip()
                elif line.startswith("Band") and current_bssid:
                    current_bssid["band"] = line.split(":", 1)[1].strip()
                elif line.startswith("Channel width") and current_bssid:
                    width = line.split(":", 1)[1].strip()
                    current_bssid["channel_width"] = width.replace(" MHz", "MHz")

            add_network_if_valid(current_network, current_bssid)
            print(f"Total networks added: {len(networks)}")

        except subprocess.TimeoutExpired:
            print("Scan timed out after 10 seconds.")
        except subprocess.CalledProcessError as e:
            print(f"Error scanning Wi-Fi on Windows: {e}")
        return networks

class MacWiFiScanner(WiFiScanner):
    def scan(self) -> list[WiFiNetwork]:
        networks = []
        mac_lookup = MacLookup()
        try:
            mac_lookup.update_vendors()
        except Exception as e:
            print(f"Failed to update OUI database: {e}")
        
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        try:
            result = subprocess.run(
                [airport_path, "-s"], capture_output=True, text=True, check=True
            )
            output = result.stdout
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 7:
                    ssid = parts[0]
                    signal = int(parts[1])
                    channel = int(parts[2].split(",")[0])
                    security = parts[6]
                    channel_width = "20MHz" if channel <= 14 else "40MHz"
                    bssid = "N/A"
                    rssi = -100 + (signal * 0.5)
                    noise_floor = -95.0
                    snr = rssi - noise_floor
                    last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Vendor lookup (use N/A for macOS as BSSID is not reliable)
                    vendor = "Unknown"
                    
                    # Determine band and PHY type
                    if 1 <= channel <= 14:
                        expected_band = "2.4GHz"
                        phy_type = "802.11n"
                    else:
                        expected_band = "5GHz"
                        phy_type = "802.11ac"
                    
                    # Validate channel
                    valid_5ghz_channels = [
                        36, 40, 44, 48, 52, 56, 60, 64,
                        100, 104, 108, 112, 116, 120, 124, 128,
                        132, 136, 140, 144, 149, 153, 157, 161, 165
                    ]
                    if expected_band == "2.4GHz" and not (1 <= channel <= 14):
                        print(f"Invalid 2.4GHz channel {channel} for SSID {ssid}, skipping.")
                        continue
                    elif expected_band == "5GHz" and channel not in valid_5ghz_channels:
                        print(f"Invalid 5GHz channel {channel} for SSID {ssid}, skipping.")
                        continue

                    network = WiFiNetwork(
                        ssid=ssid,
                        signal=signal,
                        channel=channel,
                        security=security,
                        channel_width=channel_width,
                        bssid=bssid,
                        rssi=rssi,
                        phy_type=phy_type,
                        frequency=0,  # Not available in macOS scanner
                        mode="Infra",
                        snr=snr,
                        last_seen=last_seen,
                        vendor=vendor
                    )
                    networks.append(network)
                    print(f"Added network: SSID {ssid}, Channel: {channel}, Width: {channel_width}, PHY: {phy_type}, Signal: {signal}%, RSSI: {rssi} dBm, Security: {security}, Vendor: {vendor}, BSSID: {bssid}")
        except subprocess.CalledProcessError:
            print("Error scanning Wi-Fi on macOS")
        return networks

class LinuxWiFiScanner(WiFiScanner):
    def scan(self) -> list[WiFiNetwork]:
        networks = []
        mac_lookup = MacLookup()
        try:
            mac_lookup.update_vendors()
        except Exception as e:
            print(f"Failed to update OUI database: {e}")
        
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,SIGNAL,CHAN,FREQ,MODE,SECURITY,BSSID", "device", "wifi", "list", "--rescan", "yes"],
                capture_output=True, text=True, check=True
            )
            output = result.stdout
            for line in output.splitlines():
                parts = line.split(":", 6)
                if len(parts) < 7:
                    print(f"Skipping malformed line: {line}")
                    continue
                ssid = parts[0].strip() or "Hidden Network"
                try:
                    signal = int(parts[1])
                except ValueError:
                    print(f"Invalid signal value '{parts[1]}' for SSID {ssid}, skipping.")
                    continue
                try:
                    channel = int(parts[2])
                except ValueError:
                    print(f"Invalid channel value '{parts[2]}' for SSID {ssid}, skipping.")
                    continue
                freq_str = parts[3].strip().replace(" MHz", "")
                try:
                    freq = int(freq_str)
                except ValueError:
                    print(f"Invalid frequency value '{freq_str}' for SSID {ssid}, skipping.")
                    continue
                mode = parts[4].strip()
                security = parts[5].strip() or "None"
                bssid = parts[6].strip().replace("\\:", ":").upper().rstrip(":").replace("-", ":")  # Remove trailing colon
                if not re.match(r"^[0-9A-Fa-f]{1,2}(:[0-9A-Fa-f]{1,2}){5}$", bssid):
                    print(f"Invalid BSSID format '{bssid}' for SSID {ssid}, setting to N/A.")
                    bssid = "N/A"
                else:
                    octets = bssid.split(":")
                    bssid = ":".join(octet.zfill(2) for octet in octets)

                # Vendor lookup
                try:
                    vendor = mac_lookup.lookup(bssid) if bssid != "N/A" else "Unknown"
                except Exception as e:
                    print(f"Vendor lookup failed for BSSID {bssid}: {e}")
                    vendor = "Unknown"

                if 2400 <= freq <= 2500:
                    expected_band = "2.4GHz"
                    if not (1 <= channel <= 14):
                        print(f"Invalid 2.4GHz channel {channel} for SSID {ssid} (Freq: {freq} MHz), skipping.")
                        continue
                elif 5000 <= freq <= 5900:
                    expected_band = "5GHz"
                    if not (20 <= channel <= 165):
                        print(f"Invalid 5GHz channel {channel} for SSID {ssid} (Freq: {freq} MHz), skipping.")
                        continue
                elif 5925 <= freq <= 7125:
                    expected_band = "6GHz"
                    if not (1 <= channel <= 233):
                        print(f"Invalid 6GHz channel {channel} for SSID {ssid} (Freq: {freq} MHz), skipping.")
                        continue
                else:
                    print(f"Invalid frequency {freq} MHz for SSID {ssid}, skipping.")
                    continue

                if expected_band == "2.4GHz":
                    phy_type = "802.11n"
                    channel_width = "20MHz"
                elif expected_band == "5GHz":
                    phy_type = "802.11ac" if "Infra" in mode else "802.11n"
                    channel_width = "80MHz" if phy_type == "802.11ac" else "20MHz"
                else:
                    phy_type = "802.11ax"
                    channel_width = "80MHz"

                rssi = -100 + (signal * 0.5)
                noise_floor = -95.0
                snr = rssi - noise_floor
                last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                network = WiFiNetwork(
                    ssid=ssid,
                    signal=signal,
                    channel=channel,
                    security=security,
                    channel_width=channel_width,
                    bssid=bssid,
                    rssi=rssi,
                    phy_type=phy_type,
                    frequency=freq,
                    mode=mode,
                    snr=snr,
                    last_seen=last_seen,
                    vendor=vendor
                )
                networks.append(network)
                print(f"Added network: SSID {ssid}, Channel: {channel}, Width: {channel_width}, Freq: {freq} MHz, PHY: {phy_type}, Signal: {signal}%, RSSI: {rssi} dBm, Security: {security}, Vendor: {vendor}, BSSID: {bssid}")
        except subprocess.CalledProcessError as e:
            print(f"Error scanning Wi-Fi on Linux: {e}")
        return networks

def get_scanner() -> WiFiScanner:
    system = platform.system()
    if system == "Windows":
        try:
            import pywifi
            print("Using PyWiFiScanner")
            return PyWiFiScanner()
        except ImportError:
            print("pywifi not installed, falling back to netsh scanner")
            return WindowsWiFiScanner()
    elif system == "Darwin":
        return MacWiFiScanner()
    elif system == "Linux":
        return LinuxWiFiScanner()
    raise NotImplementedError(f"Unsupported platform: {system}")