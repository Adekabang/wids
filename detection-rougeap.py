from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple
import json
from requests.exceptions import HTTPError, RequestException
from kismet import KismetAdmin, KismetWorker

@dataclass
class KismetConfig:
    """Configuration for Kismet connection."""
    server: str
    api_token: str
    base_url: str

    @classmethod
    def from_auth_info(cls, server: str, token: str) -> 'KismetConfig':
        """Create config from server and token."""
        return cls(
            server=server,
            api_token=token,
            base_url=f"http://{server}"
        )


class KismetMonitor:
    """Monitor for Kismet network devices."""

    def __init__(self, config: KismetConfig, ssid_file: str = "MacAddressToSSID.json"):
        """Initialize monitor with config and SSID mapping file."""
        self.config = config
        self.ssid_file = Path(ssid_file)
        self.kismet_admin = KismetAdmin(
            api_key=config.api_token,
            url=config.base_url
        )
        self.worker = KismetWorker(
            api_key=config.api_token,
            url=config.base_url
        )

    def load_mac_to_ssid_map(self) -> Tuple[Dict[str, List[str]], bool]:
        """Load MAC to SSID mapping from file."""
        try:
            with open(self.ssid_file) as f:
                mac_to_ssid = json.load(f)
                alert_enabled = any(ssids for ssids in mac_to_ssid.values())
                return mac_to_ssid, alert_enabled
        except FileNotFoundError:
            print("Creating new MAC Address to SSID mapping file")
            default_map = {'routerlabs': [], 'routerlabs_5Ghz': []}
            self.save_mac_to_ssid_map(default_map)
            return default_map, False

    def save_mac_to_ssid_map(self, mac_to_ssid: Dict[str, List[str]]) -> None:
        """Save MAC to SSID mapping to file."""
        with open(self.ssid_file, 'w') as f:
            json.dump(mac_to_ssid, f, indent=4)

    def alert_new_device(self, ssid_name: str, fake_mac_address: str) -> None:
        """Send alert for new device detection."""
        try:
            self.kismet_admin.raise_alert(
                name='APSPOOF',
                message=f"Fake MAC Address detected: {fake_mac_address} announce SSID: {ssid_name}"
            )
        except HTTPError:
            print(f"Alert failed for device: {ssid_name} {fake_mac_address}")
        else:
            print(f"New device detected: {ssid_name} {fake_mac_address}")

    def process_devices(self, devices: List[dict], mac_to_ssid: Dict[str, List[str]], alert_enabled: bool) -> None:
        """Process devices and trigger alerts if needed."""
        for device in devices:
            if (device['kismet.device.base.type'] == 'Wi-Fi AP' and
                    device['kismet.device.base.commonname'] in mac_to_ssid):
                
                mac_addr = device['kismet.device.base.macaddr']
                ssid = device['kismet.device.base.commonname']

                if mac_addr not in mac_to_ssid[ssid] and alert_enabled:
                    self.alert_new_device(ssid, mac_addr)
                    print(f"Unknown MAC address with listed SSID: {ssid} {mac_addr}")

    def monitor(self) -> None:
        """Main monitoring loop."""
        try:
            # Verify authentication
            self.worker.check_session()
            print("Authentication successful")

            # Load MAC to SSID mapping
            mac_to_ssid, alert_enabled = self.load_mac_to_ssid_map()

            # Get and process recent devices
            devices = self.worker.get_recent_devices()
            self.process_devices(devices, mac_to_ssid, alert_enabled)

            # Save updated mapping
            self.save_mac_to_ssid_map(mac_to_ssid)

        except RequestException as e:
            print(f"Kismet server communication error: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")


def main():
    """Main entry point."""
    # Import configuration from your auth file
    from auth_info import kismet_server, kismet_api_token
    
    config = KismetConfig.from_auth_info(kismet_server, kismet_api_token)
    monitor = KismetMonitor(config)
    monitor.monitor()


if __name__ == "__main__":
    main()
