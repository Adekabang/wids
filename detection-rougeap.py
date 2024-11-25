from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json
import websockets
import asyncio
from requests.exceptions import HTTPError, RequestException
from kismet import KismetAdmin, KismetWorker


@dataclass
class KismetConfig:
    server: str
    api_token: str
    base_url: str
    websocket_url: str = None

    @classmethod
    def from_auth_info(cls, server: str, token: str) -> 'KismetConfig':
        return cls(
            server=server,
            api_token=token,
            base_url=f"http://{server}",
            websocket_url=f"ws://{server}/eventbus/events.ws"
        )


class SSIDManager:
    def __init__(self, ssid_file: Path):
        self.ssid_file = ssid_file

    def load(self) -> Tuple[Dict[str, List[str]], bool]:
        try:
            with open(self.ssid_file) as f:
                mac_to_ssid = json.load(f)
                return mac_to_ssid, any(ssids for ssids in mac_to_ssid.values())
        except FileNotFoundError:
            default_map = {'routerlabs': [], 'routerlabs_5Ghz': []}
            self.save(default_map)
            return default_map, False

    def save(self, mac_to_ssid: Dict[str, List[str]]) -> None:
        with open(self.ssid_file, 'w') as f:
            json.dump(mac_to_ssid, f, indent=4)


class MessageParser:
    @staticmethod
    def parse_wifi_message(message: str) -> Tuple[Optional[str], Optional[str]]:
        if "advertising SSID" not in message:
            return None, None
        
        words = message.split()
        try:
            mac_index = words.index("device") + 1
            mac = words[mac_index]
            ssid = message.split("'")[1]
            return mac, ssid
        except (ValueError, IndexError):
            return None, None


class WebSocketClient:
    def __init__(self, uri: str, api_token: str):
        self.uri = uri
        self.api_token = api_token

    async def connect(self):
        uri_with_auth = f"{self.uri}?KISMET={self.api_token}"
        return await websockets.connect(uri_with_auth)

    @staticmethod
    async def subscribe_all(websocket) -> None:
        await websocket.send(json.dumps({"SUBSCRIBE": "*"}))


class KismetMonitor:
    def __init__(self, config: KismetConfig, ssid_file: str = "MacAddressToSSID.json"):
        self.config = config
        self.ssid_manager = SSIDManager(Path(ssid_file))
        self.kismet_admin = KismetAdmin(api_key=config.api_token, url=config.base_url)
        self.worker = KismetWorker(api_key=config.api_token, url=config.base_url)
        self.message_parser = MessageParser()
        self.websocket_client = WebSocketClient(config.websocket_url, config.api_token)

    def alert_new_device(self, ssid_name: str, fake_mac_address: str) -> None:
        try:
            self.kismet_admin.raise_alert(
                name='APSPOOF',
                message=f"Fake MAC Address detected: {fake_mac_address} announce SSID: {ssid_name}"
            )
            print(f"New device detected: {ssid_name} {fake_mac_address}")
        except HTTPError:
            print(f"Alert failed for device: {ssid_name} {fake_mac_address}")

    async def handle_message(self, message: str, mac_to_ssid: Dict[str, List[str]], alert_enabled: bool) -> None:
        mac, ssid = self.message_parser.parse_wifi_message(message)
        if mac and ssid and ssid in mac_to_ssid:
            if mac not in mac_to_ssid[ssid] and alert_enabled:
                self.alert_new_device(ssid, mac)
                print(f"Unknown MAC address with listed SSID: {ssid} {mac}")
                print(f"Message: {message}")

    async def monitor_events(self) -> None:
        mac_to_ssid, alert_enabled = self.ssid_manager.load()
        
        async with await self.websocket_client.connect() as websocket:
            print("Connected to Kismet WebSocket")
            await self.websocket_client.subscribe_all(websocket)
            print("Subscribed to all events")

            while True:
                try:
                    message = await websocket.recv()
                    data = json.loads(message)
                    
                    if "MESSAGE" in data:
                        message_text = data["MESSAGE"]["kismet.messagebus.message_string"]
                        await self.handle_message(message_text, mac_to_ssid, alert_enabled)
                except websockets.exceptions.ConnectionClosed:
                    print("WebSocket connection closed, attempting to reconnect...")
                    break
                except Exception as e:
                    print(f"Error processing message: {e}")

    async def run(self) -> None:
        while True:
            try:
                self.worker.check_session()
                await self.monitor_events()
            except Exception as e:
                print(f"Error in monitor loop: {e}")
                await asyncio.sleep(5)

    def start(self) -> None:
        asyncio.run(self.run())


def main() -> None:
    from auth_info import kismet_server, kismet_api_token
    
    config = KismetConfig.from_auth_info(kismet_server, kismet_api_token)
    monitor = KismetMonitor(config)
    monitor.start()


if __name__ == "__main__":
    main()
