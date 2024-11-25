from datetime import datetime
from typing import Any, Dict, Set, List, Union
import requests
import json


class KismetBase:
    """Base class for Kismet API interactions."""

    def __init__(self, *, api_key: str, url: str):
        """Initialize Kismet base client.

        Args:
            api_key: The Kismet API key
            url: URL where the Kismet server is running
        """
        self.api_key = api_key
        self.url = url if url.endswith('/') else f"{url}/"
        self.cookies = {'KISMET': self.api_key}
        self.headers = {'Content-Type': 'application/json'}

    def _make_request(self, method: str, endpoint: str, json_data: Dict = None) -> requests.Response:
        """Make HTTP request to Kismet API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            json_data: Optional JSON payload for POST requests

        Returns:
            Response object
        """
        url = f"{self.url}{endpoint}"
        response = requests.request(
            method=method,
            url=url,
            cookies=self.cookies,
            headers=self.headers,
            json=json_data
        )
        response.raise_for_status()
        return response

    def check_session(self) -> str:
        """Verify session validity and return auth cookie."""
        response = self._make_request('GET', 'session/check_session')
        return response.headers['Set-Cookie'].split(";")[0]


class KismetWorker(KismetBase):
    """Worker class for retrieving data from Kismet."""

    def get_system_status(self) -> Dict[str, Any]:
        """Get Kismet server status."""
        response = self._make_request('GET', 'system/status.json')
        return response.json()

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Get all alerts from the system."""
        response = self._make_request('GET', 'alerts/all_alerts.json')
        return response.json()

    def get_alert_by_hash(self, identifier: str) -> Dict[str, Any]:
        """Get alert details by hash."""
        if int(identifier) < 0:
            raise ValueError(f"Invalid ID provided: {identifier}")
        response = self._make_request('GET', f'alerts/by-id/{identifier}/alert.json')
        return response.json()

    def get_alert_definitions(self) -> List[Dict[str, Any]]:
        """Get defined alert types."""
        response = self._make_request('GET', 'alerts/definitions.json')
        return response.json()

    def get_recent_devices(self, lookback_seconds: int = 3600) -> List[Dict[str, Any]]:
        """Get devices seen within the specified time period."""
        last_time = int(datetime.now().timestamp()) - lookback_seconds
        response = self._make_request('GET', f'devices/last-time/{last_time}/devices.json')
        return response.json()


class KismetAdmin(KismetBase):
    """Admin class for managing Kismet alerts and configurations."""

    def define_alert(
        self,
        *,
        name: str,
        description: str,
        throttle: str = '10/min',
        burst: str = "1/sec",
        severity: int = 5,
        aclass: str = 'SYSTEM'
    ) -> None:
        """Define a new alert type."""
        command = {
            'name': name,
            'description': description,
            'throttle': throttle,
            'burst': burst,
            'severity': severity,
            'class': aclass
        }
        self._make_request('POST', 'alerts/definitions/define_alert.cmd', json_data=command)

    def raise_alert(self, *, name: str, message: str) -> None:
        """Raise a new alert."""
        command = {
            'name': name,
            'text': message
        }
        self._make_request('POST', 'alerts/raise_alerts.cmd', json_data=command)


class KismetResultsParser:
    """Parser for Kismet results and alerts."""

    SEVERITY = {
        0: {'name': 'INFO', 'description': 'Informational alerts'},
        5: {'name': 'LOW', 'description': 'Low-risk events'},
        10: {'name': 'MEDIUM', 'description': 'Medium-risk events'},
        15: {'name': 'HIGH', 'description': 'High-risk events'},
        20: {'name': 'CRITICAL', 'description': 'Critical security events'}
    }

    TYPES = {
        'DENIAL': 'Possible denial of service attack',
        'EXPLOIT': 'Known fingerprinted exploit attempt',
        'OTHER': 'General alerts',
        'PROBE': 'Probe by known tools',
        'SPOOF': 'Device spoofing attempt',
        'SYSTEM': 'System events'
    }

    @staticmethod
    def get_level_for_severity(level: str) -> int:
        """Convert severity name to numeric level."""
        for int_level, data in KismetResultsParser.SEVERITY.items():
            if data['name'] == level:
                return int_level
        raise ValueError(f"Invalid severity level: {level}")

    @staticmethod
    def parse_alert_definitions(
        alert_definitions: List[Dict[str, str]],
        keys_of_interest: Set[str] = None
    ) -> List[Dict[str, str]]:
        """Parse and filter alert definitions."""
        if keys_of_interest is None:
            keys_of_interest = {
                'kismet.alert.definition.class',
                'kismet.alert.definition.description',
                'kismet.alert.definition.severity',
                'kismet.alert.definition.header'
            }

        return [
            {key.split('.')[-1]: value for key, value in definition.items() if key in keys_of_interest}
            for definition in alert_definitions or []
        ]

    @staticmethod
    def process_alerts(alerts: List[Dict[str, Union[str, int]]]) -> tuple[List[Dict], Dict, Dict]:
        """Process and categorize alerts."""
        if not alerts:
            return [], {}, {}

        processed_alerts = []
        found_severities = {}
        found_types = {}

        for alert in alerts:
            severity = alert['kismet.alert.severity']
            severity_info = KismetResultsParser.SEVERITY[severity]
            aclass = alert['kismet.alert.class']

            found_severities[severity_info['name']] = severity_info['description']
            found_types[aclass] = KismetResultsParser.TYPES[aclass]

            processed_alerts.append({
                'text': alert['kismet.alert.text'],
                'class': aclass,
                'severity': severity_info['name'],
                'hash': alert['kismet.alert.hash'],
                'dest_mac': alert['kismet.alert.dest_mac'],
                'source_mac': alert['kismet.alert.source_mac'],
                'timestamp': datetime.fromtimestamp(alert['kismet.alert.timestamp'])
            })

        return processed_alerts, found_severities, found_types

    @staticmethod
    def anonymize_mac(mac: str) -> str:
        """Anonymize MAC address."""
        vendor = mac.split(':')[:3]
        return f"{':'.join(vendor)}:XX:XX:XX"
