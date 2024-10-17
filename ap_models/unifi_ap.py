import requests
from .base import APBase

class UniFiAP(APBase):
    def __init__(self, model, username, password, ip, port, protocol='https'):
        super().__init__(model, username, password, ip, port, protocol)
        self.base_url = f"{protocol}://{ip}:{port}/"
        self.session = requests.Session()

    def connect(self):
        """Authenticate to the UniFi Controller using the API."""
        login_url = f"{self.base_url}api/login"
        credentials = {
            "username": self.username,
            "password": self.password
        }
        try:
            response = self.session.post(login_url, json=credentials, verify=False)
            response.raise_for_status()
            print("Connected to UniFi Controller.")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to connect to UniFi Controller: {e}")

    def getSSID(self):
        """Fetch SSIDs from UniFi Controller."""
        ssid_url = f"{self.base_url}api/s/default/rest/wlanconf"
        try:
            response = self.session.get(ssid_url, verify=False)
            response.raise_for_status()
            ssids = self._parse_ssid_output(response.json())
            return ssids
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get SSIDs: {e}")

    def _parse_ssid_output(self, data):
        """Helper function to parse SSID from UniFi API output."""
        ssids = [item['name'] for item in data['data']]
        return ssids

    def gethosts(self, SSID):
        """Fetch connected hosts for a specific SSID."""
        clients_url = f"{self.base_url}api/s/default/stat/sta"
        try:
            response = self.session.get(clients_url, verify=False)
            response.raise_for_status()
            hosts = self._parse_hosts_output(response.json(), SSID)
            return hosts
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get hosts: {e}")

    def _parse_hosts_output(self, data, ssid):
        """Helper function to parse hosts from UniFi API output."""
        hosts = []
        for client in data['data']:
            if client['essid'] == ssid:
                mac_address = client['mac']
                ip_address = client.get('ip', 'Unknown')  # Not all clients may have an IP
                hosts.append({"mac_address": mac_address, "ip_address": ip_address})
        return hosts

    def getallHosts(self):
        """Fetch all connected hosts across all SSIDs."""
        ssids = self.getSSID()
        all_hosts = {}
        for ssid in ssids:
            all_hosts[ssid] = self.gethosts(ssid)
        return all_hosts
