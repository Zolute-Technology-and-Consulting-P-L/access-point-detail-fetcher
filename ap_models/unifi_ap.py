import requests
from requests.exceptions import HTTPError
from .base import APBase

class UniFiAP(APBase):
    def __init__(self, model, username, password, ip, port, protocol='https', use_proxy_network=False):
        """
        Initialize the UniFiAP class.
        
        :param use_proxy_network: Set to True for UDM/UDM-Pro devices that need /proxy/network prefix
        """
        super().__init__(model, username, password, ip, port, protocol)
        self.base_url = f"{protocol}://{ip}:{port}/"
        self.use_proxy_network = use_proxy_network
        # Use /api/auth/login for UDM devices
        self.login_endpoint = "/api/auth/login" if use_proxy_network else "/api/login"
        self.api_prefix = "/proxy/network" if use_proxy_network else ""
        self.session = requests.Session()

    def connect(self):
        """Authenticate to the UniFi Controller using the appropriate API."""
        login_url = f"{self.base_url}{self.login_endpoint}"
        credentials = {
            "username": self.username,
            "password": self.password,
            "remember": True
        }

        headers = {
            "Content-Type": "application/json"
        }

        try:
            response = self.session.post(login_url, json=credentials, headers=headers, verify=False)
            response.raise_for_status()  # Raise exception for HTTP errors
            print("Connected to UniFi Controller.")
        except HTTPError as http_err:
            raise Exception(f"Failed to connect to UniFi Controller: {http_err}")
        except Exception as err:
            raise Exception(f"An unexpected error occurred: {err}")

    def getSites(self):
        """Fetch the list of sites from the UniFi Controller."""
        sites_url = f"{self.base_url}{self.api_prefix}/api/self/sites"
        try:
            response = self.session.get(sites_url, verify=False)
            response.raise_for_status()
            sites = self._parse_sites_output(response.json())
            return sites
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get sites: {e}")

    def _parse_sites_output(self, data):
        """Helper function to parse sites from the API output."""
        sites = [{ "name": site['name'], "desc": site['desc'] } for site in data['data']]
        return sites

    def getSSID(self, site):
        """Fetch SSIDs (WLANs) from a specific site."""
        ssid_url = f"{self.base_url}{self.api_prefix}/api/s/{site}/rest/wlanconf"
        try:
            response = self.session.get(ssid_url, verify=False)
            response.raise_for_status()
            ssids = self._parse_ssid_output(response.json())
            return ssids
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get SSIDs for site '{site}': {e}")

    def _parse_ssid_output(self, data):
        """Helper function to parse SSID from UniFi API output."""
        ssids = [item['name'] for item in data['data']]
        return ssids

    def gethosts(self, site, SSID):
        """Fetch connected hosts for a specific SSID on a specific site."""
        clients_url = f"{self.base_url}{self.api_prefix}/api/s/{site}/stat/sta"
        try:
            response = self.session.get(clients_url, verify=False)
            response.raise_for_status()
            hosts = self._parse_hosts_output(response.json(), SSID)
            return hosts
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get hosts for SSID '{SSID}' in site '{site}': {e}")

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
        """Fetch all connected hosts across all SSIDs in all sites."""
        sites = self.getSites()
        all_hosts = {}

        for site in sites:
            ssids = self.getSSID(site['name'])
            for ssid in ssids:
                all_hosts[f"{site['desc']} - {ssid}"] = self.gethosts(site['name'], ssid)

        return all_hosts
