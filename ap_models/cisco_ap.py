import telnetlib
from netmiko import ConnectHandler
import re
from .base import APBase

class CiscoAP(APBase):
    def connect(self):
        """Connect to the Cisco AP via SSH or Telnet."""
        if self.protocol == 'ssh':
            self.connection = ConnectHandler(
                device_type='cisco_ios',
                ip=self.ip,
                username=self.username,
                password=self.password,
                port=self.port
            )
        elif self.protocol == 'telnet':
            self.connection = telnetlib.Telnet(self.ip, self.port)
            self.connection.read_until(b"Username:")
            self.connection.write(self.username.encode('ascii') + b"\n")
            self.connection.read_until(b"Password:")
            self.connection.write(self.password.encode('ascii') + b"\n")
        else:
            raise ValueError("Unsupported protocol: use 'ssh' or 'telnet'")

    def getSSID(self):
        """Fetch SSIDs from Cisco AP."""
        if self.protocol == 'ssh':
            output = self.connection.send_command("show wlan summary")
        elif self.protocol == 'telnet':
            self.connection.write(b"show wlan summary\n")
            output = self.connection.read_until(b"#").decode('ascii')
        
        # Parse output to extract SSIDs (this part depends on the actual output format)
        ssids = self._parse_ssid_output(output)
        return ssids

    def _parse_ssid_output(self, output):
        """Helper function to parse SSID from command output."""
        ssids = []
        for line in output.splitlines():
            if "SSID" in line:
                ssid = line.split()[1]  # Adjust based on actual output format
                ssids.append(ssid)
        return ssids

    def gethosts(self, SSID):
        """Fetch connected hosts for a specific SSID using regex."""
        if self.protocol == 'ssh':
            output = self.connection.send_command(f"show dot11 associations {SSID}")
        elif self.protocol == 'telnet':
            self.connection.write(f"show dot11 associations {SSID}\n".encode('ascii'))
            output = self.connection.read_until(b"#").decode('ascii')
        
        # Parse output to get hosts for the given SSID
        return self._parse_hosts_output(output)

    def _parse_hosts_output(self, output):
        """Helper function to parse hosts from command output using regex."""
        hosts = []
        
        # Regex pattern to match MAC and IP addresses (adjust based on actual format)
        mac_ip_regex = re.compile(r"(\w{4}\.\w{4}\.\w{4})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        for line in output.splitlines():
            match = mac_ip_regex.search(line)
            if match:
                mac_address = match.group(1)
                ip_address = match.group(2)
                hosts.append({"mac_address": mac_address, "ip_address": ip_address})

        return hosts
