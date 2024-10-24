import telnetlib
from netmiko import ConnectHandler
import re
from .base import APBase

class HuaweiAC(APBase):
    def connect(self):
            """Connect to the Huawei AP via SSH or Telnet."""
            if self.protocol == 'ssh':
                self.connection = ConnectHandler(
                    device_type='huawei',
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
        """Fetch SSIDs from Huawei AP."""
        # Add the command to get SSIDs for Huawei AP
        if self.protocol == 'ssh':
            output = self.connection.send_command("display wlan ssid")
        elif self.protocol == 'telnet':
            self.connection.write(b"display wlan ssid\n")
            output = self.connection.read_until(b"#").decode('ascii')
        return self._parse_ssid_output(output)

    def _parse_ssid_output(self, output):
        """Helper function to parse SSID from Huawei command output."""
        # Adjust this based on Huawei's actual output
        ssids = []
        for line in output.splitlines():
            if "SSID" in line:
                ssid = line.split()[1]
                ssids.append(ssid)
        return ssids

    def gethosts(self, SSID):
        """Fetch connected hosts for a specific SSID."""
        if self.protocol == 'ssh':
            output = self.connection.send_command(f"display wlan client ssid {SSID}")
        elif self.protocol == 'telnet':
            self.connection.write(f"display wlan client ssid {SSID}\n".encode('ascii'))
            output = self.connection.read_until(b"#").decode('ascii')
        return self._parse_hosts_output(output)