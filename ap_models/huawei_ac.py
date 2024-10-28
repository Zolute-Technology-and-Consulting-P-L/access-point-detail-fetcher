import telnetlib
from netmiko import ConnectHandler
import re
import pandas as pd
from .base import APBase

class HuaweiAC(APBase):
    # Class variables to hold DataFrames
    aps_df = pd.DataFrame()
    hosts_df = pd.DataFrame()
    vap_df = pd.DataFrame()

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
        """Fetch all SSIDs and update the DataFrame; return a list of dictionaries with SSID, ap.mac, and auth_type."""
        if self.protocol == 'ssh':
            output = self.connection.send_command("display vap all", delay_factor=2)
        elif self.protocol == 'telnet':
            self.connection.write(b"display vap all\n")
            output = ''
            while True:
                chunk = self.connection.read_very_eager().decode('ascii')
                output += chunk
                # Check if the output contains a prompt indicating the end of the command
                if "return" in chunk or "Info" in chunk:
                    break
        
        ssids = self._parse_vap_output(output)
        HuaweiAC.vap_df = pd.DataFrame(ssids)
        return [{"SSID": vap["SSID"], "ap.mac": vap["AP MAC"], "auth_type": vap["Auth Type"]} for vap in ssids]


    def _parse_vap_output(self, output):
        """Helper function to parse VAP output into a list of dictionaries with full VAP details."""
        pattern = r"(\d+)\s+([\w-]+)\s+(\d+)\s+(\d+)\s+([\da-f-]+)\s+(\w+)\s+([\w/-]+)\s+(\d+)\s+(.+)"
        matches = re.findall(pattern, output)

        vaps = []
        for match in matches:
            ap_id = match[0]
            ap_mac = self._get_ap_mac(ap_id)  # Retrieve AP MAC from the AP DataFrame
            vaps.append({
                "AP ID": ap_id,
                "AP Name": match[1],
                "RfID": match[2],
                "WID": match[3],
                "BSSID": match[4],
                "Status": match[5],
                "Auth Type": match[6],
                "STA": match[7],
                "SSID": match[8],
                "AP MAC": ap_mac
            })
        
        return vaps

    def _get_ap_mac(self, ap_id):
        """Helper function to get the AP MAC address using the AP ID from the aps_df DataFrame."""
        if HuaweiAC.aps_df.empty:
            return None
        ap_row = HuaweiAC.aps_df[HuaweiAC.aps_df["ID"] == ap_id]
        if not ap_row.empty:
            return ap_row.iloc[0]["MAC"]
        return None

    def gethosts(self):
        """Fetch all hosts and update the DataFrame; return a list of dictionaries with mac, ip, ap.mac, and ssid."""
        if self.protocol == 'ssh':
            output = self.connection.send_command("display station all")
        elif self.protocol == 'telnet':
            self.connection.write(b"display station all\n")
            output = self.connection.read_until(b"#").decode('ascii')
        
        hosts = self._parse_hosts_output(output)
        HuaweiAC.hosts_df = pd.DataFrame(hosts)
        return [{"mac": host["MAC"], "ip": host["IP"], "ap.mac": host["AP MAC"], "ssid": host["SSID"]} for host in hosts]

    def _parse_hosts_output(self, output):
        """Helper function to parse host output into a list of dictionaries with full host details."""
        pattern = r"([\da-f-]+)\s+(\d+)\s+([\w-]+)\s+([\d/]+)\s+([\w.]+)\s+([\w\d-]+)\s+([\d/-]+)\s+([\d-]+)\s+(\d+)\s+([\d.]+|-)\s+([\w-]+)"
        matches = re.findall(pattern, output)

        hosts = []
        for match in matches:
            ap_id = match[1]
            ap_mac = self._get_ap_mac(ap_id)  # Retrieve AP MAC from the AP DataFrame
            hosts.append({
                "MAC": match[0],
                "AP ID": ap_id,
                "AP Name": match[2],
                "Rf/WLAN": match[3],
                "Band": match[4],
                "Type": match[5],
                "Rx/Tx": match[6],
                "RSSI": match[7],
                "VLAN": match[8],
                "IP": match[9] if match[9] != '-' else None,
                "SSID": match[10],
                "AP MAC": ap_mac
            })
        
        return hosts

    def getAps(self):
        """Fetch Access points and update the DataFrame and return a list of dictionaries with mac and ip."""
        if self.protocol == 'ssh':
            output = self.connection.send_command("display ap all")
        elif self.protocol == 'telnet':
            self.connection.write(f"display ap all\n".encode('ascii'))
            output = self.connection.read_until(b"#").decode('ascii')
        
        aps = self._parse_ap_output(output)
        HuaweiAC.aps_df = pd.DataFrame(aps)
        return [{"mac": ap["MAC"], "ip": ap["IP"]} for ap in aps]

    def _parse_ap_output(self, output):
        """Helper function to parse AP output into a list of dictionaries with full AP details."""
        pattern = r"(\d+)\s+([\da-f-]+)\s+[\w-]+\s+[\w-]+\s+([\d.]+|-)\s+[\w\d]+\s+\w+\s+\d+\s+[\dD:HM\S]+\s+[\w-]+"
        matches = re.findall(pattern, output)

        aps = []
        for match in matches:
            aps.append({
                "ID": match[0],
                "MAC": match[1],
                "IP": match[2] if match[2] != '-' else None
            })
        
        return aps
