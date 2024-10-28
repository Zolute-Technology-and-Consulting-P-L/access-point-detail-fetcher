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
            self.connection.read_until(b">")
            print("connected")
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
                # Read a chunk of data
                chunk = self.connection.read_very_eager().decode('ascii')
                output += chunk
                
                # If the output contains a pattern like <hostname>, it's the end of the output
                if re.search(r"<[^>]+>", chunk):
                    break
                # If the output contains a pagination prompt (e.g., "--More--"), send a space key to continue
                elif "--More--" in chunk or "---- More ----" in chunk:
                    self.connection.write(b" ")
        ssids = self._parse_vap_output(output)
        HuaweiAC.vap_df = pd.DataFrame(ssids)
        return [{"SSID": vap["SSID"], "ap_id":vap["AP ID"],"ap_mac": vap["AP MAC"], "auth_type": vap["Auth Type"]} for vap in ssids]
    
    def _parse_vap_output(self, output):
        """Helper function to parse VAP output into a list of dictionaries with full VAP details."""
        # Split the output into individual lines
        lines = output.split("\n")
        vaps = []
        pattern = r"(\d+)\s+([\w-]+)\s+(\d+)\s+(\d+)\s+([\da-fA-F-]+)\s+(\w+)\s+([\w/-]+)\s+(\d+)\s+(.+)"
        
        for line in lines:
            match = re.match(pattern, line.strip())
            if match:
                ap_id = match.group(1)
                ap_mac = self._get_ap_mac(ap_id)  # Retrieve AP MAC from the AP DataFrame
                
                # Clean the SSID and Auth Type values
                ssid = match.group(9).strip().replace('\r', '')
                auth_type = match.group(7).strip()
                
                vaps.append({
                    "AP ID": ap_id,
                    "AP Name": match.group(2),
                    "RfID": match.group(3),
                    "WID": match.group(4),
                    "BSSID": match.group(5),
                    "Status": match.group(6),
                    "Auth Type": auth_type,
                    "STA": match.group(8),
                    "SSID": ssid,
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
            output = ''
            while True:
                # Read a chunk of data
                chunk = self.connection.read_very_eager().decode('ascii')
                output += chunk
                
                # If the output contains a pattern like <hostname>, it's the end of the output
                if re.search(r"<[^>]+>", chunk):
                    break
                # If the output contains a pagination prompt (e.g., "--More--"), send a space key to continue
                elif "--More--" in chunk or "---- More ----" in chunk:
                    self.connection.write(b" ")
        
        hosts = self._parse_hosts_output(output)
        HuaweiAC.hosts_df = pd.DataFrame(hosts)
        return [{"mac": host["MAC"], "ip": host["IP"], "ap.mac": host["AP MAC"].replace('-',''), "ssid": host["SSID"]} for host in hosts]

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
            output = ''
            while True:
                # Read a chunk of data
                chunk = self.connection.read_very_eager().decode('ascii')
                output += chunk
                
                # If the output contains a pattern like <hostname>, it's the end of the output
                if re.search(r"<[^>]+>", chunk):
                    break
                # If the output contains a pagination prompt (e.g., "--More--"), send a space key to continue
                elif "--More--" in chunk or "---- More ----" in chunk:
                    self.connection.write(b" ")
        aps = self._parse_ap_output(output)
        HuaweiAC.aps_df = pd.DataFrame(aps)
        return [{"mac": ap["MAC"].replace('-', ''), "ip": ap["IP"],"name":ap["Name"]} for ap in aps]

    def _parse_ap_output(self, output):
        """
        Parse the AP output into a list of dictionaries using dynamic column positions based on the header.
        """
        cleaned_output = self.clean_output(output)
        # Split the output into lines
        lines = cleaned_output.strip().split("\n")

        # Define column names in the order they appear in the header
        column_names = ["ID", "MAC", "Name", "Group", "IP", "Type", "State", "STA", "Uptime", "ExtraInfo"]

        # Identify the header line
        header = None
        header_index = 0
        for index, line in enumerate(lines):
            if all(col_name in line for col_name in column_names):
                header = line
                header_index = index
                break
        
        # If the header is not found, return an empty list
        if not header:
            return []

        # Identify the start positions of each column in the header
        column_positions = {}
        for col_name in column_names:
            col_start = header.find(col_name)
            if col_start != -1:
                column_positions[col_name] = col_start

        # Sort the column names by their start positions
        sorted_columns = sorted(column_positions.items(), key=lambda x: x[1])

        # Determine the column widths
        column_widths = {}
        for i, (col_name, start) in enumerate(sorted_columns):
            end = sorted_columns[i + 1][1] if i + 1 < len(sorted_columns) else len(header)
            column_widths[col_name] = end - start

        # Regex to identify lines that start with a valid ID and MAC format
        valid_line_pattern = r"\d+\s+[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}\s+"

        aps = []
        for line in lines[header_index + 1:]:
            # Skip empty lines or lines that don't match the AP record pattern
            if not re.match(valid_line_pattern, line.strip()):
                print("invalid line: ",repr(line))
                continue

            ap_data = {}
            for i, (col_name, start) in enumerate(sorted_columns):
                # Determine the end position: start of next column or end of line
                end = sorted_columns[i + 1][1] if i + 1 < len(sorted_columns) else None
                value = line[start:end].strip() if end else line[start:].strip()
                ap_data[col_name] = value if value != '-' else None
            
            aps.append(ap_data)

        return aps

    def clean_output(self,output):
        # Remove ANSI escape sequences (like '\x1b[42D')
        output = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', output)
        # Remove carriage returns and other unwanted control characters
        output = re.sub(r'[\r\n\t]+', '\n', output)  # Replace multiple line breaks/tabs with a single newline
        output = re.sub(r'[^\x20-\x7E\n]+', '', output)  # Remove non-printable characters except newline
        output = re.sub(r'---- More ----', '', output)
        return output