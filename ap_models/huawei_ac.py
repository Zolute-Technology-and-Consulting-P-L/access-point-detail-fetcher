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
    discovered_ssid_df = pd.DataFrame()

    def connect(self):
        """Connect to the Huawei AP via SSH or Telnet with error handling."""
        try:
            if self.protocol == 'ssh':
                try:
                    self.connection = ConnectHandler(
                        device_type='huawei',
                        ip=self.ip,
                        username=self.username,
                        password=self.password,
                        port=self.port
                    )
                except Exception as e:
                    raise ConnectionError(f"Unexpected error during SSH connection: {e}")
            elif self.protocol == 'telnet':
                try:
                    self.connection = telnetlib.Telnet(self.ip, self.port)
                    self.connection.read_until(b"Username:")
                    self.connection.write(self.username.encode('ascii') + b"\n")
                    self.connection.read_until(b"Password:")
                    self.connection.write(self.password.encode('ascii') + b"\n")
                    self.connection.read_until(b">")
                    print("Connected via Telnet")
                except Exception as e:
                    raise ConnectionError(f"Telnet connection failed: {e}")
            else:
                raise ValueError("Unsupported protocol: use 'ssh' or 'telnet'")
        
        except ConnectionError as ce:
            print(f"ConnectionError: {ce}")
            raise  # Re-raise the exception to propagate it further
        #if connection is scucesful then lets get all ap detail and create ap dataframe.

        self.getAps()

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
        ssids = self._parse_tabular_output(output=output,columns=["AP ID", "AP name", "RfID", "WID", "BSSID", "Status", "Auth type", "STA", "SSID"],valid_line_pattern = r"^\d+\s+[\w-]+.+")
        HuaweiAC.vap_df = pd.DataFrame(ssids)
    


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
        
        hosts = self._parse_tabular_output(output=output,columns=["STA MAC",          "AP ID", "Ap name",        "Rf/WLAN",  "Band",  "Type",  "Rx/Tx",      "RSSI",  "VLAN",  "IP address",       "SSID"],valid_line_pattern = r"^[\w-]+\s+\d+.+")
        HuaweiAC.hosts_df = pd.DataFrame(hosts)
    
    def getDiscoveredHosts(self,ap_id):
        """Fetch all hosts and update the DataFrame; return a list of dictionaries with mac, ip, ap.mac, and ssid."""
        command = f"display ap around-ssid-list ap-id {ap_id}"
        if self.protocol == 'ssh':
            output = self.connection.send_command(command)
        elif self.protocol == 'telnet':
            self.connection.write(f"{command}\n".encode('ascii'))
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
        
        ssids = self._parse_discovered_ssids(output=output)
        HuaweiAC.discovered_ssid_df = pd.DataFrame(ssids)


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
        aps = self._parse_tabular_output(output=output,columns=["ID", "MAC", "Name", "Group", "IP", "Type", "State", "STA", "Uptime", "ExtraInfo"],valid_line_pattern = r"^\d+\s+[\w-]+.+")
        HuaweiAC.aps_df = pd.DataFrame(aps)

    
    def clean_output(self,output):
        # Remove ANSI escape sequences (like '\x1b[42D')
        output = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', output)
        # Remove carriage returns and other unwanted control characters
        output = re.sub(r'[\r\n\t]+', '\n', output)  # Replace multiple line breaks/tabs with a single newline
        output = re.sub(r'[^\x20-\x7E\n]+', '', output)  # Remove non-printable characters except newline
        output = re.sub(r'---- More ----', '', output)
        return output
    
    def _parse_tabular_output(self, output,columns,valid_line_pattern):
        """
        Parse the AP output into a list of dictionaries using dynamic column positions based on the header.
        """
        cleaned_output = self.clean_output(output)
        # Split the output into lines
        lines = [line.strip() for line in cleaned_output.strip().split("\n")]

        # Define column names in the order they appear in the header
        column_names = columns

        # Identify the header line
        # Try to locate the header line by checking for the presence of any column names
        header = None
        header_index = 0
        for index, line in enumerate(lines):
                if all(re.search(rf'\b{col_name}\b', line) for col_name in column_names):
                    print("Detected header:", repr(line))
                    header = line
                    header_index = index
                    break

        # If the header is not found, return an empty list
        if not header:
            print("Header not found in the output.")
            return []

        # Identify the exact start positions of each column in the header
        column_positions = {}
        for col_name in column_names:
            match = re.search(rf'\b{col_name}\b', header)
            if match:
                column_positions[col_name] = match.start()

        # Sort the columns by their start positions
        sorted_columns = sorted(column_positions.items(), key=lambda x: x[1])

        
        # Determine the column widths
        column_widths = {}
        for i, (col_name, start) in enumerate(sorted_columns):
            end = sorted_columns[i + 1][1] if i + 1 < len(sorted_columns) else len(header)
            column_widths[col_name] = end - start
        

        # Regex to identify lines that start with a valid ID and MAC format
        

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
    
    def _parse_discovered_ssids(self,output):
        """Parse and return a list of unique SSIDs from the provided output text."""
        lines = [line.strip() for line in output.splitlines()]  # Clean whitespace from each line
        ssids = []
        collecting_ssids = False
        hyphen_pattern = re.compile(r"^-+$")

        i = 0
        while i < len(lines):
            line = lines[i]

            # Check for the three-line pattern to start collecting SSIDs
            if (
                hyphen_pattern.match(line) and i + 2 < len(lines) 
                and lines[i + 1] == "SSID" and hyphen_pattern.match(lines[i + 2])
            ):
                collecting_ssids = True
                i += 3  # Skip the "SSID" and following hyphen line to start collecting actual SSID names
                continue

            # Stop collecting if another hyphen line appears
            elif hyphen_pattern.match(line) and collecting_ssids:
                collecting_ssids = False

            # Collect SSIDs if we are in the SSID section
            elif collecting_ssids and line:
                ssids.append(line)

            i += 1

        # Use set to remove duplicates while preserving the original order
        unique_ssids = list(dict.fromkeys(ssids))
        ssid_data = [{"SSID": ssid} for ssid in unique_ssids]
        return ssid_data