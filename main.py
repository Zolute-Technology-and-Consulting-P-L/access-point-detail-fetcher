from ap_manager import APManager

# Initialize the AP manager
ap_manager = APManager()

# Create an AP instance based on model
model = "cisco"  # or "huawei", depending on the AP you're connecting to
username = "your_username"
password = "your_password"
ip = "192.168.1.1"
port = 22
protocol = "ssh"  # or "telnet"

ap = ap_manager.create_ap(model, username, password, ip, port, protocol)

# Connect to the AP
ap.connect()

# Get SSIDs
ssids = ap.getSSID()
print(f"SSIDs: {ssids}")

# Get hosts for a specific SSID
for ssid in ssids:
    hosts = ap.gethosts(ssid)
    print(f"Hosts for SS
