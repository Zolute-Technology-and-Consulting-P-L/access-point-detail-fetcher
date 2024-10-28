from ap_manager import APManager

def main():
    # User input or configuration to specify the AP model, credentials, and connection details
    model = input("Enter the AP model (e.g., 'cisco', 'huawei'): ").strip().lower()
    username = input("Enter the username: ").strip()
    password = input("Enter the password: ").strip()
    ip = input("Enter the AP IP address: ").strip()
    port = int(input("Enter the port (default 22 for SSH, 23 for Telnet): ").strip())
    protocol = input("Enter the protocol (ssh or telnet): ").strip().lower()

    # Initialize the AP manager and create an AP instance based on the model
    ap_manager = APManager()

    try:
        # Create the appropriate AP instance
        ap = ap_manager.create_ap(model, username, password, ip, port, protocol)

        # Connect to the AP
        print(f"Connecting to {model} AP at {ip} via {protocol}...")
        ap.connect()

        # Fetch SSIDs
        print("\nFetching SSIDs...")
        ssids = ap.getSSID()
        print(f"SSIDs found: {ssids}")

        # Fetch hosts for each SSID
       

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
