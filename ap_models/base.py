class APBase:
    def __init__(self, model, username, password, ip, port, protocol):
        self.model = model
        self.username = username
        self.password = password
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.connection = None

    def connect(self):
        """Connect to the device based on protocol (SSH/Telnet)."""
        raise NotImplementedError("This method should be implemented by subclasses")

    def getSSID(self):
        """Fetch all SSIDs from the AP."""
        raise NotImplementedError("This method should be implemented by subclasses")

    def gethosts(self, SSID):
        """Fetch all hosts for a specific SSID."""
        raise NotImplementedError("This method should be implemented by subclasses")

