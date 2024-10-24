from ap_models.cisco_ap import CiscoAP
from ap_models.huawei_ap import HuaweiAP
from ap_models.unifi_ap import UniFiAP
from ap_models.huawei_ac import HuaweiAC

class APManager:
    def __init__(self):
        self.model_mapping = {
            'cisco': CiscoAP,
            'huawei': HuaweiAP,
            'unifi': UniFiAP,
            'huaweiac':HuaweiAC
        }

    def create_ap(self, model, username, password, ip, port, protocol):
        """Dynamically create an AP instance based on the model."""
        if model.lower() not in self.model_mapping:
            raise ValueError(f"Model '{model}' not supported.")
        return self.model_mapping[model.lower()](model, username, password, ip, port, protocol)
