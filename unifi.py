import sdks.unifiapi as us
c = us.controller(endpoint='https://192.168.1.200:8443', username='', password='ubnt', verify=False)
s = c.sites['default']()
s.devices()