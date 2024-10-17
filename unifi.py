import unifiapi
c = unifiapi.controller(endpoint='https://192.168.1.200:8443', username='', password='ubnt', verify=False)
s = c.sites['default']()
s.devices()