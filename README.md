# Netskope alerts reporter
## Related documentations
[Dataexport Netskope documentation](https://docs.netskope.com/en/netskope-help/admin-console/rest-api/rest-api-v2-overview-312207/using-the-rest-api-v2-dataexport-iterator-endpoints/)<br/>
[NetskopeSDK](https://pypi.org/project/netskopesdk/)</li>

## Create this file named config.ini and place it into the folder private
```
######
###### Make sure you gitignore this file
######

#To be set
[logging]
file = ../logger-reporter.log
format = %(asctime)s ; %(levelname)s ; %(message)s
level = DEBUG

[params]
NSKP_TOKEN = 
NSKP_TENANT_HOSTNAME = ###YOUR TENANT###
NSKP_URL = .goskope.com
NSKP_ALERTS_DLP = /api/v2/events/dataexport/alerts/dlp
NSKP_EVENTS_DLP = /api/v2/events/dataexport/events/incident
NSKP_event_alert = /api/v2/events/dataexport/events/alert

# Optional param to pass the proxy hosts.
NSKP_PROXIES = {<PROXY-HOSTS>}
NSKP_EVENT_TYPE = <EVENT-TYPE>
NSKP_ITERATOR_NAME = <ITERATOR-NAME>
NSKP_USER_AGENT = <SPLUNK-TENANT-HOSTNAME>
```


## TODO:

- Bypass steering to allow NS to work at the same time
- Add Argparse

