# Netskope alerts reporter
## Related documentations
<li/>[Dataexport Netskope documentation](https://docs.netskope.com/en/netskope-help/admin-console/rest-api/rest-api-v2-overview-312207/using-the-rest-api-v2-dataexport-iterator-endpoints/)
<li />[NetskopeSDK](https://pypi.org/project/netskopesdk/)
# Prerequesites
```
pip install netskopesdk
```
## Create this file named "config.ini" and place it into the folder "private"
```
######
###### Make sure you gitignore this file
######
#[Category]
#api = XXX
#url = URL

#To be set
[logging]
file = ../logger-reporter.log
format = %(asctime)s ; %(levelname)s ; %(message)s
level = DEBUG

[params]
NSKP_TOKEN : "<REST-API-TOKEN>"
NSKP_TENANT_HOSTNAME : "<HOSTNAME>"
# Optional param to pass the proxy hosts.
NSKP_PROXIES : {"<PROXY-HOSTS>"}
NSKP_EVENT_TYPE : "<EVENT-TYPE>"
NSKP_ITERATOR_NAME : "<ITERATOR-NAME>"
NSKP_USER_AGENT : "<SPLUNK-TENANT-HOSTNAME>"
```