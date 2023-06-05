## Temporarily block an IP address due to its abusive level

### As Cisco FTD has no functionality to block IP temporarily, I have written a Python-Flask project to temporary block IP addredd via Cisco SecureX API 

##### Here is possible to add IP address by its abusive percentage( 0-25% - 1 Hour, 25-50% - 1 day, 50-75 - 1 hour, 75-100% - 24 hour ) or you can select Auto and program will automatically define percentage via [AbuseIPDB](https://www.abuseipdb.com/).

#### You can block, unblock and check blocked IP addresses list. Here I use job and Robot which checks if time expired or not. If time is up IP address removes(unblocks) from the list. 

#### Request sends to AbuseIPDB via its API and IP percentage defines automatically.

![](assets/images/abuseipdb.png)

#### To achieve this you need to create workflow. Below workflow is default on Cisco SecureX platform

![](assets/images/image.jpg)

For the more details you can check the full documentation for the [Triggering via Threat Response API](https://ciscosecurity.github.io/sxo-05-security-workflows/workflows/response/tr-api)
