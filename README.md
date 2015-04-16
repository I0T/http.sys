# http.sys scanner
https://isc.sans.edu/forums/diary/MS15034+HTTPsys+IIS+DoS+And+Possible+Remote+Code+Execution+PATCH+NOW/19583/

Scans for MS15-034: HTTP.sys vuln by sending a (safe) poisoned HTTP header "Range: bytes=0-18446744073709551615" and then checks the server's response status code for '416'.

This module takes one arguement, the path to a new-line delimited IP:PORT file
If the protocol is known to be HTTP or HTTPS only, only that schemas will be used.
If the protocol schema is unknown (e.g. port 8900 or 10000), both will be attempted.

If the target is vuln, a string is print to stout.
If the target fails to send a '416' response for any reason, no output is displayed.

![alt tag](http://i.imgur.com/GVjxrAP.png)

![alt tag](http://i.imgur.com/qwXg9vW.gif)
