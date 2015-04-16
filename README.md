# http.sys scanner
https://isc.sans.edu/forums/diary/MS15034+HTTPsys+IIS+DoS+And+Possible+Remote+Code+Execution+PATCH+NOW/19583/

This is a quick and dirty script; dirrrtier than Christina Aguilera.

Scans for MS15-034: HTTP.sys vuln by sending a (safe) poisoned HTTP header "Range: bytes=0-18446744073709551615" and then checks the server's response status code for '416'.

This module takes one argument, the path to a new-line delimited IP:PORT file.

If the protocol is known to be HTTP or HTTPS only, only that schemas will be used.
If the protocol schema is unknown (e.g. port 8900 or 10000), both will be attempted.

If the target is vuln, a string is print to stout.
If the target fails to send a '416' response for any reason, no output is displayed.

python http_sys_scanner.py webservers.txt

![alt tag](http://i.imgur.com/BTs9IvG.png)

By the power of Queen B, scan, scan, scan!

![alt tag](http://i.imgur.com/qwXg9vW.gif)
