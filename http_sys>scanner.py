#cypherg
#http.sys_scanner
#scans for MS15-034

import argparse
import requests
import socket 
import ssl
import OpenSSL
#-------------------------------------------------------------------------------------------------#
#requests.packages.urllib3.disable_warnings()
try_http = 'http://'
try_SSL = 'https://'
target_count = 0  
total_vuln = 0
http_ports = ['80','8008','8080','8088']   #known ports that actively refuse SSL
https_ports = ['443','8443'] #know ports that actively refuse plain HTTP
custom_headers = {'Range': 'bytes=0-18446744073709551615'}
#-------------------------------------------------------------------------------------------------#
parser = argparse.ArgumentParser(description='Process IP:PORT file') 
parser.add_argument('ipfile', type=argparse.FileType('r'))
args = parser.parse_args() #reads first arg as 'ipfile' and treats it as a file 
host_list = args.ipfile.readlines()
total_targets = len(host_list)
args.ipfile.close()
#-------------------------------------------------------------------------------------------------#
def makeConnection(schema, testip):
    try:
        r = requests.get(schema + testip, verify=False, allow_redirects=True, timeout=4.00, headers=custom_headers)  #makes HTTP connections, gets data   
    	return r
    except:
	pass
        
#--------------------------------------------------------------------------------------------------#
print #print a blank line to the console for readability
for testip in host_list: #master loop. iterates through all ip:port combinations try http first then try ssl
    target_count +=1
    testip = testip.strip()
    ip = testip.split(':', 1)[0].strip() #gets ip address from ip:port
    port = testip.split(':', 1)[1].strip() #gets port number from ip:port
#--------------------------------------------------------------------------------------------------#

    if port not in https_ports: #checks if port strictly requires http or https schema
        schema = try_http
        r = makeConnection(schema, testip)
	try:	
		if '416' in str(r.status_code):
			total_vuln +=1
                	print "{} is vulnerable to http.sys MS15-034 | Target {} of {} | Total vuln:{}".format(testip, target_count, total_targets, total_vuln)
	except:
		pass
    if port not in http_ports:
        schema = try_SSL 
        r = makeConnection(schema, testip)
	try:    
                if '416' in str(r.status_code):
                        total_vuln +=1
                        print "{} is vulnerable to http.sys MS15-034 | Target {} of {} | Total vuln:{}".format(testip, target_count, total_targets, total_vuln)
        except:
		pass
#--------------------------------------------------------------------------------------------------#
