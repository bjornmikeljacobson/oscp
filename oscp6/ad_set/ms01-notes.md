
### Scans

PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy
9595/tcp open  pds - Ivanti?


PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_03-21-22  02:45AM             38100936 ServerSetup-3.9.0.2463.exe
| ftp-syst:
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: oscp.exam
|   DNS_Computer_Name: MS01.oscp.exam
|   DNS_Tree_Name: oscp.exam
|   Product_Version: 10.0.19041
|_  System_Time: 2024-06-20T11:14:35+00:00
|_ssl-date: 2024-06-20T11:15:10+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=MS01.oscp.exam
| Issuer: commonName=MS01.oscp.exam
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-19T11:02:51
| Not valid after:  2024-12-19T11:02:51
| MD5:   33c0:5a80:32b7:e5dc:b30f:6b15:d0fc:580d
|_SHA-1: 6551:e597:4084:b3b9:bb35:744e:f2b8:d9b1:0766:52eb
5040/tcp  open  unknown
7680/tcp  open  tcpwrapped
8080/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
9510/tcp  open  nagios-nsca   Nagios NSCA
9512/tcp  open  unknown
9595/tcp  open  pds?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
51393/tcp open  msrpc         Microsoft Windows RPC


PORT     STATE         SERVICE
123/udp  open|filtered ntp
137/udp  open|filtered netbios-ns
138/udp  open|filtered netbios-dgm
500/udp  open|filtered isakmp
1900/udp open|filtered upnp
3389/udp open|filtered ms-wbt-server
4500/udp open|filtered nat-t-ike
5050/udp open|filtered mmcc
5353/udp open|filtered zeroconf
5355/udp open|filtered llmnr


nikto -h ms01.oscp.exam 80                                                                                                                                                                              took 10s
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          192.168.134.101
+ Target Hostname:    ms01.oscp.exam
+ Target Port:        80
+ Start Time:         2024-06-20 07:14:26 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Server leaks inodes via ETags, header found with file /, fields: 0x2bfe24669c3ed81:0
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server banner has changed from 'Microsoft-IIS/10.0' to 'Microsoft-HTTPAPI/2.0' which may suggest a WAF, load balancer or proxy is in place
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST
+ 6544 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2024-06-20 07:17:40 (GMT-4) (194 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

ENUM4LINUX - next generation (v1.3.3)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... ms01.oscp.exam
[*] Username ......... ''
[*] Random Username .. 'rxdpmtib'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =======================================
|    Listener Scan on ms01.oscp.exam    |
 =======================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =============================================================
|    NetBIOS Names and Workgroup/Domain for ms01.oscp.exam    |
 =============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ===========================================
|    SMB Dialect Check on ms01.oscp.exam    |
 ===========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: false
  SMB 2.02: true
  SMB 2.1: true
  SMB 3.0: true
  SMB 3.1.1: true
Preferred dialect: SMB 3.0
SMB1 only: false
SMB signing required: false

 =============================================================
|    Domain Information via SMB session for ms01.oscp.exam    |
 =============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: MS01
NetBIOS domain name: OSCP
DNS domain: oscp.exam
FQDN: MS01.oscp.exam
Derived membership: domain member
Derived domain: OSCP

 ===========================================
|    RPC Session Check on ms01.oscp.exam    |
 ===========================================
[*] Check for null session
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE
[-] Sessions failed, neither null nor user sessions were possible

 =================================================
|    OS Information via RPC for ms01.oscp.exam    |
 =================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: '2004'
OS build: '19041'
Native OS: not supported
Native LAN manager: not supported
Platform id: null
Server type: null
Server type string: null

[!] Aborting remainder of tests since sessions failed, rerun with valid credentials

Completed after 6.16 seconds


nikto -h ms01.oscp.exam 8080
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          192.168.134.101
+ Target Hostname:    ms01.oscp.exam
+ Target Port:        80
+ Start Time:         2024-06-20 07:14:42 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Server leaks inodes via ETags, header found with file /, fields: 0x2bfe24669c3ed81:0
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server banner has changed from 'Microsoft-IIS/10.0' to 'Microsoft-HTTPAPI/2.0' which may suggest a WAF, load balancer or proxy is in place
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST
+ 6544 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2024-06-20 07:17:57 (GMT-4) (195 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
