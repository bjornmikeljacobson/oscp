
SMB null session - access denied


IIS server is probably exploitable by uploading a malicious web.config file

nikto -h ms01.oscp.exam:8000
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.225.153
+ Target Hostname:    ms01.oscp.exam
+ Target Port:        8000
+ Start Time:         2024-06-05 14:50:22 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ /: Retrieved x-powered-by header: ASP.NET.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /FFEK9dzr.ashx: Retrieved x-aspnet-version header: 4.0.30319.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ 8046 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2024-06-05 14:57:30 (GMT-4) (428 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


 $ whatweb -a 4 http://ms01.oscp.exam:8000 -v --color='always'                                                                                                                                          
WhatWeb report for http://ms01.oscp.exam:8000
Status    : 200 OK
Title     : IIS Windows
IP        : 192.168.225.153
Country   : RESERVED, ZZ

Summary   : HTTPServer[Microsoft-IIS/10.0], Matomo, Microsoft-IIS[10.0], X-Powered-By[ASP.NET]

Detected Plugins:
[ HTTPServer ]
        HTTP server header string. This plugin also attempts to
        identify the operating system from the server header.

        String       : Microsoft-IIS/10.0 (from server string)

[ Matomo ]
        Matomo is the leading open alternative to Google Analytics
        that gives you full control over your data. Matomo lets you
        easily collect data from websites, apps & the IoT and
        visualise this data and extract insights. Privacy is
        built-in. Matomo was formerly known as Piwik, and is
        developed in PHP.

        Aggressive function available (check plugin file or details).
        Google Dorks: (1)
        Website     : https://matomo.org

[ Microsoft-IIS ]
        Microsoft Internet Information Services (IIS) for Windows
        Server is a flexible, secure and easy-to-manage Web server
        for hosting anything on the Web. From media streaming to
        web application hosting, IIS's scalable and open
        architecture is ready to handle the most demanding tasks.

        Version      : 10.0
        Website     : http://www.iis.net/

[ X-Powered-By ]
        X-Powered-By HTTP header

        String       : ASP.NET (from x-powered-by string)

HTTP Headers:
        HTTP/1.1 200 OK
        Content-Type: text/html
        Last-Modified: Thu, 10 Nov 2022 11:53:10 GMT
        Accept-Ranges: bytes
        ETag: "921b41fbf4d81:0"
        Server: Microsoft-IIS/10.0
        X-Powered-By: ASP.NET
        Date: Wed, 05 Jun 2024 19:07:21 GMT
        Connection: close
        Content-Length: 696

 $ enum4linux-ng -A ms01.oscp.exam
ENUM4LINUX - next generation (v1.3.3)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... ms01.oscp.exam
[*] Username ......... ''
[*] Random Username .. 'irwpvtbq'
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

Completed after 6.92 seconds

