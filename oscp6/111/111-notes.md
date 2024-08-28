https://github.com/openwall/john/blob/bleeding-jumbo/run/keychain2john.py
https://hashcat.net/forum/thread-10129.html

^[1;34mStandard Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:38:32 2024 as: nmap -v -Pn -oN 192.168.134.111-std.nmap 192.168.134.111
Nmap scan report for 192.168.134.111
Host is up (0.026s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy

# Nmap done at Thu Jun 20 13:38:38 2024 -- 1 IP address (1 host up) scanned in 6.13 seconds

[1;34mFull TCP Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:38:32 2024 as: nmap -v -Pn -p- -A -oN 192.168.134.111-full-tcp.nmap 192.168.134.111
Nmap scan report for 192.168.134.111
Host is up (0.030s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd              
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Home
|_http-generator: Nicepage 4.16.0, nicepage.com
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: OSCP
|   DNS_Computer_Name: OSCP
|   Product_Version: 10.0.19041
|_  System_Time: 2024-06-20T17:41:04+00:00
| ssl-cert: Subject: commonName=OSCP
| Issuer: commonName=OSCP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-19T11:02:24
| Not valid after:  2024-12-19T11:02:24
| MD5:   678e:e125:a9c9:1dc0:097f:d1ea:7c62:40ef
|_SHA-1: eedc:16ca:8300:547a:7950:a514:f250:57f8:028e:2555
|_ssl-date: 2024-06-20T17:41:34+00:00; 0s from scanner time.
7680/tcp open  pando-pub?
8080/tcp open  http          Microsoft IIS httpd 10.0
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows XP SP3 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   30.52 ms 192.168.49.1
2   31.01 ms 192.168.134.111

# Nmap done at Thu Jun 20 13:41:34 2024 -- 1 IP address (1 host up) scanned in 182.45 seconds

[1;34mStandard UDP Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:38:32 2024 as: nmap -v -Pn -sU -oN 192.168.134.111-udp 192.168.134.111
Nmap scan report for 192.168.134.111
Host is up.
All 1000 scanned ports on 192.168.134.111 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

# Nmap done at Thu Jun 20 13:41:53 2024 -- 1 IP address (1 host up) scanned in 201.22 seconds


#### Todo
 - []

#### Tech Stack 
IIS 10.0
Nicepage 4.16.0
Website not using wordpress/joomla


Port 21 - Can connect anonymously but ls command times out
Port 80/8080: 
IIS web server 
Nikto returns no results
Nothing significant from dirsearch
