[1;34mStandard Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 09:44:54 2024 as: nmap -v -Pn -oN ms02.oscp.exam-std.nmap ms02.oscp.exam
Nmap scan report for ms02.oscp.exam (172.16.134.102)
Host is up (0.056s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

# Nmap done at Thu Jun 20 09:45:00 2024 -- 1 IP address (1 host up) scanned in 6.78 seconds

[1;34mFull TCP Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 09:44:54 2024 as: nmap -v -Pn -p- -A -oN ms02.oscp.exam-full-tcp.nmap ms02.oscp.exam
Nmap scan report for ms02.oscp.exam (172.16.134.102)
Host is up (0.018s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MS02.oscp.exam
| Issuer: commonName=MS02.oscp.exam
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-24T15:05:39
| Not valid after:  2024-11-23T15:05:39
| MD5:   fd39:73cd:ba9b:792b:dc9c:9a40:ad47:154b
|_SHA-1: 8d20:fb78:0986:c583:fca2:c14e:2265:fcdc:1390:ec14
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: MS02
|   DNS_Domain_Name: oscp.exam
|   DNS_Computer_Name: MS02.oscp.exam
|   DNS_Tree_Name: oscp.exam
|   Product_Version: 10.0.19041
|_  System_Time: 2024-06-20T13:50:20+00:00
|_ssl-date: 2024-06-20T13:51:00+00:00; 0s from scanner time.
5040/tcp  open  unknown
49669/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Uptime guess: 42.198 days (since Thu May  9 05:05:20 2024)
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: Incrementing by 2
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| nbstat: NetBIOS name: MS02, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:8a:d9:d3 (VMware)
| Names:
|   MS02<20>             Flags: <unique><active>
|   MS02<00>             Flags: <unique><active>
|_  OSCP<00>             Flags: <group><active>
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-06-20T13:50:20
|_  start_date: N/A

TRACEROUTE
HOP RTT      ADDRESS
1   18.29 ms ms02.oscp.exam (172.16.134.102)

# Nmap done at Thu Jun 20 09:51:01 2024 -- 1 IP address (1 host up) scanned in 367.37 seconds

[1;34mStandard UDP Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 09:44:54 2024 as: nmap -v -Pn -sU -oN ms02.oscp.exam-udp ms02.oscp.exam
Nmap scan report for ms02.oscp.exam (172.16.134.102)
Host is up (0.088s latency).
Not shown: 999 open|filtered udp ports (no-response)
PORT    STATE SERVICE
137/udp open  netbios-ns

# Nmap done at Thu Jun 20 09:48:08 2024 -- 1 IP address (1 host up) scanned in 194.27 seconds
