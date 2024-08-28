[1;34mStandard Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:38:58 2024 as: nmap -v -Pn -oN 192.168.134.112-std.nmap 192.168.134.112
Nmap scan report for 192.168.134.112
Host is up (0.032s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

# Nmap done at Thu Jun 20 13:38:59 2024 -- 1 IP address (1 host up) scanned in 0.59 seconds

[1;34mFull TCP Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:38:58 2024 as: nmap -v -Pn -p- -A -oN 192.168.134.112-full-tcp.nmap 192.168.134.112
Nmap scan report for 192.168.134.112
Host is up (0.029s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.49.134
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0         3557581 Nov 25  2021 2d5ef5a0f0c9579458c9
| -rw-r--r--    1 0        0         1258508 Nov 25  2021 4835e976619690ae006e
| -rw-r--r--    1 0        0         1617905 Nov 25  2021 4e8cce46d6abec9a9d9a
| -rw-r--r--    1 0        0          438095 Nov 25  2021 77cfe070405f6ca327a5
|_-rw-r--r--    1 0        0          841392 Nov 25  2021 c5237630ef40e2585d35
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0e:84:80:bd:8f:b6:51:7d:c1:87:db:8c:f4:f3:15:9e (RSA)
|   256 8c:98:44:30:1c:37:53:84:32:22:eb:e1:9c:06:68:06 (ECDSA)
|_  256 1b:db:c7:c9:36:54:b8:cf:ff:1a:2f:9a:91:b1:56:e4 (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: The Stationery Warehouse &#8211; Just another WordPress site
|_http-favicon: Unknown favicon MD5: 38BC6973F189E1FBB976EB4864D93528
|_http-generator: WordPress 6.0.2
|_http-trane-info: Problem with XML parsing of /evox/about
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=6/20%OT=21%CT=1%CU=34113%PV=Y%DS=2%DC=T%G=Y%TM=6674
OS:696B%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=107%TI=Z%II=I%TS=A)OPS(O
OS:1=M551ST11NW7%O2=M551ST11NW7%O3=M551NNT11NW7%O4=M551ST11NW7%O5=M551ST11N
OS:W7%O6=M551ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R
OS:=Y%DF=Y%TG=40%W=FAF0%O=M551NNSNW7%CC=Y%Q=)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M55
OS:1NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)T1(R=Y%DF=Y%T=40
OS:%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=
OS:S+%F=AR%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)
OS:T7(R=N)U1(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%TG=40%CD=S)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 18.996 days (since Sat Jun  1 13:45:48 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: the; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-06-20T17:39:50
|_  start_date: N/A
| nbstat: NetBIOS name: OSCP, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   OSCP<00>             Flags: <unique><active>
|   OSCP<03>             Flags: <unique><active>
|   OSCP<20>             Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   29.39 ms 192.168.49.1
2   29.42 ms 192.168.134.112

# Nmap done at Thu Jun 20 13:39:55 2024 -- 1 IP address (1 host up) scanned in 57.21 seconds

[1;34mStandard UDP Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:38:58 2024 as: nmap -v -Pn -sU -oN 192.168.134.112-udp 192.168.134.112
Nmap scan report for 192.168.134.112
Host is up (0.030s latency).
Not shown: 957 closed udp ports (port-unreach)
PORT      STATE         SERVICE
13/udp    open|filtered daytime
111/udp   open|filtered rpcbind
137/udp   open          netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
631/udp   open|filtered ipp
781/udp   open|filtered hp-collector
1886/udp  open|filtered leoip
1993/udp  open|filtered snmp-tcp-port
3130/udp  open|filtered squid-ipc
5353/udp  open|filtered zeroconf
9103/udp  open|filtered bacula-sd
10080/udp open|filtered amanda
17184/udp open|filtered unknown
18617/udp open|filtered unknown
18958/udp open|filtered unknown
18996/udp open|filtered unknown
19022/udp open|filtered unknown
19161/udp open|filtered unknown
19415/udp open|filtered unknown
20146/udp open|filtered unknown
20313/udp open|filtered unknown
21206/udp open|filtered unknown
21454/udp open|filtered unknown
21834/udp open|filtered unknown
22043/udp open|filtered unknown
22996/udp open|filtered unknown
23679/udp open|filtered unknown
23980/udp open|filtered unknown
26415/udp open|filtered unknown
30975/udp open|filtered unknown
31073/udp open|filtered unknown
34580/udp open|filtered unknown
40116/udp open|filtered unknown
41971/udp open|filtered unknown
43514/udp open|filtered unknown
44190/udp open|filtered unknown
44334/udp open|filtered unknown
47808/udp open|filtered bacnet
49201/udp open|filtered unknown
49220/udp open|filtered unknown
51905/udp open|filtered unknown

# Nmap done at Thu Jun 20 13:56:20 2024 -- 1 IP address (1 host up) scanned in 1042.25 seconds


$ wpscan -e ap --url http://192.168.134.112:80/ --detection-mode aggressive --api-token 'iLcYFLCBNUrIwBWwCrlssHZiwslx1EG0TxEO8lBmSHY' --plugins-detection aggressive --verbose                          took 4m16s
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.134.112/ [192.168.134.112]
[+] Started: Thu Jun 20 13:52:24 2024

Interesting Finding(s):

[+] robots.txt found: http://192.168.134.112/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.134.112/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.134.112/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.134.112/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.0.2 identified (Insecure, released on 2022-08-30).
 | Found By: Rss Generator (Aggressive Detection)
 |  - http://192.168.134.112/feed/, <generator>https://wordpress.org/?v=6.0.2</generator>
 |  - http://192.168.134.112/comments/feed/, <generator>https://wordpress.org/?v=6.0.2</generator>
 |
 | [!] 27 vulnerabilities identified:
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via wp-mail.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/713bdc8b-ab7c-46d7-9847-305344a579c4
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/abf236fdaf94455e7bc6e30980cf70401003e283
 |
 | [!] Title: WP < 6.0.3 - Open Redirect via wp_nonce_ays
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/926cd097-b36f-4d26-9c51-0dfab11c301b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/506eee125953deb658307bb3005417cb83f32095
 |
 | [!] Title: WP < 6.0.3 - Email Address Disclosure via wp-mail.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/c5675b59-4b1d-4f64-9876-068e05145431
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/5fcdee1b4d72f1150b7b762ef5fb39ab288c8d44
 |
 | [!] Title: WP < 6.0.3 - Reflected XSS via SQLi in Media Library
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/cfd8b50d-16aa-4319-9c2d-b227365c2156
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/8836d4682264e8030067e07f2f953a0f66cb76cc
 |
 | [!] Title: WP < 6.0.3 - CSRF in wp-trackback.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/b60a6557-ae78-465c-95bc-a78cf74a6dd0
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/a4f9ca17fae0b7d97ff807a3c234cf219810fae0
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via the Customizer
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/2787684c-aaef-4171-95b4-ee5048c74218
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/2ca28e49fc489a9bb3c9c9c0d8907a033fe056ef
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via Comment Editing
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/02d76d8e-9558-41a5-bdb6-3957dc31563b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/89c8f7919460c31c0f259453b4ffb63fde9fa955
 |
 | [!] Title: WP < 6.0.3 - Content from Multipart Emails Leaked
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/3f707e05-25f0-4566-88ed-d8d0aff3a872
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/3765886b4903b319764490d4ad5905bc5c310ef8
 |
 | [!] Title: WP < 6.0.3 - SQLi in WP_Date_Query
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/1da03338-557f-4cb6-9a65-3379df4cce47
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/d815d2e8b2a7c2be6694b49276ba3eee5166c21f
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via RSS Widget
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/58d131f5-f376-4679-b604-2b888de71c5b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/929cf3cb9580636f1ae3fe944b8faf8cca420492
 |
 | [!] Title: WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/b27a8711-a0c0-4996-bd6a-01734702913e
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ebaac57a9ac0174485c65de3d32ea56de2330d8e
 |
 | [!] Title: WP < 6.0.3 - Multiple Stored XSS via Gutenberg
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/f513c8f6-2e1c-45ae-8a58-36b6518e2aa9
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/gutenberg/pull/45045/files
 |
 | [!] Title: WP <= 6.2 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/
 |
 | [!] Title: WP < 6.2.1 - Directory Traversal via Translation Files
 |     Fixed in: 6.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/2999613a-b8c8-4ec0-9164-5dfe63adf6e6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2745
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Thumbnail Image Update via CSRF
 |     Fixed in: 6.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/a03d744a-9839-4167-a356-3e7da0f1d532
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Stored XSS via Open Embed Auto Discovery
 |     Fixed in: 6.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/3b574451-2852-4789-bc19-d5cc39948db5
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.2 - Shortcode Execution in User Generated Data
 |     Fixed in: 6.0.5
 |     References:
 |      - https://wpscan.com/vulnerability/ef289d46-ea83-4fa5-b003-0352c690fd89
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-2-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Content Injection
 |     Fixed in: 6.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/1527ebdb-18bc-4f9d-9c20-8d729a628670
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP 5.6-6.3.1 - Contributor+ Stored XSS via Navigation Block
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/cd130bb3-8d04-4375-a89a-883af131ed3a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38000
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP 5.6-6.3.1 - Reflected XSS via Application Password Requests
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/da1419cc-d821-42d6-b648-bdb3c70d91f2
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Denial of Service via Cache Poisoning
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/6d80e09d-34d5-4fda-81cb-e703d0e56e4f
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Subscriber+ Arbitrary Shortcode Execution
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/3615aea0-90aa-4f9a-9792-078a90af7f59
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Contributor+ Comment Disclosure
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/d35b2a3d-9b41-4b4f-8e87-1b8ccb370b9f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39999
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Unauthenticated Post Author Email Disclosure
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5561
 |      - https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Deserialization of Untrusted Data
 |     Fixed in: 6.0.7
 |     References:
 |      - https://wpscan.com/vulnerability/5e9804e5-bbd4-4836-a5f0-b4388cc39225
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Admin+ PHP File Upload
 |     Fixed in: 6.0.7
 |     References:
 |      - https://wpscan.com/vulnerability/a8e12fbe-c70b-4078-9015-cf57a05bdd4a
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.5.2 - Unauthenticated Stored XSS
 |     Fixed in: 6.0.8
 |     References:
 |      - https://wpscan.com/vulnerability/1a5c5df1-57ee-4190-a336-b0266962078f
 |      - https://wordpress.org/news/2024/04/wordpress-6-5-2-maintenance-and-security-release/

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:24:53 <===============================================================================================================================> (105843 / 105843) 100.00% Time: 00:24:53
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://192.168.134.112/wp-content/plugins/akismet/
 | Latest Version: 5.3.2
 | Last Updated: 2024-05-31T16:57:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.134.112/wp-content/plugins/akismet/, status: 500
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Akismet 2.5.0-3.1.4 - Unauthenticated Stored Cross-Site Scripting (XSS)
 |     Fixed in: 3.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/1a2f3094-5970-4251-9ed0-ec595a0cd26c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9357
 |      - http://blog.akismet.com/2015/10/13/akismet-3-1-5-wordpress/
 |      - https://blog.sucuri.net/2015/10/security-advisory-stored-xss-in-akismet-wordpress-plugin.html
 |
 | The version could not be determined.

[+] feed
 | Location: http://192.168.134.112/wp-content/plugins/feed/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.134.112/wp-content/plugins/feed/, status: 200
 |
 | The version could not be determined.

[+] mail-masta
 | Location: http://192.168.134.112/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 | Readme: http://192.168.134.112/wp-content/plugins/mail-masta/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.134.112/wp-content/plugins/mail-masta/, status: 403
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Mail Masta <= 1.0 - Unauthenticated Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/5136d5cf-43c7-4d09-bf14-75ff8b77bb44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10956
 |      - https://www.exploit-db.com/exploits/40290/
 |      - https://www.exploit-db.com/exploits/50226/
 |      - https://cxsecurity.com/issue/WLB-2016080220
 |
 | [!] Title: Mail Masta 1.0 - Multiple SQL Injection
 |     References:
 |      - https://wpscan.com/vulnerability/c992d921-4f5a-403a-9482-3131c69e383a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6095
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6096
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6097
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6098
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6570
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6571
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6572
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6573
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6574
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6575
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6576
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6577
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6578
 |      - https://www.exploit-db.com/exploits/41438/
 |      - https://github.com/hamkovic/Mail-Masta-Wordpress-Plugin
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.134.112/wp-content/plugins/mail-masta/readme.txt

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 21

[+] Finished: Thu Jun 20 14:17:27 2024
[+] Requests Done: 105865
[+] Cached Requests: 41
[+] Data Sent: 29.331 MB
[+] Data Received: 29.836 MB
[+] Memory used: 519.09 MB
[+] Elapsed time: 00:25:02

#### /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
sarah:x:1000:1000:Sarah Pine,,,:/home/sarah:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
nick:x:1001:1001:Nick,Williamson,,:/home/nick:/bin/bash
sshd:x:126:65534::/run/sshd:/usr/sbin/nologin
ftp:x:127:133:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
mysql:x:128:134:MySQL Server,,,:/nonexistent:/bin/false
paul:x:1002:1002:Paul,,,:/home/paul:/bin/bash
linda:x:1003:1003:Linda,,,:/home/linda:/bin/bash
joe:x:1004:1004:Joe,,,:/home/joe:/bin/bash

#### /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,sarah
tty:x:5:syslog
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:sarah
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:pulse
dip:x:30:sarah
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:sarah
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
systemd-timesync:x:104:
crontab:x:105:
messagebus:x:106:
input:x:107:
kvm:x:108:
render:x:109:
syslog:x:110:
tss:x:111:
bluetooth:x:112:
ssl-cert:x:113:
uuidd:x:114:
tcpdump:x:115:
avahi-autoipd:x:116:
rtkit:x:117:
ssh:x:118:
netdev:x:119:
lpadmin:x:120:sarah
avahi:x:121:
scanner:x:122:saned
saned:x:123:
nm-openvpn:x:124:
whoopsie:x:125:
colord:x:126:
geoclue:x:127:
pulse:x:128:
pulse-access:x:129:
gdm:x:130:
lxd:x:131:sarah
sarah:x:1000:
sambashare:x:132:sarah
systemd-coredump:x:999:
nick:x:1001:
ftp:x:133:
mysql:x:134:
paul:x:1002:
linda:x:1003:
joe:x:1004:
rdma:x:135:


$ ./enum4linux-ng.py 192.168.134.112                                           via  v3.12.3 (venv)
ENUM4LINUX - next generation (v1.3.3)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 192.168.134.112
[*] Username ......... ''
[*] Random Username .. 'zgqihqqq'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ========================================
|    Listener Scan on 192.168.134.112    |
 ========================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ==============================================================
|    NetBIOS Names and Workgroup/Domain for 192.168.134.112    |
 ==============================================================
[+] Got domain/workgroup name: WORKGROUP
[+] Full NetBIOS names information:
- OSCP            <00> -         B <ACTIVE>  Workstation Service
- OSCP            <03> -         B <ACTIVE>  Messenger Service
- OSCP            <20> -         B <ACTIVE>  File Server Service
- ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
- WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
- WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
- WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections
- MAC Address = 00-00-00-00-00-00

 ============================================
|    SMB Dialect Check on 192.168.134.112    |
 ============================================
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

 ==============================================================
|    Domain Information via SMB session for 192.168.134.112    |
 ==============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: OSCP
NetBIOS domain name: ''
DNS domain: ''
FQDN: oscp
Derived membership: workgroup member
Derived domain: unknown

 ============================================
|    RPC Session Check on 192.168.134.112    |
 ============================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 ======================================================
|    Domain Information via RPC for 192.168.134.112    |
 ======================================================
[+] Domain: WORKGROUP
[+] Domain SID: NULL SID
[+] Membership: workgroup member

 ==================================================
|    OS Information via RPC for 192.168.134.112    |
 ==================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Linux/Unix (Samba 4.13.14-Ubuntu)
OS version: '6.1'
OS release: ''
OS build: '0'
Native OS: not supported
Native LAN manager: not supported
Platform id: '500'
Server type: '0x809a03'
Server type string: Wk Sv PrQ Unx NT SNT Samba 4.13.14-Ubuntu

 ========================================
|    Users via RPC on 192.168.134.112    |
 ========================================
[*] Enumerating users via 'querydispinfo'
[+] Found 0 user(s) via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 0 user(s) via 'enumdomusers'

 =========================================
|    Groups via RPC on 192.168.134.112    |
 =========================================
[*] Enumerating local groups
[+] Found 0 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 0 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 0 group(s) via 'enumdomgroups'

 =========================================
|    Shares via RPC on 192.168.134.112    |
 =========================================
[*] Enumerating shares
[+] Found 2 share(s):
Developer:
  comment: Developer Files
  type: Disk
IPC$:
  comment: IPC Service (Samba 4.13.14-Ubuntu)
  type: IPC
[*] Testing share Developer
[+] Mapping: OK, Listing: OK
[*] Testing share IPC$
[-] Could not check share: STATUS_OBJECT_NAME_NOT_FOUND

 ============================================
|    Policies via RPC for 192.168.134.112    |
 ============================================
[*] Trying port 445/tcp
/home/bjorn/tools/enum4linux-ng/enum4linux-ng/./enum4linux-ng.py:2681: DeprecationWarning: datetime.datetime.utcfromtimestamp() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.fromtimestamp(timestamp, datetime.UTC).
  minutes = datetime.utcfromtimestamp(tmp).minute
/home/bjorn/tools/enum4linux-ng/enum4linux-ng/./enum4linux-ng.py:2682: DeprecationWarning: datetime.datetime.utcfromtimestamp() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.fromtimestamp(timestamp, datetime.UTC).
  hours = datetime.utcfromtimestamp(tmp).hour
/home/bjorn/tools/enum4linux-ng/enum4linux-ng/./enum4linux-ng.py:2683: DeprecationWarning: datetime.datetime.utcfromtimestamp() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.fromtimestamp(timestamp, datetime.UTC).
  time_diff = datetime.utcfromtimestamp(tmp) - datetime.utcfromtimestamp(0)
[+] Found policy:
Domain password information:
  Password history length: None
  Minimum password length: 5
  Maximum password age: 49710 days 6 hours 21 minutes
  Password properties:
  - DOMAIN_PASSWORD_COMPLEX: false
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
Domain lockout information:
  Lockout observation window: 30 minutes
  Lockout duration: 30 minutes
  Lockout threshold: None
Domain logoff information:
  Force logoff time: 49710 days 6 hours 21 minutes

 ============================================
|    Printers via RPC for 192.168.134.112    |
 ============================================
[+] No printers returned (this is not an error)

Completed after 6.70 seconds
