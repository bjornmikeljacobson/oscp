[1;34mStandard Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:39:43 2024 as: nmap -v -Pn -oN 192.168.134.110-std.nmap 192.168.134.110
Nmap scan report for 192.168.134.110
Host is up (0.029s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT   STATE  SERVICE
20/tcp closed ftp-data
21/tcp open   ftp
22/tcp open   ssh
53/tcp closed domain
80/tcp open   http

# Nmap done at Thu Jun 20 13:39:56 2024 -- 1 IP address (1 host up) scanned in 12.96 seconds

[1;34mFull TCP Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:39:43 2024 as: nmap -v -Pn -p- -A -oN 192.168.134.110-full-tcp.nmap 192.168.134.110
Nmap scan report for 192.168.134.110
Host is up (0.026s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT   STATE  SERVICE  VERSION
20/tcp closed ftp-data
21/tcp open   ftp      vsftpd 3.0.5
22/tcp open   ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a7:09:ae:7c:78:41:c7:a8:b4:41:17:20:f5:cd:15:75 (ECDSA)
|_  256 6c:fc:3e:2e:95:6a:54:1e:98:89:0e:c9:97:69:10:b9 (ED25519)
53/tcp closed domain
80/tcp open   http     Apache httpd 2.4.52
|_http-title: Index of /
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Device type: general purpose|storage-misc|firewall|webcam
Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (86%), Synology DiskStation Manager 5.X (86%), WatchGuard Fireware 11.X (86%), Tandberg embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:3.4 cpe:/o:linux:linux_kernel:4.2 cpe:/o:linux:linux_kernel cpe:/a:synology:diskstation_manager:5.1 cpe:/o:watchguard:fireware:11.8 cpe:/h:tandberg:vcs
Aggressive OS guesses: Linux 2.6.32 (86%), Linux 3.4 (86%), Linux 3.5 (86%), Linux 4.2 (86%), Linux 4.4 (86%), Synology DiskStation Manager 5.1 (86%), WatchGuard Fireware 11.8 (86%), Linux 2.6.35 (85%), Linux 3.10 (85%), Linux 4.9 (85%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 14.789 days (since Wed Jun  5 18:45:00 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.0.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   24.35 ms 192.168.49.1
2   24.45 ms 192.168.134.110

# Nmap done at Thu Jun 20 13:41:51 2024 -- 1 IP address (1 host up) scanned in 127.72 seconds

[1;34mStandard UDP Scan[0m
# Nmap 7.94SVN scan initiated Thu Jun 20 13:39:43 2024 as: nmap -v -Pn -sU -oN 192.168.134.110-udp 192.168.134.110
Nmap scan report for 192.168.134.110
Host is up.
All 1000 scanned ports on 192.168.134.110 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

# Nmap done at Thu Jun 20 13:43:04 2024 -- 1 IP address (1 host up) scanned in 201.21 seconds
