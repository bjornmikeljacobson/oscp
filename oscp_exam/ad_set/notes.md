anonymous user enum using nxc doesn't work
ldap anonymous bind no good either

### ms01 - 192.168.112.101
Port 8080 - Running Jenkins 2.150.2
Default credentials - admin/password (no good)

- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.112.101
+ Target Hostname:    192.168.112.101
+ Target Port:        8080
+ Start Time:         2024-05-19 15:36:49 (GMT-4)
---------------------------------------------------------------------------
+ Server: Jetty(9.4.z-SNAPSHOT)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Uncommon header 'x-you-are-in-group-disabled' found, with contents: JENKINS-39402: use -Dhudson.security.AccessDeniedException2.REPORT_GROUP_HEADERS=true or use /whoAmI to diagnose.
+ /: Uncommon header 'x-jenkins' found, with contents: 2.150.2.
+ /: Uncommon header 'x-required-permission' found, with contents: hudson.model.Hudson.Read.
+ /: Uncommon header 'x-you-are-authenticated-as' found, with contents: anonymous.
+ /: Uncommon header 'x-hudson' found, with contents: 1.395.
+ /: Uncommon header 'x-jenkins-session' found, with contents: 87568b21.
+ /: Uncommon header 'x-permission-implied-by' found, with multiple values: (hudson.security.Permission.GenericRead,hudson.model.Hudson.Administer,).
+ All CGI directories 'found', use '-C none' to test none
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Jetty/9.4.z-SNAPSHOT appears to be outdated (current is at least 11.0.6). Jetty 10.0.6 AND 9.4.41.v20210516 are also currently supported.
+ /favicon.ico: identifies this app/server as: Jenkins. See: https://en.wikipedia.org/wiki/Favicon
+ /cgi.cgi/%2e%2e/abyss.conf: Uncommon header 'x-hudson-theme' found, with contents: default.
+ /cgi.cgi/%2e%2e/abyss.conf: Uncommon header 'x-instance-identity' found, with contents: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GMig2JhpMAl308QFQ+YE9TeyO5QBRFgh8qbXN0hzmgYg/9YQR3tM6owKt1pPEiJzocJJhp9IBB61xFBwsUmT+WBHV7JdGytgOKxI7xIX/8LYdP85Snk/kVADiDKyynXuxuqszVXJAsy++Pkm5kvvM5nizNT1GjgolVCL15+bN9AZ1K0EJRU7L2RgCFEAsBP/EF778dcskXnVn1ZfuJgiaDiYS4Ud4HFeQzmrqCK/NB9dyp4aOSl1y0UkQoKZ6CTalbnOOL14h3ZKUEsZoT5GGaw9gdKBlz5ey9jwKw5VY6OFe9vwxx2mB03ah1E1InC/2HAXszxG6F0fx4eGvQ9rQIDAQAB.


Jenkins-Crumb%3D5dc67b241caebdd66de75c50499d5000

Using Jetty 9.4.x / Java 8
Hudson version 1.395

Robots.txt says "we don't want anyone clicking build links"

navigable pages: oops, login, signup, 

#### try 
 - [ ] sql-injection via login form
 - [x] metasploit module vs jenkins version (can't get any to work)
 - [ ] 

#### post-exploitation
 - [ ] still need to run winPEAS
 - [ ] try to extract and crack creds form jenkins secrets
 - [ ] find kerberoastable/asreproastable users

### ms02 - 192.168.112.102

- [x] evil-winrm as nate (no good)

### dc01 - 192.168.112.100

#### try 
- [x] ldap directly on dc (no good)

kerbrute found users
kate
nate
sam

 - [ ] need to run bloodhound ingestor 
 - [ ] set up ligolo to access mysql
 - [ ] dump creds from ms01 in metasploit
 - [ ] can try ntlm relay to authenticate to mysql
