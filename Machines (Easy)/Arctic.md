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

## 4. Enumerating Port 8500, FMTP
Inspecting the source page of the `CFIDE/administrator/` login page, we see something interesting.
```
<form name="loginform" action="/CFIDE/administrator/enter.cfm" method="POST" onSubmit="cfadminPassword.value = hex_hmac_sha1(salt.value, hex_sha1(cfadminPassword.value));" >
```
From this, we know that the salted password is encrypted with SHA1.

Let's enumerate a little more down the list of directories.
```

```
