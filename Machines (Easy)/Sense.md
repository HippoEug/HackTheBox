# Summary
### 1. NMAP
x

### 2. Port 80 HTTP Enumeration
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

## 2. Port 80 HTTP Enumeration
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

Ah nothing interesting on this particular page.

## 3. Port 80 XXXX Exploitation
