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

## 2. Enumeration & Attack Attempt 1
