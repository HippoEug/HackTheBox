## NMAP Scan
`nmap -sC -v 10.10.10.3 -Pn`

## First Attack on FTP
Shows Port 21 FTP Login allowed amongst othger opened ports
`nc 10.10.10.3 21` shows `vsFTPd v2.3.4` 
`searchsploit vsftpd 2.3.4` shows `Backdoor Command Execution
However, metasploit attacks etc didn't work.

Sources:
- https://www.hackingtutorials.org/metasploit-tutorials/exploiting-vsftpd-metasploitable/
- https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/
- https://metalkey.github.io/vsftpd-v234-backdoor-command-execution.html

## Finding another attack vector
Our first NMAP scan was useless. Let's try more nmap scans!
`nmap --script nmap-vulners -sV 10.10.10.3 -Pn -v` but didn't turn out to be useful. (Source: https://securitytrails.com/blog/nmap-vulnerability-scan)
Let's try something else which turned out to be more useful.
`nmap -sC -sV -A -v 10.10.10.3 -Pn`

## Second attack on Port 445 Samba
Shows Samba smbd 3.0.20-Debian
`searchsploit samba 3.0.20`
There are a few interesting choices, but we are going for `Metasploit Usernawme map script Command Execution`.
Researching it, we find https://securitytrails.com/blog/nmap-vulnerability-scan.
Let's run the metasploit script `use exploit/multi/samba/usermap_script`
Boom, we got root access and find the flag!
