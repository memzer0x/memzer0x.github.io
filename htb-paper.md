# Paper Hackthebox
Paper is an easy machine from HackTheBox, you should be able to complete it on your own, however i will make a small writeup on how to complete this machine.

## User
First thing first, enumeration.

When sending a request to the ip address where the challenge is being hosted, it should send back a response header with an interesting field to use `X-Backend-Server`, this field is unusual and tells me that the website might be available on this domain, so i added `office.paper` to /etc/hosts.

Then going on this website we can quickly notice that it's a wordpress website and that it's outdated (5.2.3), little more digging reveals us that a user of name micheal left the password inside the wordpress drafts. Luckily for us, we can view these drafts without being authenticated with a small exploit for wordpress version 5.2.3.

PoC for the exploit :
`?static=1&order=asc`

So using the exploit i tried visiting `http://office.paper/?static=1&order=asc` but i get a 404 page not found, so i decided to remove the `&order=asc` part of the url and it worked.

Looking at the content of the draft, we don't see a password but a link to `chat.office.paper` where we can register, so i added `chat.office.paper` to /etc/hosts and registered on the website.

The website chat.office.paper is a rocketchat instance with a bot that has been made by a certain user, this bot can be used to list files in a directory and also read them. After a bit of digging, the file `../hubot/.env` contains credentials to the bot, trying the bot password with the ssh user dwight (you can read /etc/passwd with the bot to find out users) and the password we just found and we can read the user flag !

## Root
Root was also very easy to do, if you've been following the news, then you'd surely know that polkit has been target to a number of CVE's in the recent months (notably CVE-2021-4034 aKa Pwnkit and CVE-2021-3560).

In our case polkit is vulnerable to CVE-2021-3560, which as per [redhat](https://access.redhat.com/security/cve/cve-2021-3560)
- It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user.
- This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

We won't go deep into the exploit as this is just a simple vulnerable machine, however feel free to dig more on polkit exploits by yourselves.

You can download this [script](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) on the victim machine.

Executing the script the following way, will try to exploit polkit and create a user of the name penis with sudo access.
```
$ ./poc.sh -u=penis -p=penis
```

Then if the exploit succeeded, there should be a new user with sudo access named penis, let's change user and spawn a root shell.
```
$ su penis
$ sudo passwd
```