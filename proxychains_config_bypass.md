# Proxychains Config File Bypass

Okay, in this chapter i will demonstrate the Proxychains config file bypass i've found, which wasn't really hidden if you look at the source code.

The programmer of proxychains4-ng (rofl0r), said that the behavior of the program was intended to work in this way, therefore does not intend to fix it.

*Note this is not the exploit of the century but it can be extremely useful in certain scenarios.*

## How it works ?

The bypass is fairly simple, the program looks in some directories for proxychains.conf, before looking in /etc/proxychains.conf which is the default config path on most linux installation.

The program looks in each one of these directories until it finds a proper config file :

1. PROXYCHAINS_CONF_FILE environment variable
2. Current Directory (where the program is located)
3. $HOME/.proxychains/proxychains.conf
4. ~/config/settings/proxychains.conf
5. $SYSCONFDIF/proxychains.conf
6. /etc/proxychains.conf (default directory is checked last, we can use any directories before this one)

This means we can put a config file in any of the directories at index 1-5 (before the program checks for /etc/proxychains.conf), and the program will run with our custom proxychains.conf file.

This also means that even if we restrict the permissions on the /etc/proxychains.conf file, people will eventually still be able to run their own custom config files even without having write access to the default config file.

## Prove it ?

Let's start by showing you the vulnerable (not that vulnerable) part...note how **/etc/proxychains.conf** is the last priority, but the default config on most linux installation :think:

```c
char *get_config_path(char* default_path, char* pbuf, size_t bufsize) {
	char buf[512];
	// top priority: user defined path
	char *path = default_path;
	
	if(check_path(path)) // this will check if our path is not null
		goto have; //this will return the config path found

	// priority 1: env var PROXYCHAINS_CONF_FILE <------
	path = getenv(PROXYCHAINS_CONF_FILE_ENV_VAR);
	if(check_path(path))
		goto have;

	// priority 2; proxychains conf in actual dir <------
	path = getcwd(buf, sizeof(buf));
	snprintf(pbuf, bufsize, "%s/%s", path, PROXYCHAINS_CONF_FILE);
	path = pbuf;
	if(check_path(path))
		goto have;

	// priority 3; $HOME/.proxychains/proxychains.conf <------
	path = getenv("HOME");
	snprintf(pbuf, bufsize, "%s/.proxychains/%s", path, PROXYCHAINS_CONF_FILE);
	path = pbuf;
	if(check_path(path))
		goto have;
    
    // priority 3b: ~/config/settings/proxychains.conf (for haiku) <------
	path = getenv("HOME");
	snprintf(pbuf, bufsize, "%s/config/settings/%s", path, PROXYCHAINS_CONF_FILE);
	path = pbuf;
	if(check_path(path))
		goto have;

	// priority 4: $SYSCONFDIR/proxychains.conf <------
	path = SYSCONFDIR "/" PROXYCHAINS_CONF_FILE;
	if(check_path(path))
		goto have;

	// priority 5: /etc/proxychains.conf <------
	path = "/etc/" PROXYCHAINS_CONF_FILE;
	if(check_path(path))
		goto have; // note here that the last priority is /etc/proxychains.conf, which is the default used by most linux installations

	perror("couldnt find configuration file");
	exit(1);

	return NULL;
	have:
	return path;
}
```

**Can you see it now ??!!** Of course like i said it's not the exploit of the year, but it can be HIGHLY useful when you try to pivot on another system on the network, you can start a dynamic tunnel and proxychains into it, the dynamic tunnel will act like a SOCKS Proxy.

# Bypass the config file (demo)

Okay so i'm on a system connected to a user that doesn't have access to the **/etc/proxychains.conf** file, and i'm connected via SSH.

I was able to start a dynamic tunnel on another computer in my network at 192.168.1.69, now i would like to use this tunnel like a SOCKS Proxy to enumerate other machines on the network, all i have to do is make a new proxychains.conf file and modify it so it uses our dynamic tunnel as proxy, next you have to make sure to put the file in one of these 5 directories :

1. PROXYCHAINS_CONF_FILE environment variable
2. Current Directory (Pretty similar to CVE-2015-3887, but way much useless)
3. $HOME/.proxychains/proxychains.conf
4. ~/config/settings/proxychains.conf
5. $SYSCONFDIF/proxychains.conf

For my example i will put my config file inside the PROXYCHAINS_CONF_FILE environment variable, to do that i will use the command
`export PROXYCHAINS_CONF_FILE=<path/to/configfile>` and we can run the program, let's prove it works...
![alt](https://i.imgur.com/77RPyQS.png)

Note the yellow highlighted text is the config file the program is currently using, on the first run it uses the default one, however i bypassed the default config file on the second run.

The green highlighted text is just a proof that i do not have write access to the file **/etc/proxychains.conf**

And the purple highlighted text is the command i used to bypass the config file.

# How to fix that ?

The best way to fix that is to put **/etc/proxychains.conf** as first priority, this will block users that don't have access to **/etc/proxychains.conf** from being able to make their own config files and use proxychains the way they want on your system.

I have made a fork of proxychains4-ng and i fixed the part that was bothersome to be and probably for a lot of people too.

You can find it there : https://github.com/XORausaurus/Proxychains4-ng
