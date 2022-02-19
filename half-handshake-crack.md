# Half-Handshake Crack
Sometimes when waiting for handshakes you will catch only the half part of that handshake, that is without the handshake being acknowledged by the network in question.
Know that those handshakes can be extremely useful in certain scenarios.

When listening for handshakes in public places, you will often see half handshakes popped up in your capture file (or wireshark, or whatever you use). These handshakes are as much crackable as full three-way handshakes, thing is you can't know for sure if the password is right since half-handshake aren't acknowledge by the router.

You can capture Half Handshake pretty easily, first you need an adapter that his compatible with the aircrack-ng suite, here's a small list of chipset compatible with aicrack.
- Ralink RT8070, RT3070
- Ralink RT2770, RT2750
- Ralink RT3572, RT5572
- Ralink RT5370N
- Realtek RTL8812AU
- Atheros AR9002U
- Realtek RTL8188SU
- Realtek RTL8192EU
- Atheros AR9271

Next thing to do is to install the right drivers for the adapter your going to use, i use Atheros AR9002U (TN-WN722N) and RTL8812AU (AWUS036ACH), so i installed the following drivers to get started.
```
$ git clone https://github.com/aircrack-ng/rtl8188eus
$ git clone https://github.com/aircrack-ng/rtl8812au
```
Then you should be ready to go, enable monitor mode (don't forget to change your mac address *wink wink*), start airodump.
```
$ sudo airodump-ng <device>
```

Find a target network (make sure you have the right to crack it), and note the channel the network is currently using. Now let's start the real things, we are going to want to see what's going on in the airodump capture for this reason we'll manually capture the handshake with wireshark instead of using the airodump --write switch.
```
$ sudo airodump-ng <device> -c <network channel> & wireshark
```
Open the wireshark window, and double click on the interface your currently listening on with airodump, now you can copy the BSSID of your target network and we'll use a filter inside wireshark so we will see only the packets addressed to this network.
```
Wireshark BSSID Filter : wlan.ta == <bssid> || wlan.da == <bssid>
Handshake filter : eapol && wlan.da == <bssid> || eapol && wlan.ta == <bssid>
```
Now you can wait until someone tries to connect to the network with a password, you should capture EAPOL packets when the key reach **Message 2 of 4**, you know you have your half handshake.

## Social Engineering Scenario
Okay let's go a little deeper because half-handshakes can be used in a tons of different scenario, but in this section we'll explore one. 

So here it is, you are currently in your home and you want to hack into your neighbor's wifi (totally unethical and illegal), but you can't seem to get any handshake out of their network, what you could do is make an Evil Access Point that looks exactly like your target network (same name, bssid) and put some random password on this network, you will also launch a ddos attack agains't the target network so that the victim can't connect to his real network. Now your neighbor get's home after a long day of work, he see's that he his disconnected from the network so he tries to connect to it, prompt is usual password and he see's that it doesn't work. 

At this point you should have catched at least a handshake or even more that you can crack, it's time to stop the attack and allow your poor neighbor to connect back again to it's network.

Check on wireshark using the **eapol** filter or the Handshake filter i shown a little earlier, if you have eapol packets with "Key (Message 2 of 4)" this means you successfully captured your half-handshake. Save the capture to a .pcap file and we can go to the next step.

## Time to crack
Now you have successfully gotten your hands on your handshake it's time to crack it. For this, you can use either a predefined wordlist (works sometimes), or if you know the target you could build one based on your target, in this case i will show you using a predefined wordlist **rockyou.txt**, the command is the same as usual but i will still show it.
```
aircrack-ng -w /usr/share/wordlists/rockyou.txt <capture file>
```
