# Monitor Mode on TN-WN722N
Installing the required packages and configure them to make TN-WN722N works in monitor mode is pretty straight forward, let's see how to do it.

## Arch Linux
```bash
	pamcan -Syu
	pacman -S install bc -y
	sudo rmmod r8188eu.ko
	git clone https://github.com/aircrack-ng/rtl8188eus
	cd rtl8188eus
	sudo -i
	echo "blacklist r8188eu" > "/etc/modprobe.d/realtek.conf"
	exit
	make
	sudo make install
	sudo modprobe 8188eu

	# You can ignore compilation errors related to redhat
```

## Debian based System
```bash
	sudo apt update
	sudo apt install bc -y
	sudo rmmod r8188eu.ko
	git clone https://github.com/aircrack-ng/rtl8188eus
	cd rtl8188eus
	sudo -i
	echo "blacklist r8188eu" > "/etc/modprobe.d/realtek.conf"
	exit
	make
	sudo make install
	sudo modprobe 8188eu
```
