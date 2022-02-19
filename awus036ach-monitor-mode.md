# Monitor Mode on AWUS036ACH
Installing the required packages and configure them to make AWUS036ACH works in monitor mode is pretty straight forward, let's see how to do it.

## Arch Linux
```bash
	pamcan -Syu
	pacman -S install bc -y
	 git clone https://github.com/aircrack-ng/rtl8812au.git
	cd rtl8812au
	make
	sudo make install
	reboot
```
