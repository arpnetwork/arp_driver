# ARP Driver

arp-driver is a Linux kernel driver for fast A/V communication.

## Usage

   ```bash
   git clone https://github.com/arpnetwork/arp-driver.git
   sudo mv arp-driver /usr/src/arp-1.0
   sudo dkms add arp/1.0
   sudo dkms build arp/1.0
   sudo dkms install arp/1.0
   modprobe arp
   ```
