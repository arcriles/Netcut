# Netcut: A Command-Line ARP Spoofing Tool

A C++ based command-line tool for network reconnaissance and authorized ARP spoofing tests on a local area network (LAN). This tool allows users to scan the network to discover hosts and perform network attacks like LAN isolation and MITM traffic interception.

***

### 📜 Disclaimer

This tool is intended for educational purposes and for use only on networks where you have explicit authorization. Unauthorized ARP spoofing on a network can lead to service disruption and is illegal in many jurisdictions. The developers assume no liability and are not responsible for any misuse of this tool. **Use at your own risk.**

***

### ✨ Features

* **Network Scanning**: Broadcasts ARP requests to discover all active hosts on the current network segment.
* **Known Devices**: Displays a list of discovered devices, including their IP address and MAC address.
* **LAN Isolation Attack**: Isolates one or more target devices from communicating with other devices on the same local network by poisoning their ARP caches.
* **MITM (Cut Off) Attack**: Performs a Man-in-the-Middle attack by spoofing ARP replies to both a target device and the network gateway. This redirects traffic through the attacker's machine, effectively cutting off the target's internet access.
* **Graceful Recovery**: Upon stopping an attack, the tool sends corrective ARP packets to restore the ARP tables of all affected devices, ensuring the network returns to a normal state.

***

### 🔧 Getting Started

#### Prerequisites
* A Linux-based operating system (tested on Arch Linux).
* `g++` compiler with C++17 support.
* `make` build automation tool.
* Root privileges are required to run the application, as it uses raw sockets for crafting network packets.

#### Compilation
To compile the project, simply run the `make` command in the root directory of the project.

```bash
make