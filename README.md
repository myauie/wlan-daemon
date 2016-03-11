# wlan-daemon
Automated wireless network manager for OpenBSD.

Supports wired and wireless networks with the following authentication types: none, WEP, WPA-PSK (WPA1 and WPA2), WPA-Enterprise.

Requires installation of wpa_supplicant to support WPA-Enterprise networks. These will typically found in a work or university environment, rather than a home network. The OpenBSD command to install this is:
```
doas pkg_add wpa_supplicant
```
(or sudo if you prefer)

The program is designed to be run at boot as a system daemon. It regularly polls and attempts to locate networks that are listed in the wlan-daemon.conf file, in the order they are listed by the user. This software is designed to support laptop users that may transport their computer in and out of range of different access points. Automatically connecting to new access points is supported by default in other operating systems (including <a href="https://wiki.gnome.org/Projects/NetworkManager">NetworkManager</a> for Linux), and this software is intended to provide the same functionality.
