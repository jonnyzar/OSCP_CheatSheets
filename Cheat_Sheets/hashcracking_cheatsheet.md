# Hash cracking
Standard to be used is hashcat

## Hashcat setup

tbd

## Hashcat basic use

```
hashcat -O -a 0 -m 100 try.hash  /usr/share/wordlists/rockyou.txt

-O: swith optimized kernels to improve performance
-a: attack mode selection (o for straight)
-m: hash type (see help)
try.hash: file with list of hashes (best practice to reduce garbage on screen)
/usr/share/wordlists/rockyou.txt: use this for OSCP (find fresh rockyou on github)

```

## WiFi cracking

Manual origin: `https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2`

1. Stop all services that are accessing the WLAN device (e.g .: NetworManager and wpa_supplicant.service)
```
$ sudo systemctl stop NetworkManager.service
$ sudo systemctl stop wpa_supplicant.service
```
2. Capture handshake with hcxdumptool (send deauth to speed up)

`$ hcxdumptool -i interface -o dumpfile.pcapng --active_beacon --enable_status=15`

3. restart services

```
$ sudo systemctl start wpa_supplicant.service
$ sudo systemctl start NetworkManager.service
```
4. Convert the traffic to hash format 22000

`$ hcxpcapngtool -o hash.hc22000 -E wordlist dumpfile.pcapng`

for cap file (obtained from airgeddon) it's the same

`$ hcxpcapngtool -o hash.22000 --csv=AP.txt handshake-xx:xx:xx.cap  `

5. run hashcat

`hashcat -m 22000 hash.hc22000 wordlist.txt`
