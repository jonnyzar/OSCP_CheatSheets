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