# Pivoting 

## Readme

https://cheatsheet.haax.fr/network/pivot_techniques/


## using proxychains

 chisel server -p 3333 --reverse --socks5

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