# Pivoting usinng proxychains

 chisel server -p 3333 --reverse --socks5

./chisel_lin client 172.16.40.5:3333 R:7777:socks

sudo vim /etc/proxychains4.conf

socks5 127.0.0.1 3333

proxychains nmap -F 10.185.10.0/24