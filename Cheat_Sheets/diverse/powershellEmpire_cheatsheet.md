# PowerShell Empire

A post-exploitation framework which is useful once foothold is obtained.

### Stating up PSempire

* Setup a server

`sudo powershell-empire server`

Server manages all requests and can be understood as a multi-player game server

Server address once started can be like `[*] Starting Empire RESTful API on 0.0.0.0:1337`

* Setup a client

Via client attacker uses server to attack victims. Connect to server address show like one above:

```bash

powershell-empire client

#in the psempire shell connect to local host or other ip

(Empire) > connect -c localhost

[*] Connected to localhost

```

### Connecting to Victim

* To connect to victim it is necessary to setup a `listener` and a `stager`
* listener is going to wait on you attacker host for the stager, which is on victim host, to connect

#### Setup a Listener

```bash
#lsit listeners
(Empire) > listeners

#none right now
┌Listeners List──────┬───────────────────┬────────────┬─────────┐
│ ID │ Name │ Module │ Listener Category │ Created At │ Enabled │
└────┴──────┴────────┴───────────────────┴────────────┴─────────┘

#available listeners
(Empire: listeners) > uselistener

#press TAB after uselistener and get a list of possible listeners
(Empire: listeners) > uselistener
                                   dbx             
                                   http            
                                   http_com        
                                   http_foreign    
                                   http_hop        
                                   http_malleable  
                                   onedrive        
                                   redirector      

#http listener is always a good choice since not blocked mostly by FWs

(Empire: listeners) > uselistener http

 Author       @harmj0y                                                              
 Description  Starts a http[s] listener (PowerShell or Python) that uses a GET/POST                                                  
```

Now like with Metasploit set the attacker listener IP and port

```bash

(Empire: uselistener/http) > set Host 192.168.115.111
[*] Set Host to 192.168.119.158
(Empire: uselistener/http) > set Port 443
[*] Set Port to 443

#execute and enjoy

(Empire: uselistener/http) > execute
[+] Listener http successfully started

```

#### Setup a stager

Now somehow we need to connect to a victim. There are two ways of doing it:

1. bind: we connect to a victim
2. reverse: victim connects to us

Both of those ways need a stager that must be transferred to victim and activated preferrably with root or SYSTEM privileges.