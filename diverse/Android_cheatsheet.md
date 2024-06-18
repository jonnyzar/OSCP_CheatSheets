# Pentesting Android

## Setup

### Setup Burp proxy and CA

```bash

# careful do not use Google APIs
emulator -writable-system -avd <Nougat 7.11 API> -qemu -s

# for google Store phone

docker run --rm --network host ha0ris/aeroot daemon

# go to burp and export a cert.der in DER format
# convert to pem and rename

openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1
mv cacert.pem <hash>.0

# push to mobile device

#adb root
adb remount
adb push <cert>.0 /sdcard/

# move and give privs in device
mv /sdcard/<cert>.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/<cert>.0

reboot

# enjoy your proxy traffic in burp
Settings -> Wi-Fi -> Mofidy -> advanced -> proxy -> your burp ip and port 

```

### Rooting

#### root the device on the fly

1. start the device as (parameters ahve to be in exact same order!!!): `emulator -abd <name.apk> -qemu -s` 

2. root: `docker run --rm --network host ha0ris/aeroot daemon`

#### install and run frida to bypass debugging app's protection

https://medium.com/my-infosec-write-ups/frida-installation-40f52845ae98

or 

```bash

pip install frida-tools

frida --version

# check device to know which frida to download
adb shell
getprop | grep abi

# upload correct frida to device
push frida_86_something /data/local/tmp/frida86

# in device 
adb shell
chmod 700 /data/local/tmp/frida86
./data/local/tmp/frida86

# on PC check if frida seems any processes from device
frida-ps -Uai

# inject into process of interest

frida -U -l hook.js -f app.process.test

```

if needed inspect code with `jdax gui` and then change the `hook.js`. 
here is example:

```js
this._v0.value = false;
this._u0.value = false;
this._w0.value = false;
this._x0.value = false;
this._z0.value = false;
```

## Common hacks

### finding installed apk and downloading it

Useful if you do not have apk but only Google play link

```bash

adb shell pm list packages | sort

adb shell pm path <pkg name>

adb pull data/app/path/to/base.apk

```


## use Burp proxy

since Nougat has no proxy setting in the UI, do it per CLI

`adb shell settings put global http_proxy :0`

then go to Setting (via ... in emulator Window) and set Manual proxy `127.0.0.1:8080`

## Ressources

* MobSF: quick overview of vulenerabilities and source code
* JADX-GUI: source code and ressources