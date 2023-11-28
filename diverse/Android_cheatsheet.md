# Pentesting Android

## Basics

### Emulating

* use Android Studio
* make sure qemu is installed

1. Install app in the GUI: use Google Play if app is in Google store or needs to start in non debugged mode
2. start emulating 

`emulator -avd Pixel_6a_API_33_Google_Store -qemu -s`


### Installing 

* install apk on Android emulator `adb install some.apk`

### Rooting

3. root the device

`sudo docker run --rm --network host aeroot daemon`

4. install and run frida to bypass debugging app's protection

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


### Setting up Burp proxy

* From the Emulated Device you can reach the Development Machine Host using `10.0.2.2`
* follow this to setup certificates and know where to click: https://portswigger.net/burp/documentation/desktop/mobile/config-android-device

### Decoding Ressources

* MobSF: quick overview of vulenerabilities and source code
* JADX-GUI: source code and ressources