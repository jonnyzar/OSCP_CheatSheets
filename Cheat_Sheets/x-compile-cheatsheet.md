# X-Compiling binaries on kali

## Get cross-compiler for windows

`apt install mingw-w64 `


```c
#include <stdlib.h>

int main(){
	system("Your command here");
  return 0;
}
```

cross compile for 32 bit
	
`i686-w64-mingw32-gcc foo.c -o foo.exe`


cross compile for 64 bits
	
`x86_64-w64-mingw32-gcc foo.c -o foo.exe`
	
List compilation options
	
	apt-cache search mingw-w64
	
Compile malicious dll

`x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll`

## For Linux

Use another box or directly on kali

if doesnt compile, for older machines add : `-static -static-libgcc -static-libstdc++`
