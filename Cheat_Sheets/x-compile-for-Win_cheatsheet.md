# Get cross-compiler for Kali
<code> apt install mingw-w64 </code>

# Exploit code for cmd command execution (use only in your private environment for stuff that belongs to you!)

#include <stdlib.h>

int main(){
	system("Your command here");
  return 0;
}

# cross compile for 32 bit
	
<code> i686-w64-mingw32-gcc foo.c -o foo.exe </code>


# cross compile for 64 bits
	
<code> x86_64-w64-mingw32-gcc foo.c -o foo.exe </code>
	
# List compilation options
	
	apt-cache search mingw-w64
	
# Compile malicious dll

<code> x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll </code>
