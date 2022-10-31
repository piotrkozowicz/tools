$numofpaths  = 0
$countcopies = 0
$filetocopy  = "testfile.txt"


$myarray = Get-ChildItem -Recurse -Directory C:\

Write-Host ""
Write-Host "[i] Number of folder paths :" $myarray.count

# If the last path entry ends in semi-colon

if ($myarray[$myarray.count-1] -eq "")
{
   $numofpaths = $myarray.count - 2
}
else
{
   $numofpaths = $myarray.count - 1
}

New-Item $filetocopy -type file | Out-Null

$FileExists = (Test-Path $filetocopy)

if (!($FileExists))
{
    Write-Host "[i] Dummy test file used to test access was not outputted:" $filetocopy
    exit
}

Write-Host "[i] Copying and removing test file to path folders where access is granted"

for($i=0; $i -le $numofpaths; $i++)
{
if (Test-Path -Path $myarray[$i].FullName)
{
    Copy-Item $filetocopy $myarray[$i].FullName -errorAction SilentlyContinue -errorVariable errors

    if ($errors.count -le 0)
    {
        Write-Host -foregroundColor Green "      Access granted:" $myarray[$i].FullName
        $countcopies = $countcopies + 1
        $filetoremove = $myarray[$i].FullName + "\" + $filetocopy
        Remove-Item $filetoremove
    }
    else
    {
        $filetowrite = $myarray[$i].FullName + "\" + $filetocopy
        New-Item $filetowrite -type file -errorAction SilentlyContinue -errorVariable errors
        if ($errors.count -le 0)
        {
            Write-Host -foregroundColor Green "      Access granted:" $myarray[$i].FullName
            $countcopies = $countcopies + 1
            Remove-Item $filetowrite
        }

    }

}

}

Remove-Item $filetocopy
