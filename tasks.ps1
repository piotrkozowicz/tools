# Get-ScheduledTasksReport.ps1
# Extracts all scheduled tasks with executable, parameters, and user info

function Get-AllScheduledTasksInfo {
    $results = @()

    $tasks = Get-ScheduledTask

    foreach ($task in $tasks) {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

        foreach ($action in $task.Actions) {
            $obj = [PSCustomObject]@{
                TaskName        = $task.TaskName
                TaskPath        = $task.TaskPath
                State           = $task.State
                RunAsUser       = $task.Principal.UserId
                RunLevel        = $task.Principal.RunLevel        # Limited / Highest (admin)
                LogonType       = $task.Principal.LogonType
                Execute         = $action.Execute
                Arguments       = $action.Arguments
                WorkingDir      = $action.WorkingDirectory
                Enabled         = $task.Settings.Enabled
                LastRunTime     = $taskInfo.LastRunTime
                LastTaskResult  = $taskInfo.LastTaskResult
                NextRunTime     = $taskInfo.NextRunTime
                Triggers        = ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join "; "
                Description     = $task.Description
            }
            $results += $obj
        }
    }

    return $results
}

# --- Run and display ---
Write-Host "Collecting scheduled tasks..." -ForegroundColor Cyan

$tasks = Get-AllScheduledTasksInfo

# Display in console
$tasks | Format-Table -AutoSize -Property TaskName, State, RunAsUser, Execute, Arguments, LastRunTime, LastTaskResult

# Export to CSV
$csvPath = "$env:USERPROFILE\Desktop\ScheduledTasksReport.csv"
$tasks | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`nExported to: $csvPath" -ForegroundColor Green

# Summary stats
Write-Host "`n--- Summary ---" -ForegroundColor Yellow
Write-Host "Total tasks:    $($tasks.Count)"
Write-Host "Enabled:        $(($tasks | Where-Object { $_.Enabled }).Count)"
Write-Host "Disabled:       $(($tasks | Where-Object { -not $_.Enabled }).Count)"
Write-Host "Running now:    $(($tasks | Where-Object { $_.State -eq 'Running' }).Count)"
Write-Host "Ready:          $(($tasks | Where-Object { $_.State -eq 'Ready' }).Count)"
