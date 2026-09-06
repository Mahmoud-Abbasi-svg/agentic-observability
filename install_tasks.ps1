<#
Register the collector and evaluator as Windows scheduled tasks that start at logon.

    .\install_tasks.ps1              register (or re-register) both tasks and start them
    .\install_tasks.ps1 -Status      what is registered and whether it is running
    .\install_tasks.ps1 -Uninstall   remove both tasks

WHY THIS EXISTS. A monitor that stops when you log off is not a monitor. Launching the two
processes by hand works until the machine sleeps, restarts or you sign out - and then the gap
is invisible until someone asks why there is no data. This registers them with the Task
Scheduler so they come back on their own at every logon.

No elevation needed: these are per-user tasks running as the logged-in user, which is also the
only account whose network the monitor should be measuring.

Four settings do the real work:
  - restart up to 3 times if the process exits unexpectedly
  - one instance only, so a second logon cannot start a second collector writing the same rows
  - no execution time limit, because "runs forever" is the point
  - a REPEATING trigger, which is the one that actually saved it

WHY THE REPETITION IS NOT REDUNDANT. The first version had the logon trigger and RestartCount
alone, and the monitor still went down for 51 hours without anyone noticing. This project
lives on a non-boot volume, and at logon the trigger fired before J: had finished mounting:
both tasks failed instantly with 0x8007010B, ERROR_DIRECTORY.

RestartCount does not cover that. It restarts a process that DIED after starting; a task whose
working directory does not exist never starts at all, so there is nothing to restart and the
task simply sits in Ready until the next logon. The failure is also silent - the tasks look
healthy, and only the absence of new rows gives it away.

So the trigger now waits a minute for volumes to appear, and then repeats every 15 minutes
indefinitely. Combined with -MultipleInstances IgnoreNew that is a self-healing watchdog: if
the collector is running the repeat is ignored, and if it is not, the next repeat brings it
back within a quarter of an hour instead of at the next logon.
#>
param(
    [switch]$Status,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonw = (Get-Command pythonw -ErrorAction SilentlyContinue).Source
if (-not $pythonw) { throw "pythonw.exe not found on PATH" }

$tasks = @(
    @{ Name = 'NetMonitor-Collector'; Script = 'net_collect.py'
       Desc  = 'Network observability: measures on a schedule and writes to net_monitor.db' },
    @{ Name = 'NetMonitor-Evaluator'; Script = 'net_alert.py'
       Desc  = 'Network observability: evaluates history and raises alerts' }
)

if ($Status) {
    foreach ($t in $tasks) {
        $task = Get-ScheduledTask -TaskName $t.Name -ErrorAction SilentlyContinue
        if (-not $task) { "{0,-24} not registered" -f $t.Name; continue }
        $info = Get-ScheduledTaskInfo -TaskName $t.Name
        "{0,-24} {1,-10} last run {2}  result {3}" -f `
            $t.Name, $task.State, $info.LastRunTime, $info.LastTaskResult
    }
    # The task being "Running" is not proof the work is happening - check the store too.
    Push-Location $dir
    python -c "import net_store,time; c=net_store.connect(); b=c.execute('SELECT MAX(ts) FROM heartbeat').fetchone()[0]; print('last heartbeat %.1f min ago' % ((time.time()-b)/60) if b else 'no heartbeats yet')"
    Pop-Location
    return
}

if ($Uninstall) {
    foreach ($t in $tasks) {
        if (Get-ScheduledTask -TaskName $t.Name -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $t.Name -Confirm:$false
            "removed $($t.Name)"
        }
    }
    return
}

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -StartWhenAvailable
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
# Give non-boot volumes time to mount before the working directory is needed.
$trigger.Delay = 'PT1M'
# And retry for ever, because a delay is a guess and this one has already been wrong once.
# Borrowed from a throwaway -Once trigger; IgnoreNew makes the repeats free when it is up.
# Duration is left unset, which the Task Scheduler schema reads as "repeat indefinitely".
# [TimeSpan]::MaxValue looks like the way to say that and is not: it serialises to
# P99999999DT23H59M59S, which the service rejects outright - and because the script
# unregisters before it registers, that failure removes both tasks instead of leaving the
# working ones alone. That is fixed below by dropping the unregister entirely.
$rep = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 15)).Repetition
$rep.Duration = $null
$trigger.Repetition = $rep

foreach ($t in $tasks) {
    $action = New-ScheduledTaskAction -Execute $pythonw `
        -Argument "$($t.Script) -q" -WorkingDirectory $dir
    # No unregister first. -Force already replaces an existing task, and removing it up front
    # means any failure in Register-ScheduledTask leaves NOTHING registered - which is exactly
    # what happened when an invalid repetition duration was passed: a bad edit to this script
    # silently uninstalled a working monitor. Replacing in one step makes the operation
    # all-or-nothing.
    Register-ScheduledTask -TaskName $t.Name -Action $action -Trigger $trigger `
        -Settings $settings -Description $t.Desc -Force | Out-Null
    Start-ScheduledTask -TaskName $t.Name
    "registered and started $($t.Name)"
}

"`nboth run at every logon, restart on failure, one instance each."
"check with:  .\install_tasks.ps1 -Status"
