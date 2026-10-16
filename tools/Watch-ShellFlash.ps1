#Requires -Version 5.1
<#
.SYNOPSIS
    Watches for console windows that flash up for a split second and shows
    exactly which program opened them, its full command line and what started it.

.DESCRIPTION
    A window that flashes for a split second belongs to a process that only
    lives for a split second: too short for Task Manager, and too short for
    tools that poll the process list. So this script switches on Windows' own
    process-creation auditing (Security log, event 4688, with command lines).
    Windows then records every process that starts, however short-lived, and
    the script follows that log live.

    Reported:
      * every start of cmd, powershell, pwsh, wscript, cscript, mshta, wsl, bash
      * any other program that gets its own console window (a conhost.exe)
    For each one it shows the time, the full command line, the program's path,
    publisher and signature, the chain of processes that started it, the
    scheduled task behind it (when Task Scheduler started it) and a hint.
    Every hit is also appended to a CSV file.

    One-time setup done by the script (needs admin; stays on after the script
    exits, so you can also look back in time later with -LookBackMinutes):
      * audit policy "Process Creation" (success) on
      * command lines included in event 4688
      * Task Scheduler history on
      * Security log maximum size raised to 256 MB, so history lasts longer
    Run with -Disable to switch the first three off again.

    With -Inventory it instead takes a snapshot of what is on the PC right
    now: scheduled tasks that start console or script programs (the usual
    cause of a flash), autostart entries, WMI event consumers, and running
    processes and services not signed by Microsoft. Saved as
    shell-flash-inventory.txt next to this script.

.PARAMETER LookBackMinutes
    Also report what was recorded in the last N minutes. Handy right after you
    saw a flash, as long as the setup was done before it happened.

.PARAMETER All
    Report every process that starts, not only console ones.

.PARAMETER Beep
    Beep on every hit, so you can match a flash to a line on screen.

.PARAMETER LogPath
    CSV file hits are appended to. Default: shell-flash-log.csv next to this script.

.PARAMETER Disable
    Undo the setup and exit.

.PARAMETER Inventory
    Take the snapshot described above and exit. Changes nothing.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Watch-ShellFlash.ps1 -Beep

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Watch-ShellFlash.ps1 -Inventory

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Watch-ShellFlash.ps1 -LookBackMinutes 60

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Watch-ShellFlash.ps1 -Disable
#>
[CmdletBinding()]
param(
    [int]$LookBackMinutes = 0,
    [switch]$All,
    [switch]$Beep,
    [string]$LogPath,
    [switch]$Disable,
    [switch]$Inventory
)

# Programs reported every time they start.
$ShellNames = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'wsl.exe', 'bash.exe')
# Any other program is reported when Windows starts one of these for it, i.e. when it gets a console window.
$ConsoleHosts = @('conhost.exe', 'openconsole.exe')
# Windows' own launchers. Everything below them in a process chain belongs to whatever they started.
$SystemLaunchers = @('svchost.exe', 'taskhostw.exe', 'taskeng.exe', 'services.exe', 'wininit.exe', 'winlogon.exe', 'userinit.exe', 'wmiprvse.exe', 'explorer.exe')
$ScriptFiles = '(?i)\.(bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta)\b'
$UserWritable = '(?i)\\(AppData|Temp|Downloads|ProgramData|Users\\Public)\\'

$ProcessCreationGuid = '{0CCE922B-69AE-11D9-BED3-505054503030}'  # "Process Creation"; the GUID works on any Windows language
$AuditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$TaskLog = 'Microsoft-Windows-TaskScheduler/Operational'

$script:Seen = @{}        # pid -> record of every process start seen
$script:Reported = @{}    # pid -> start time of hits already reported
$script:FileInfo = @{}    # path -> publisher/signature text
$script:Pending = New-Object System.Collections.Generic.List[object]
$script:Bookmark = $null
$script:TaskActions = $null
$script:TaskActionsTime = [datetime]::MinValue

# ------------------------------------------------------------------ setup

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-StateFile { Join-Path $env:ProgramData 'Watch-ShellFlash\changes.json' }

function Enable-Tracing {
    # Remember what was on before the first setup, so that -Disable only undoes our own changes.
    $stateFile = Get-StateFile
    if (-not (Test-Path $stateFile)) {
        $cmdLine = Get-ItemProperty -Path $AuditKey -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
        $state = @{
            AuditWasOn   = [bool]@(Get-RecentProcessEvents 60).Count
            CmdLineValue = if ($cmdLine) { $cmdLine.ProcessCreationIncludeCmdLine_Enabled } else { $null }
            TaskLogWasOn = (Get-WinEvent -ListLog $TaskLog).IsEnabled
        }
        New-Item -ItemType Directory -Path (Split-Path $stateFile) -Force | Out-Null
        $state | ConvertTo-Json | Set-Content -Path $stateFile -Encoding UTF8
    }

    auditpol.exe /set "/subcategory:$ProcessCreationGuid" /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed (exit code $LASTEXITCODE)." }
    if (-not (Test-Path $AuditKey)) { New-Item -Path $AuditKey -Force | Out-Null }
    New-ItemProperty -Path $AuditKey -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
    wevtutil.exe sl $TaskLog /e:true | Out-Null
    if ((Get-WinEvent -ListLog Security).MaximumSizeInBytes -lt 256MB) { wevtutil.exe sl Security /ms:268435456 | Out-Null }
}

function Disable-Tracing {
    $stateFile = Get-StateFile
    $state = $null
    if (Test-Path $stateFile) { $state = Get-Content -Path $stateFile -Raw | ConvertFrom-Json }

    if (-not ($state -and $state.AuditWasOn)) {
        auditpol.exe /set "/subcategory:$ProcessCreationGuid" /success:disable | Out-Null
    }
    if ($state -and $null -ne $state.CmdLineValue) {
        New-ItemProperty -Path $AuditKey -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value $state.CmdLineValue -Force | Out-Null
    } else {
        Remove-ItemProperty -Path $AuditKey -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
    }
    if (-not ($state -and $state.TaskLogWasOn)) { wevtutil.exe sl $TaskLog /e:false | Out-Null }
    Remove-Item -Path $stateFile -ErrorAction SilentlyContinue
}

# Starts a harmless cmd.exe inside this console and checks that Windows logged it with its command line.
function Test-Tracing {
    $marker = 'shell-flash-selftest'
    $proc = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c rem $marker" -NoNewWindow -PassThru -Wait
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 500
        foreach ($record in @(Get-RecentProcessEvents 2)) {
            $p = ConvertFrom-ProcessEvent $record
            if ($p.Pid -eq $proc.Id) {
                if ($p.CommandLine -like "*$marker*") { return 'ok' }
                return 'no-command-line'
            }
        }
    }
    'not-logged'
}

# ------------------------------------------------------------ reading events

function New-SecurityQuery {
    New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*[System[EventID=4688]]')
}

# Process starts of the last $Minutes, oldest first. Reads newest-first and stops at
# the first older event, so a big Security log is not scanned end to end.
function Get-RecentProcessEvents([int]$Minutes) {
    $query = New-SecurityQuery
    $query.ReverseDirection = $true
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    $since = (Get-Date).AddMinutes(-$Minutes)
    $records = New-Object System.Collections.Generic.List[object]
    try {
        while (($record = $reader.ReadEvent()) -and $record.TimeCreated -ge $since) { $records.Add($record) }
    } finally { $reader.Dispose() }
    $records.Reverse()
    $records
}

function Get-NewestProcessEventBookmark {
    $query = New-SecurityQuery
    $query.ReverseDirection = $true
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    try {
        $record = $reader.ReadEvent()
        if ($record) { $record.Bookmark }
    } finally { $reader.Dispose() }
}

# Process starts logged since the last call.
function Read-NewProcessEvents {
    $query = New-SecurityQuery
    if ($script:Bookmark) {
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query, $script:Bookmark)
    } else {
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    }
    try {
        while ($record = $reader.ReadEvent()) {
            $script:Bookmark = $record.Bookmark
            $record
        }
    } finally { $reader.Dispose() }
}

function Get-EventData($Record) {
    $data = @{}
    foreach ($node in ([xml]$Record.ToXml()).Event.EventData.Data) { $data[$node.Name] = $node.InnerText }
    $data
}

function ConvertFrom-HexId([string]$Value) {
    if (-not $Value) { return [int64]0 }
    if ($Value.StartsWith('0x')) { return [Convert]::ToInt64($Value.Substring(2), 16) }
    [int64]$Value
}

function Get-LeafName([string]$Path) {
    if (-not $Path) { return '?' }
    ($Path -split '\\')[-1]
}

function New-ProcessRecord($Id, $Path, $CommandLine, $ParentId, $ParentPath, $Time, $User) {
    [pscustomobject]@{
        Pid         = [int64]$Id
        Name        = Get-LeafName $Path
        Path        = $Path
        CommandLine = $CommandLine
        ParentPid   = [int64]$ParentId
        ParentPath  = $ParentPath
        Time        = $Time
        User        = $User
    }
}

function ConvertFrom-ProcessEvent($Record) {
    $d = Get-EventData $Record
    # Target* names the new process's account when it differs from its creator's.
    if ($d.TargetUserName -and $d.TargetUserName -ne '-') { $user = $d.TargetUserName; $domain = $d.TargetDomainName }
    else { $user = $d.SubjectUserName; $domain = $d.SubjectDomainName }
    if ($user -like '*$') { $user = 'SYSTEM' } else { $user = "$domain\$user" }
    New-ProcessRecord (ConvertFrom-HexId $d.NewProcessId) $d.NewProcessName $d.CommandLine (ConvertFrom-HexId $d.ProcessId) $d.ParentProcessName $Record.TimeCreated $user
}

# ------------------------------------------------------- working out the origin

function Get-LiveProcess([int64]$Id) {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$Id" -ErrorAction SilentlyContinue
    if (-not $p) { return }
    $record = New-ProcessRecord $p.ProcessId $p.ExecutablePath $p.CommandLine $p.ParentProcessId $null $p.CreationDate $null
    if (-not $p.ExecutablePath) { $record.Name = $p.Name }   # protected processes such as services.exe hide their path
    $record
}

# The process with this ID that existed at $NotAfter (PIDs get reused, so later ones don't count).
function Find-Process([int64]$Id, $NotAfter) {
    $limit = $NotAfter.AddSeconds(1)
    $p = $script:Seen["$Id"]
    if ($p -and $p.Time -le $limit) { return $p }
    $p = Get-LiveProcess $Id
    if ($p -and $p.Time -le $limit) { return $p }
    $null
}

function Get-Ancestry($Proc) {
    $child = $Proc
    $visited = @{}
    for ($i = 0; $i -lt 8; $i++) {
        $id = $child.ParentPid
        if ($id -le 4 -or $visited["$id"]) { break }
        $visited["$id"] = $true
        $parent = Find-Process $id $child.Time
        if (-not $parent) {
            New-ProcessRecord $id $child.ParentPath '(already exited)' 0 $null $null $null
            break
        }
        $parent
        if ($parent.Name.ToLower() -in 'services.exe', 'wininit.exe', 'winlogon.exe', 'explorer.exe', 'smss.exe') { break }   # top of the interesting part
        $child = $parent
    }
}

function Format-ForMatch([string]$Text) { (($Text -replace '"', '') -replace '\s+', ' ').Trim().ToLower() }

function Get-TaskActions {
    if ($script:TaskActions -and ((Get-Date) - $script:TaskActionsTime).TotalMinutes -lt 10) { return $script:TaskActions }
    $list = @()
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        foreach ($action in @($task.Actions)) {
            if (-not $action.Execute) { continue }   # COM-handler actions run inside taskhostw.exe and have no Execute
            $exe = (Get-LeafName ([Environment]::ExpandEnvironmentVariables($action.Execute.Trim().Trim('"')))).ToLower()
            if ($exe -notlike '*.*') { $exe += '.exe' }
            $list += [pscustomobject]@{
                Task      = $task.TaskPath + $task.TaskName
                Exe       = $exe
                Arguments = Format-ForMatch ([Environment]::ExpandEnvironmentVariables("$($action.Arguments)"))
            }
        }
    }
    $script:TaskActions = $list
    $script:TaskActionsTime = Get-Date
    $list
}

function Find-ScheduledTask($Hit, $Chain) {
    $candidates = @($Hit)
    foreach ($p in $Chain) {
        if ($p.Name.ToLower() -in $SystemLaunchers) { break }
        $candidates += $p
    }

    # 1) Task Scheduler history: event 129 names the task and the process ID it started.
    foreach ($p in $candidates) {
        if (-not $p.Time) { continue }
        $filter = @{ LogName = $TaskLog; Id = 129; StartTime = $p.Time.AddSeconds(-5); EndTime = $p.Time.AddSeconds(5) }
        foreach ($record in @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)) {
            $data = Get-EventData $record
            if ((ConvertFrom-HexId $data.ProcessID) -eq $p.Pid) { return $data.TaskName }
        }
    }

    # 2) No history entry: compare the command lines with the actions of all scheduled tasks.
    $viaScheduler = $false
    foreach ($p in $Chain) { if ($p.Name.ToLower() -in 'svchost.exe', 'taskhostw.exe', 'taskeng.exe') { $viaScheduler = $true } }
    if (-not $viaScheduler) { return $null }
    $found = @()
    foreach ($p in $candidates) {
        $name = $p.Name.ToLower()
        $cmd = Format-ForMatch $p.CommandLine
        foreach ($action in (Get-TaskActions)) {
            if ($action.Exe -eq $name -and (-not $action.Arguments -or $cmd.Contains($action.Arguments))) { $found += $action.Task }
        }
    }
    $found = @($found | Select-Object -Unique -First 3)
    if ($found.Count) { return 'probably ' + ($found -join ' or ') }
    $null
}

function Get-FileInfo([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ Text = ''; Signed = $false; Microsoft = $false } }
    if ($script:FileInfo.ContainsKey($Path)) { return $script:FileInfo[$Path] }
    $parts = @()
    $signer = $null
    if (-not (Test-Path -LiteralPath $Path)) { $parts += 'file not found' }
    try {
        $company = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.CompanyName
        if ($company) { $parts += $company }
    } catch { }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ("$($sig.Status)" -eq 'Valid') {
            $signer = $sig.SignerCertificate.GetNameInfo('SimpleName', $false)
            $parts += "signed by $signer"
        } else { $parts += "NOT signed ($($sig.Status))" }
    } catch { }
    $info = [pscustomobject]@{ Text = $parts -join ', '; Signed = [bool]$signer; Microsoft = $signer -like 'Microsoft*' }
    $script:FileInfo[$Path] = $info
    $info
}

# The program a command line (service PathName, task action) starts.
function Get-ExePath([string]$CommandLine) {
    if (-not $CommandLine) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c.StartsWith('"')) { $exe = $c.Substring(1).Split('"')[0] }
    elseif ($c -match '^(.+?\.(exe|com|bat|cmd))(\s|$)') { $exe = $Matches[1] }   # unquoted path with spaces
    else { $exe = ($c -split '\s+')[0] }
    if ($exe -notmatch '\\') {
        $cmd = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { $exe = $cmd.Source }
    }
    $exe
}

function Get-Hints($Hit, $Chain, $Task) {
    $name = $Hit.Name.ToLower()
    if ($Task) {
        if ($Task -like 'probably *') { $how = 'Most likely started by scheduled task' } else { $how = 'Started by scheduled task' }
        "$how $($Task -replace '^probably ', ''). Open Task Scheduler (taskschd.msc), find it in the library and look at its Actions tab; disable it there if you don't want it."
    } else {
        $origin = $null
        $originIndex = 0
        foreach ($p in $Chain) {
            $origin = switch ($p.Name.ToLower()) {
                'svchost.exe' {
                    if ($p.CommandLine -match '-s\s+(\S+)') {
                        if ($Matches[1] -eq 'Schedule') { 'Task Scheduler' } else { "the Windows service '$($Matches[1])'" }
                    } else { 'a Windows service host, most likely Task Scheduler' }
                }
                'taskhostw.exe' { 'Task Scheduler' }
                'taskeng.exe' { 'Task Scheduler' }
                'services.exe' { 'a Windows service' }
                'wmiprvse.exe' { 'WMI (a WMI event subscription, or a management tool using WMI)' }
                'scrcons.exe' { 'a WMI event subscription' }
                'explorer.exe' { 'Explorer: something you clicked, a shortcut, the Startup folder or a Run registry key at sign-in' }
                'userinit.exe' { 'your sign-in (a logon script or Run registry key)' }
                'winlogon.exe' { 'your sign-in (a logon script or Run registry key)' }
            }
            if ($origin) { break }
            $originIndex++
        }
        if ($origin -and $originIndex -gt 0) { "Started by $($Chain[0].Name) ($($Chain[0].Path)), which was itself launched via $origin." }
        elseif ($origin) { "Launched via $origin." }
        elseif ($Chain) { "Started by $($Chain[0].Name) ($($Chain[0].Path)): that program is the one to look at." }
        else { 'What started it could not be traced (it started before this watch and has exited). Run -Inventory to list likely candidates.' }
        if ($origin -like 'WMI*' -or $origin -like 'a WMI*') {
            'List WMI subscriptions with: Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer'
        }
    }
    if ($name -in 'powershell.exe', 'pwsh.exe' -and $Hit.CommandLine -match '(?i)\s[-/]w\w*\s+(hidden|h|1)\b') {
        'PowerShell started with a "hidden" window still shows a console for a split second while it starts: a classic cause of exactly this flash.'
    }
    if ($name -in 'wscript.exe', 'cscript.exe', 'mshta.exe') {
        'This is a script host: the script file named in the command line is what actually runs.'
    }
    if ($Hit.Path -match $UserWritable -and -not (Get-FileInfo $Hit.Path).Signed) {
        'It runs from a user-writable folder and has no valid signature: worth a closer look (e.g. upload the file to virustotal.com).'
    } elseif ($name -in $ShellNames -and $Hit.CommandLine -match $UserWritable) {
        'The command line points into a user-writable folder: look at that file to see what it does.'
    }
    if ($Hit.User -eq 'SYSTEM' -or $Hit.User -like 'NT AUTHORITY\*') {
        'It ran under a background account, and those normally cannot show a window on your desktop: probably not the flash you saw.'
    }
}

# ---------------------------------------------------------------- reporting

function Write-Hit($Hit, [string]$Note) {
    $chain = @(Get-Ancestry $Hit)
    $task = Find-ScheduledTask $Hit $chain
    $hints = @(Get-Hints $Hit $chain $task)
    $command = if ($Hit.CommandLine) { $Hit.CommandLine } else { '(not recorded)' }

    Write-Host ''
    Write-Host ('[{0:yyyy-MM-dd HH:mm:ss.fff}] {1}  (pid {2}){3}' -f $Hit.Time, $Hit.Name, $Hit.Pid, $Note) -ForegroundColor Yellow
    Write-Host "  Command : $command"
    Write-Host "  Program : $($Hit.Path)  [$((Get-FileInfo $Hit.Path).Text)]"
    if ($Hit.User) { Write-Host "  User    : $($Hit.User)" }
    if ($chain) {
        Write-Host '  Started by:'
        foreach ($p in $chain) { Write-Host "    <- $($p.Name) (pid $($p.Pid))  $($p.CommandLine)" -ForegroundColor Gray }
    }
    if ($task) { Write-Host "  Task    : $task" -ForegroundColor Cyan }
    foreach ($h in $hints) { Write-Host "  Hint    : $h" -ForegroundColor Green }
    if ($Beep) { [Console]::Beep(880, 150) }

    $row = [pscustomobject]@{
        Time          = '{0:yyyy-MM-dd HH:mm:ss.fff}' -f $Hit.Time
        Program       = $Hit.Name
        Pid           = $Hit.Pid
        CommandLine   = $Hit.CommandLine
        Path          = $Hit.Path
        Publisher     = (Get-FileInfo $Hit.Path).Text
        User          = $Hit.User
        StartedBy     = ($chain | ForEach-Object { "$($_.Name) (pid $($_.Pid)) $($_.CommandLine)" }) -join ' <- '
        ScheduledTask = $task
        Hint          = $hints -join ' '
    }
    try { $row | Export-Csv -Path $LogPath -Append -NoTypeInformation -Encoding UTF8 }
    catch { Write-Warning "Could not write to $LogPath (open in Excel?): $($_.Exception.Message)" }
}

function Invoke-ProcessEvent($Proc, [bool]$Report) {
    $script:Seen["$($Proc.Pid)"] = $Proc
    if (-not $Report -or $Proc.ParentPid -eq $PID) { return }   # skip what this script starts itself
    $name = $Proc.Name.ToLower()
    $hit = $null
    $note = ''
    if ($All -or $name -in $ShellNames) {
        $hit = $Proc
    } elseif ($name -in $ConsoleHosts -and $Proc.CommandLine -notmatch '--headless') {
        # A console window was created for the parent. Report the parent, unless that was done already.
        $seenAt = $script:Reported["$($Proc.ParentPid)"]
        if ($seenAt -and [Math]::Abs(($Proc.Time - $seenAt).TotalSeconds) -lt 30) { return }
        $hit = Find-Process $Proc.ParentPid $Proc.Time
        if (-not $hit) { $hit = New-ProcessRecord $Proc.ParentPid $Proc.ParentPath '(exited before it could be looked up)' 0 $null $Proc.Time $Proc.User }
        $note = '  - opened a console window'
    }
    if (-not $hit) { return }
    $script:Reported["$($hit.Pid)"] = $hit.Time
    Write-Hit $hit $note
}

function Invoke-Poll {
    foreach ($record in @(Read-NewProcessEvents)) { $script:Pending.Add((ConvertFrom-ProcessEvent $record)) }
    # Handle each start ~2 s late, so that Task Scheduler's own log entry for it exists by then.
    $cutoff = (Get-Date).AddSeconds(-2)
    while ($script:Pending.Count -and $script:Pending[0].Time -le $cutoff) {
        Invoke-ProcessEvent $script:Pending[0] $true
        $script:Pending.RemoveAt(0)
    }

    if ($script:Seen.Count -gt 50000) {
        $old = (Get-Date).AddHours(-1)
        foreach ($key in @($script:Seen.Keys)) { if ($script:Seen[$key].Time -lt $old) { $script:Seen.Remove($key) } }
    }
    $old = (Get-Date).AddMinutes(-5)
    foreach ($key in @($script:Reported.Keys)) { if ($script:Reported[$key] -lt $old) { $script:Reported.Remove($key) } }
}

function Start-Watch {
    # Load a few minutes of history so parents that started just before now can still be named.
    $history = @(Get-RecentProcessEvents ([Math]::Max($LookBackMinutes, 10)))
    if ($history.Count) { $script:Bookmark = $history[-1].Bookmark } else { $script:Bookmark = Get-NewestProcessEventBookmark }
    $reportFrom = (Get-Date).AddMinutes(-$LookBackMinutes)
    foreach ($record in $history) {
        Invoke-ProcessEvent (ConvertFrom-ProcessEvent $record) ($LookBackMinutes -gt 0 -and $record.TimeCreated -ge $reportFrom)
    }
    if ($LookBackMinutes -gt 0) {
        Write-Host ''
        Write-Host "---- end of the last $LookBackMinutes minutes, now watching live ----" -ForegroundColor Magenta
    }
    while ($true) {
        Start-Sleep -Seconds 1
        Invoke-Poll
    }
}

# ---------------------------------------------------------------- inventory

function Out-Line([string]$Text = '', [string]$Color = 'Gray') {
    Write-Host $Text -ForegroundColor $Color
    $script:Report.Add($Text)
}

# $Command is the full command line, so a script in AppData run by a Microsoft-signed host still gets flagged.
function Get-Flag($Command, $Info) {
    if (-not $Info.Signed) { return '!!' }
    if ($Command -match $UserWritable) { return '! ' }
    '  '
}

function Format-RunTime($Time) {
    if (-not $Time -or $Time.Year -lt 2000) { return '-' }
    '{0:yyyy-MM-dd HH:mm}' -f $Time
}

function Format-Trigger($Trigger) {
    $kind = $Trigger.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', ''
    if (-not $kind) { $kind = 'other' }
    if ($Trigger.Repetition -and $Trigger.Repetition.Interval) {
        try { $kind += ' every ' + [System.Xml.XmlConvert]::ToTimeSpan($Trigger.Repetition.Interval) } catch { }
    }
    $kind
}

function Show-ScheduledTaskSuspects {
    Out-Line ''
    Out-Line '== Scheduled tasks that start a console/script program or non-Microsoft software ==' 'Yellow'
    Out-Line '   Only tasks marked VISIBLE run in your session and can flash a window on your desktop.'
    $rows = @()
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { "$($_.State)" -ne 'Disabled' })) {
        foreach ($action in @($task.Actions)) {
            if (-not $action.Execute) { continue }   # COM-handler actions start no program of their own
            $exe = Get-ExePath $action.Execute
            $info = Get-FileInfo $exe
            $console = ((Get-LeafName $exe).ToLower() -in $ShellNames) -or ("$($action.Execute) $($action.Arguments)" -match $ScriptFiles)
            if (-not $console -and $info.Microsoft) { continue }
            $rows += [pscustomobject]@{
                Task    = $task
                Action  = $action
                Exe     = $exe
                Info    = $info
                Console = $console
                Visible = "$($task.Principal.LogonType)" -in 'Interactive', 'InteractiveOrPassword', 'Group'
            }
        }
    }
    if (-not $rows) { Out-Line '   (none)' }
    foreach ($row in ($rows | Sort-Object @{ Expression = 'Visible'; Descending = $true }, @{ Expression = 'Console'; Descending = $true })) {
        $t = $row.Task
        $who = if ($t.Principal.UserId) { $t.Principal.UserId } else { $t.Principal.GroupId }
        if ($row.Visible) { $where = 'VISIBLE, runs in your session'; $color = 'White' } else { $where = 'background'; $color = 'Gray' }
        $taskInfo = Get-ScheduledTaskInfo -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction SilentlyContinue
        $triggers = @($t.Triggers | ForEach-Object { Format-Trigger $_ }) -join ', '
        if (-not $triggers) { $triggers = 'no trigger (started on demand)' }
        Out-Line ('{0} {1}{2}   [{3}, as {4}]' -f (Get-Flag "$($row.Exe) $($row.Action.Arguments)" $row.Info), $t.TaskPath, $t.TaskName, $where, $who) $color
        Out-Line "     Runs    : $($row.Action.Execute) $($row.Action.Arguments)"
        Out-Line "     Program : $($row.Exe)  [$($row.Info.Text)]"
        Out-Line "     When    : $triggers; last run $(Format-RunTime $taskInfo.LastRunTime), next run $(Format-RunTime $taskInfo.NextRunTime)"
    }
}

function Show-Autostart {
    Out-Line ''
    Out-Line '== Autostart entries (Run keys and Startup folders) ==' 'Yellow'
    $count = 0
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        $item = Get-Item -Path $key -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($name in $item.GetValueNames()) {
            $command = "$($item.GetValue($name))"
            $exe = Get-ExePath $command
            $info = Get-FileInfo $exe
            Out-Line ('{0} {1}   [{2}]' -f (Get-Flag $command $info), $name, $key)
            Out-Line "     Runs    : $command"
            Out-Line "     Program : $exe  [$($info.Text)]"
            $count++
        }
    }
    foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        if (-not $folder) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $exe = $file.FullName
            $runs = $exe
            if ($file.Extension -eq '.lnk') {
                $link = (New-Object -ComObject WScript.Shell).CreateShortcut($file.FullName)
                $exe = $link.TargetPath
                $runs = "$($link.TargetPath) $($link.Arguments)".Trim()
            }
            $info = Get-FileInfo $exe
            Out-Line ('{0} {1}   [Startup folder {2}]' -f (Get-Flag $runs $info), $file.Name, $folder)
            Out-Line "     Runs    : $runs"
            Out-Line "     Program : $exe  [$($info.Text)]"
            $count++
        }
    }
    if (-not $count) { Out-Line '   (none)' }
}

function Show-WmiConsumers {
    Out-Line ''
    Out-Line '== WMI event consumers that run commands or scripts ==' 'Yellow'
    $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Where-Object { $_.CimClass.CimClassName -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer' })
    foreach ($c in $consumers) {
        $runs = $c.CommandLineTemplate
        if (-not $runs) { $runs = $c.ScriptFileName }
        if (-not $runs) { $runs = ("$($c.ScriptText)" -replace '\s+', ' ') }
        if ($runs.Length -gt 300) { $runs = $runs.Substring(0, 300) + '...' }
        Out-Line "!! $($c.Name)   [$($c.CimClass.CimClassName)]" 'White'
        Out-Line "     Runs    : $runs"
    }
    if (-not $consumers) { Out-Line '   (none - good, these are rare and often malicious)' }
}

function Show-Processes {
    Out-Line ''
    Out-Line '== Running programs not signed by Microsoft ==' 'Yellow'
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $names = @{}
    foreach ($p in $all) { $names["$($p.ProcessId)"] = $p.Name }
    $groups = @($all | Where-Object { $_.ExecutablePath } | Group-Object ExecutablePath)
    Write-Host "   (checking the signatures of $($groups.Count) programs, this can take a moment...)" -ForegroundColor DarkGray
    $rows = @(foreach ($g in $groups) {
        $info = Get-FileInfo $g.Name
        if ($info.Microsoft) { continue }
        [pscustomobject]@{ Path = $g.Name; Info = $info; Procs = @($g.Group) }
    })
    if (-not $rows) { Out-Line '   (none)' }
    foreach ($row in ($rows | Sort-Object @{ Expression = { $_.Info.Signed } }, Path)) {
        $first = $row.Procs[0]
        $count = if ($row.Procs.Count -gt 1) { " x$($row.Procs.Count)" } else { '' }
        $ids = ($row.Procs | Select-Object -First 5 | ForEach-Object { $_.ProcessId }) -join ', '
        Out-Line ('{0} {1}{2}   (pid {3})' -f (Get-Flag $row.Path $row.Info), $first.Name, $count, $ids)
        Out-Line "     Program : $($row.Path)  [$($row.Info.Text)]"
        if (-not $row.Info.Signed -or $row.Path -match $UserWritable) {
            Out-Line "     Command : $($first.CommandLine)"
            Out-Line "     Parent  : $($names["$($first.ParentProcessId)"]) (pid $($first.ParentProcessId))"
        }
    }
}

function Show-Services {
    Out-Line ''
    Out-Line '== Services (Dienste) not signed by Microsoft ==' 'Yellow'
    $rows = @(foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $exe = Get-ExePath $s.PathName
        $info = Get-FileInfo $exe
        if ($info.Microsoft) { continue }
        [pscustomobject]@{ Service = $s; Exe = $exe; Info = $info }
    })
    if (-not $rows) { Out-Line '   (none)' }
    foreach ($row in ($rows | Sort-Object @{ Expression = { $_.Service.State -ne 'Running' } }, @{ Expression = { $_.Service.DisplayName } })) {
        $s = $row.Service
        Out-Line ('{0} {1} ({2})   [{3}, start: {4}]' -f (Get-Flag $s.PathName $row.Info), $s.DisplayName, $s.Name, $s.State, $s.StartMode)
        Out-Line "     Program : $($s.PathName)  [$($row.Info.Text)]"
    }
}

function Show-Inventory {
    $script:Report = New-Object System.Collections.Generic.List[string]
    $reportPath = Join-Path $PSScriptRoot 'shell-flash-inventory.txt'
    Out-Line "Inventory of $env:COMPUTERNAME, $(Get-Date -Format 'yyyy-MM-dd HH:mm')" 'Green'
    Out-Line '!! = no valid signature   ! = runs from a user-writable folder   Microsoft-signed items are left out.'
    Show-ScheduledTaskSuspects
    Show-Autostart
    Show-WmiConsumers
    Show-Processes
    Show-Services
    $script:Report | Set-Content -Path $reportPath -Encoding UTF8
    Write-Host ''
    Write-Host "Saved to $reportPath" -ForegroundColor Green
}

# ------------------------------------------------------------------- main

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced: only load the functions

if (-not (Test-IsAdmin)) {
    Write-Host 'Administrator rights are needed to read the Security log - asking for them...'
    $argList = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) { if ($kv.Value) { $argList += "-$($kv.Key)" } }
        else { $argList += "-$($kv.Key)", "`"$($kv.Value)`"" }
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    return
}

if ($Inventory) {
    Show-Inventory
    return
}

if ($Disable) {
    Disable-Tracing
    Write-Host 'Process-creation auditing and Task Scheduler history are back to how they were.' -ForegroundColor Green
    Write-Host 'The Security log keeps its larger maximum size (harmless; change it in Event Viewer if you like).'
    return
}

if (-not $LogPath) { $LogPath = Join-Path $PSScriptRoot 'shell-flash-log.csv' }
$Host.UI.RawUI.WindowTitle = 'Shell flash watch - Ctrl+C to stop'

Enable-Tracing
switch (Test-Tracing) {
    'ok' { }
    'no-command-line' { Write-Warning 'Process starts are logged, but without command lines (a group policy may override this). You will still see the programs and their parents.' }
    'not-logged' {
        Write-Warning 'Windows did not log a test process start. A group policy probably overrides the audit settings; check "auditpol /get /category:*". Watching anyway.'
    }
}

Write-Host ''
Write-Host 'Watching for console windows. Leave this window open; press Ctrl+C to stop.' -ForegroundColor Green
Write-Host "Every hit is also written to $LogPath"
Write-Host 'Not every hit is a visible window: compare the time with when you saw the flash.'
Write-Host 'Auditing stays on after you stop, so later you can run again with -LookBackMinutes 60 to see what happened.'
Write-Host 'For a snapshot of scheduled tasks, autostarts, running programs and services, run again with -Inventory.'
Start-Watch
