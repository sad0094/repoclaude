<#
Nobet Agent for Windows Server 2016+ (Windows PowerShell 5.1, no extra modules).

Collects and reports to the Nobet Manager:
  * host metrics (CPU, memory, fixed disks, network throughput)
  * every device on the local subnet (ARP / neighbor table)
  * inbound TCP connection attempts
      capture = "audit": Windows Filtering Platform audit events 5156/5157/5152
                         (allowed + blocked attempts; needs the audit policy that
                         install.ps1 -EnableConnectionAudit turns on)
      capture = "poll" : established connections only (no policy change needed)
  * Windows logon attempts (Security events 4625 failed, 4624 successful; network and RDP)

Usage:
  nobet-agent.ps1                      # uses %ProgramData%\Nobet\agent.json
  nobet-agent.ps1 -Manager https://panel.example.com -Token nbt_... -Print

NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads BOM-less scripts in the
system ANSI code page, so non-ASCII characters would be corrupted.
#>
[CmdletBinding()]
param(
    [string]$Config = (Join-Path $env:ProgramData 'Nobet\agent.json'),
    [string]$Manager,
    [string]$Token,
    [switch]$Once,
    [switch]$Print
)

$ErrorActionPreference = 'Stop'
# Invariant culture: avoids the Turkish dotless-i casing problem and decimal commas in JSON.
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
try {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
} catch { }

$script:Version = '0.1.0-win'
$script:MaxPending = 20000
$script:Names = @{}          # ip -> reverse DNS name cache
$script:PendingConn = @{}    # "src|port|open" -> count
$script:PendingAuth = @{}    # "src|user|result|port" -> count
$script:SeenConn = @{}       # poll mode: currently established tuples
$script:PollReady = $false
$script:LastRecord = [long]-1
$script:LastScan = [datetime]::MinValue
$script:PrevNet = $null
$script:PrevTime = Get-Date
$script:LogFile = Join-Path (Split-Path -Parent $Config) 'agent.log'

function Write-Log([string]$Message) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    try {
        if ((Test-Path -LiteralPath $script:LogFile) -and ((Get-Item -LiteralPath $script:LogFile).Length -gt 1MB)) {
            Remove-Item -LiteralPath $script:LogFile -Force
        }
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding ASCII
    } catch { }
}

function Get-AgentConfig {
    $cfg = @{ manager = ''; token = ''; interval = 30; scan_interval = 300; capture = 'poll'; discovery = $true; subnets = @() }
    if (Test-Path -LiteralPath $Config) {
        $json = Get-Content -LiteralPath $Config -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $json.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
    }
    if ($Manager) { $cfg.manager = $Manager }
    if ($Token) { $cfg.token = $Token }
    if (-not $cfg.manager -or -not $cfg.token) { throw 'manager address and token are required (config file or -Manager/-Token)' }
    return $cfg
}

# ------------------------------------------------------------------ IPv4 helpers
function ConvertTo-UInt32([string]$Ip) {
    $bytes = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-UInt32([long]$Value) {
    $bytes = [System.BitConverter]::GetBytes([uint32]$Value)
    [Array]::Reverse($bytes)
    return (New-Object System.Net.IPAddress (, $bytes)).ToString()
}

function Get-NetworkRange([string]$Ip, [int]$Prefix) {
    # Returns the usable host range of the subnet as numbers.
    $size = [long][Math]::Pow(2, 32 - $Prefix)
    $address = [long](ConvertTo-UInt32 $Ip)
    $network = $address - ($address % $size)
    return @{ Cidr = ('{0}/{1}' -f (ConvertFrom-UInt32 $network), $Prefix); First = $network + 1; Last = $network + $size - 2 }
}

function Get-LocalNetworks($cfg) {
    # Returns @{ Ips = <set of own IPv4 addresses>; Nets = <ranges to scan> }
    $ips = @{}
    $nets = @()
    foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        $ip = [string]$a.IPAddress
        if ($ip -like '127.*' -or $ip -like '169.254.*') { continue }
        $ips[$ip] = $true
        $alias = [string]$a.InterfaceAlias
        if ($alias -like 'vEthernet*' -or $alias -like '*Loopback*') { continue }
        # Very large subnets are limited to a /22 slice around the server.
        $nets += (Get-NetworkRange $ip ([Math]::Max([int]$a.PrefixLength, 22)))
    }
    if (@($cfg.subnets).Count -gt 0) {
        $nets = @()
        foreach ($cidr in @($cfg.subnets)) {
            $parts = ([string]$cidr).Split('/')
            $nets += (Get-NetworkRange $parts[0] ([int]$parts[1]))
        }
    }
    return @{ Ips = $ips; Nets = $nets }
}

function Test-InNetworks([string]$Ip, $Nets) {
    try { $n = [long](ConvertTo-UInt32 $Ip) } catch { return $false }
    foreach ($net in $Nets) { if ($n -ge $net.First -and $n -le $net.Last) { return $true } }
    return $false
}

# ------------------------------------------------------------------ discovery
function Resolve-NameFast([string]$Ip) {
    $name = ''
    try {
        $task = [System.Net.Dns]::GetHostEntryAsync($Ip)
        if ($task.Wait(400)) { $name = [string]$task.Result.HostName }
    } catch { }
    $script:Names[$Ip] = $name
    return $name
}

function Invoke-Discovery($Nets) {
    # Send one empty UDP datagram to every address so Windows resolves its MAC,
    # then read the neighbor (ARP) table. No ICMP and no extra tools needed.
    $udp = New-Object System.Net.Sockets.UdpClient
    $payload = [byte[]]@(0)
    $sent = 0
    foreach ($net in $Nets) {
        for ($i = [long]$net.First; $i -le [long]$net.Last; $i++) {
            try { [void]$udp.Send($payload, 1, (ConvertFrom-UInt32 $i), 9) } catch { }
            $sent++
            if ($sent % 64 -eq 0) { Start-Sleep -Milliseconds 50 }
        }
    }
    $udp.Close()
    Start-Sleep -Seconds 2

    $gateways = @{}
    foreach ($r in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) { $gateways[[string]$r.NextHop] = $true }
    $devices = @()
    $seen = @{}
    $lookups = 0
    foreach ($nb in @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        $state = [string]$nb.State
        if ($state -eq 'Unreachable' -or $state -eq 'Incomplete' -or $state -eq 'Permanent') { continue }
        $ip = [string]$nb.IPAddress
        $mac = ([string]$nb.LinkLayerAddress).ToLowerInvariant().Replace('-', ':')
        if ($mac.Length -ne 17 -or $mac -eq '00:00:00:00:00:00' -or $mac -eq 'ff:ff:ff:ff:ff:ff' -or $mac.StartsWith('01:00:5e')) { continue }
        if ($seen.ContainsKey($mac) -or -not (Test-InNetworks $ip $Nets)) { continue }
        $seen[$mac] = $true
        $name = ''
        if ($script:Names.ContainsKey($ip)) { $name = $script:Names[$ip] }
        elseif ($lookups -lt 60) { $lookups++; $name = Resolve-NameFast $ip }   # the rest resolve on later scans
        $devices += @{ ip = $ip; mac = $mac; iface = [string]$nb.InterfaceAlias; hostname = $name; gateway = $gateways.ContainsKey($ip) }
    }
    return , $devices
}

# ------------------------------------------------------------------ metrics
function Get-Metrics {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cpu = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    if ($null -eq $cpu) { $cpu = 0 }
    $total = [long]$os.TotalVisibleMemorySize * 1024
    $used = $total - ([long]$os.FreePhysicalMemory * 1024)
    $memPct = 0
    if ($total -gt 0) { $memPct = [Math]::Round($used * 100.0 / $total, 1) }

    $disks = @()
    foreach ($d in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
        if (-not $d.Size) { continue }
        $size = [long]$d.Size
        $usedBytes = $size - [long]$d.FreeSpace
        $disks += @{ mount = [string]$d.DeviceID; total = $size; used = $usedBytes; pct = [Math]::Round($usedBytes * 100.0 / $size, 1) }
    }

    $rx = [long]0; $tx = [long]0
    foreach ($s in @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) { $rx += [long]$s.ReceivedBytes; $tx += [long]$s.SentBytes }
    $now = Get-Date
    $rxBps = 0; $txBps = 0
    if ($null -ne $script:PrevNet) {
        $elapsed = [Math]::Max(($now - $script:PrevTime).TotalSeconds, 0.001)
        $rxBps = [long]([Math]::Max($rx - $script:PrevNet[0], 0) * 8 / $elapsed)
        $txBps = [long]([Math]::Max($tx - $script:PrevNet[1], 0) * 8 / $elapsed)
    }
    $script:PrevNet = @($rx, $tx)
    $script:PrevTime = $now

    return @{
        Uptime  = [long]($now - $os.LastBootUpTime).TotalSeconds
        OsName  = [string]$os.Caption
        Metrics = @{ cpu = [Math]::Round([double]$cpu, 1); mem_pct = $memPct; mem_used = $used; mem_total = $total
                     rx_bps = $rxBps; tx_bps = $txBps; disks = $disks }
    }
}

function Get-ListeningPorts {
    return , @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty LocalPort | Sort-Object -Unique | ForEach-Object { [int]$_ })
}

function Get-MachineId {
    try { return [string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid }
    catch { return $env:COMPUTERNAME }
}

function Get-PrimaryIp($cfg, $LocalIps) {
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Connect(([System.Uri]$cfg.manager).Host, 9)
        $ip = $udp.Client.LocalEndPoint.Address.ToString()
        $udp.Close()
        if ($ip -notlike '127.*' -and $ip -ne '::1') { return $ip }
    } catch { }
    return [string](@($LocalIps.Keys) | Select-Object -First 1)
}

# ------------------------------------------------------------------ connections and logons
function Add-Count($Table, [string]$Key, [int]$Count = 1) {
    if ($Table.ContainsKey($Key)) { $Table[$Key] += $Count }
    elseif ($Table.Count -lt $script:MaxPending) { $Table[$Key] = $Count }
}

function Test-RemoteAddress([string]$Ip, $LocalIps) {
    if (-not $Ip -or $Ip -eq '-' -or $Ip -eq '::1' -or $Ip -like '127.*') { return $false }
    return -not $LocalIps.ContainsKey($Ip)
}

function Get-EventFields($Record) {
    # ($Event is an automatic variable in PowerShell, so the parameter must not use that name.)
    $map = @{}
    $xml = [xml]$Record.ToXml()
    foreach ($node in $xml.Event.EventData.ChildNodes) {
        if ($node.NodeType -eq 'Element') { $map[$node.GetAttribute('Name')] = $node.InnerText }
    }
    return $map
}

function Get-SecurityEvents([string]$Filter, [long]$From, [long]$To) {
    $xpath = "*[System[($Filter) and EventRecordID>$From and EventRecordID<=$To]]"
    return @(Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents 5000 -ErrorAction SilentlyContinue)
}

function Read-SecurityLog($cfg, $LocalIps) {
    # Reads only records written since the previous cycle (tracked by EventRecordID).
    $newest = @(Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue)
    if ($newest.Count -eq 0) { return }
    $top = [long]$newest[0].RecordId
    if ($script:LastRecord -lt 0 -or $top -lt $script:LastRecord) {   # first run or log cleared: do not replay history
        $script:LastRecord = $top
        return
    }
    $from = $script:LastRecord

    if ($cfg.capture -eq 'audit') {
        # 5156 = connection allowed, 5157 = connection blocked, 5152 = packet dropped.
        # Which side is "source" differs between these events, so the remote side is
        # decided by comparing both addresses with this server's own addresses.
        foreach ($ev in (Get-SecurityEvents 'EventID=5156 or EventID=5157 or EventID=5152' $from $top)) {
            $f = Get-EventFields $ev
            if ($f['Protocol'] -ne '6' -or $f['Direction'] -ne '%%14592') { continue }   # inbound TCP only
            $src = [string]$f['SourceAddress']; $dst = [string]$f['DestAddress']
            if ($LocalIps.ContainsKey($dst) -and (Test-RemoteAddress $src $LocalIps)) { $remote = $src; $port = $f['DestPort'] }
            elseif ($LocalIps.ContainsKey($src) -and (Test-RemoteAddress $dst $LocalIps)) { $remote = $dst; $port = $f['SourcePort'] }
            else { continue }
            $open = 0
            if ($ev.Id -eq 5156) { $open = 1 }
            Add-Count $script:PendingConn ('{0}|{1}|{2}' -f $remote, $port, $open)
        }
    }

    # Logons: type 3 = network (SMB, NLA), type 10 = RDP.
    foreach ($ev in (Get-SecurityEvents 'EventID=4625 or EventID=4624' $from $top)) {
        $f = Get-EventFields $ev
        $type = [string]$f['LogonType']
        if ($type -ne '3' -and $type -ne '10') { continue }
        $ip = ([string]$f['IpAddress']) -replace '^::ffff:', ''
        $user = [string]$f['TargetUserName']
        # S-1-5-7 = anonymous logon (compared by SID because the account name is localized)
        if (-not (Test-RemoteAddress $ip $LocalIps) -or -not $user -or $user.EndsWith('$') -or $f['TargetUserSid'] -eq 'S-1-5-7') { continue }
        $result = 'ok'
        if ($ev.Id -eq 4625) { $result = 'fail' }
        $port = ''
        if ($type -eq '10') { $port = '3389' }
        Add-Count $script:PendingAuth ('{0}|{1}|{2}|{3}' -f $ip, $user, $result, $port)
    }
    $script:LastRecord = $top
}

function Update-PolledConnections($LocalIps) {
    # Poll mode: count newly established inbound connections to listening ports.
    $listening = @{}
    foreach ($p in (Get-ListeningPorts)) { $listening[[int]$p] = $true }
    $current = @{}
    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
        $remote = [string]$c.RemoteAddress
        if (-not $listening.ContainsKey([int]$c.LocalPort) -or -not (Test-RemoteAddress $remote $LocalIps)) { continue }
        $key = '{0}|{1}|{2}' -f $remote, $c.RemotePort, $c.LocalPort
        $current[$key] = $true
        if (-not $script:SeenConn.ContainsKey($key) -and $script:PollReady) {
            Add-Count $script:PendingConn ('{0}|{1}|1' -f $remote, $c.LocalPort)
        }
    }
    $script:SeenConn = $current
    $script:PollReady = $true   # connections that existed at startup are not counted as new
}

# ------------------------------------------------------------------ report
function New-Report($cfg, $Local) {
    $m = Get-Metrics
    try { Read-SecurityLog $cfg $Local.Ips } catch { Write-Log ('security log read failed: ' + $_.Exception.Message) }
    if ($cfg.capture -eq 'poll') { Update-PolledConnections $Local.Ips }

    $connections = @()
    foreach ($key in @($script:PendingConn.Keys)) {
        $p = $key.Split('|')
        $connections += @{ src = $p[0]; port = [int]$p[1]; open = ($p[2] -eq '1'); count = [int]$script:PendingConn[$key] }
    }
    $auth = @()
    foreach ($key in @($script:PendingAuth.Keys)) {
        $p = $key.Split('|')
        $entry = @{ src = $p[0]; user = $p[1]; result = $p[2]; service = 'windows'; count = [int]$script:PendingAuth[$key] }
        if ($p[3]) { $entry.port = [int]$p[3] }
        $auth += $entry
    }

    $report = @{
        agent_version = $script:Version
        capture_mode  = [string]$cfg.capture
        host          = @{ id = (Get-MachineId); hostname = $env:COMPUTERNAME; os = $m.OsName; ip = (Get-PrimaryIp $cfg $Local.Ips)
                           uptime_s = $m.Uptime; cores = [Environment]::ProcessorCount }
        metrics       = $m.Metrics
        listening     = (Get-ListeningPorts)
        subnets       = @($Local.Nets | ForEach-Object { $_.Cidr })
        connections   = $connections
        auth          = $auth
    }
    if ($cfg.discovery -and ((Get-Date) - $script:LastScan).TotalSeconds -ge [int]$cfg.scan_interval) {
        $report.devices = (Invoke-Discovery $Local.Nets)
        $script:LastScan = Get-Date
    }
    return $report
}

function Send-Report($cfg, $Report) {
    $json = $Report | ConvertTo-Json -Depth 6 -Compress
    $body = [System.Text.Encoding]::UTF8.GetBytes($json)
    Invoke-RestMethod -Uri ($cfg.manager.TrimEnd('/') + '/api/agent/report') -Method Post -Body $body `
        -ContentType 'application/json' -Headers @{ Authorization = 'Bearer ' + $cfg.token } `
        -UserAgent ('nobet-agent/' + $script:Version) -TimeoutSec 20 -UseBasicParsing | Out-Null
}

function Invoke-Cycle($cfg, $Local) {
    $report = New-Report $cfg $Local
    if ($Print) {
        # Write-Host on purpose: pipeline output would be swallowed by the caller's "if".
        Write-Host ($report | ConvertTo-Json -Depth 6)
        return $true
    }
    try {
        Send-Report $cfg $report
    } catch {
        # Counters stay in the pending tables and go out with the next report.
        if ($report.ContainsKey('devices')) { $script:LastScan = [datetime]::MinValue }
        Write-Log ('report failed: ' + $_.Exception.Message)
        return $false
    }
    $script:PendingConn = @{}
    $script:PendingAuth = @{}
    return $true
}

function Start-Agent {
    $cfg = Get-AgentConfig
    $local = Get-LocalNetworks $cfg
    $interval = [Math]::Max(5, [int]$cfg.interval)
    Write-Log ('Nobet Agent {0} started: {1} (capture: {2}, subnets: {3})' -f $script:Version, $cfg.manager, $cfg.capture,
        (@($local.Nets | ForEach-Object { $_.Cidr }) -join ', '))
    [void](Get-Metrics)          # baseline for network throughput
    Start-Sleep -Seconds 1
    if ($Once -or $Print) {
        if (Invoke-Cycle $cfg $local) { exit 0 } else { exit 1 }
    }
    $cycles = 0
    while ($true) {
        $started = Get-Date
        try { [void](Invoke-Cycle $cfg $local) } catch { Write-Log ('collection error: ' + $_.Exception.Message) }
        $cycles++
        if ($cycles % 20 -eq 0) { try { $local = Get-LocalNetworks $cfg } catch { } }   # pick up address changes
        # Sleep until the next report; in poll mode keep sampling connections meanwhile.
        while (((Get-Date) - $started).TotalSeconds -lt $interval) {
            Start-Sleep -Seconds 5
            if ($cfg.capture -eq 'poll') { try { Update-PolledConnections $local.Ips } catch { } }
        }
    }
}

# Dot-sourcing the file only loads the functions (useful for testing).
if ($MyInvocation.InvocationName -ne '.') { Start-Agent }
