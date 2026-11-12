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
  * service health checks defined in the Manager (TCP port, HTTP/HTTPS URL, certificate expiry)
  * data-leak monitoring: USB storage insert/remove, and file operations (with the user name) in
    the sensitive folders defined in the Manager. Folder auditing uses Security event 4663 and
    needs "file_audit": true in the config (install.ps1 -EnableFileAudit); the agent then adds an
    audit rule (SACL) to each watched folder. Only file names and operation types are reported.

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
$script:Checks = @()         # check definitions received in the Manager's last reply
$script:Watches = @()        # sensitive folders received in the Manager's last reply
$script:WatchStatus = @{}    # watch id -> @{ id; ok; detail }
$script:KnownUsb = $null     # serial/PNP id -> info of USB disks currently attached
$script:PendingUsb = @()
$script:PendingFiles = @{}   # "watchId|action|user|path" -> count
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
    if ($cfg.dlp -ne $false) {
        try { Read-FileAuditEvents $from $top } catch { Write-Log ('file audit read failed: ' + $_.Exception.Message) }
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

# ------------------------------------------------------------------ data-leak monitoring
function Update-UsbDevices {
    # Compares attached USB disks with the previous cycle; disks present at startup are not events.
    $current = @{}
    foreach ($d in @(Get-CimInstance -ClassName Win32_DiskDrive -Filter "InterfaceType='USB'" -ErrorAction SilentlyContinue)) {
        $serial = ([string]$d.SerialNumber).Trim()
        $key = $serial
        if (-not $key) { $key = [string]$d.PNPDeviceID }
        $size = [long]0
        if ($d.Size) { $size = [long]$d.Size }
        $current[$key] = @{ vendor = ''; model = ([string]$d.Model).Trim(); serial = $serial; size = $size }
    }
    if ($null -ne $script:KnownUsb) {
        foreach ($key in @($current.Keys)) {
            if (-not $script:KnownUsb.ContainsKey($key)) { $e = $current[$key].Clone(); $e.action = 'insert'; $script:PendingUsb += $e }
        }
        foreach ($key in @($script:KnownUsb.Keys)) {
            if (-not $current.ContainsKey($key)) { $e = $script:KnownUsb[$key].Clone(); $e.action = 'remove'; $script:PendingUsb += $e }
        }
    }
    $script:KnownUsb = $current
}

function Set-WatchedFolders($cfg, $Definitions) {
    # Applies the folder list from the Manager. Adding the audit rule changes the folder's SACL,
    # so it only happens when the administrator opted in with "file_audit": true.
    $script:Watches = @($Definitions | Select-Object -First 20)
    $script:WatchStatus = @{}
    foreach ($w in $script:Watches) {
        $path = [string]$w.path
        $status = @{ id = $w.id; ok = $false; detail = '' }
        if ($cfg.file_audit -ne $true) { $status.detail = 'File auditing is off on this server (install with -EnableFileAudit)' }
        elseif ($path -notmatch '^[A-Za-z]:\\.+' -or $path -like '*..*') { $status.detail = 'Invalid folder path' }
        elseif (-not (Test-Path -LiteralPath $path -PathType Container)) { $status.detail = 'Folder not found' }
        else {
            try {
                $acl = Get-Acl -LiteralPath $path -Audit
                $everyone = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'
                $rights = [System.Security.AccessControl.FileSystemRights]'ReadData, WriteData, AppendData, Delete, DeleteSubdirectoriesAndFiles'
                $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
                $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, $rights, $inherit,
                    [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AuditFlags]::Success)
                $acl.AddAuditRule($rule)      # additive: existing audit rules are kept
                Set-Acl -LiteralPath $path -AclObject $acl
                $status.ok = $true
                $status.detail = 'Audit rule active'
            } catch { $status.detail = 'Could not set audit rule: ' + $_.Exception.Message }
        }
        if ($status.detail.Length -gt 150) { $status.detail = $status.detail.Substring(0, 150) }
        $script:WatchStatus[[string]$w.id] = $status
    }
}

function Read-FileAuditEvents([long]$From, [long]$To) {
    # 4663 = an object was accessed. AccessMask bits: 0x1 read, 0x2 write, 0x4 append, 0x10000 delete.
    $active = @($script:Watches | Where-Object { $script:WatchStatus[[string]$_.id].ok })
    if ($active.Count -eq 0) { return }
    foreach ($ev in (Get-SecurityEvents 'EventID=4663' $From $To)) {
        $f = Get-EventFields $ev
        if ($f['ObjectType'] -ne 'File' -or $f['SubjectUserSid'] -eq 'S-1-5-18') { continue }   # skip SYSTEM
        $user = [string]$f['SubjectUserName']
        if (-not $user -or $user.EndsWith('$')) { continue }                                     # skip machine accounts
        $object = [string]$f['ObjectName']
        $watch = $null
        foreach ($w in $active) {
            $root = ([string]$w.path).TrimEnd('\')
            if ($object.Length -ge $root.Length -and $object.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase) -and
                ($object.Length -eq $root.Length -or $object[$root.Length] -eq '\')) { $watch = $w; break }
        }
        if ($null -eq $watch) { continue }
        $mask = 0
        try { $mask = [Convert]::ToInt32((([string]$f['AccessMask']) -replace '^0x', ''), 16) } catch { continue }
        if ($mask -band 0x10000) { $action = 'delete' }
        elseif ($mask -band 0x6) { $action = 'write' }
        elseif ($mask -band 0x1) { $action = 'read' }
        else { continue }
        if ($f['SubjectDomainName']) { $user = ([string]$f['SubjectDomainName']) + '\' + $user }
        Add-Count $script:PendingFiles ('{0}|{1}|{2}|{3}' -f $watch.id, $action, $user, $object)
    }
}

# ------------------------------------------------------------------ service health checks
function Get-AcceptAllCallback {
    # Compiled callback for checks with certificate verification turned off. A script block
    # cannot be used here: .NET may invoke the callback on a thread without a PowerShell runspace.
    if (-not ('NobetTls' -as [type])) {
        Add-Type -TypeDefinition @'
public static class NobetTls {
    public static bool AcceptAll(object sender, System.Security.Cryptography.X509Certificates.X509Certificate cert,
        System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors errors) { return true; }
}
'@
    }
    return [System.Delegate]::CreateDelegate([System.Net.Security.RemoteCertificateValidationCallback], [NobetTls].GetMethod('AcceptAll'))
}

function Invoke-ServiceCheck($Check) {
    # Only status and timing go back to the Manager; response bodies are never sent.
    $result = @{ id = $Check.id; ok = $false }
    $timeoutMs = 5000
    if ($Check.timeout) { $timeoutMs = [Math]::Min([Math]::Max([int]$Check.timeout, 1), 10) * 1000 }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($Check.type -eq 'tcp') {
            $target = [string]$Check.target
            $split = $target.LastIndexOf(':')
            $client = New-Object System.Net.Sockets.TcpClient
            try {
                $pending = $client.BeginConnect($target.Substring(0, $split), [int]$target.Substring($split + 1), $null, $null)
                if (-not $pending.AsyncWaitHandle.WaitOne($timeoutMs)) { throw 'Timeout' }
                $client.EndConnect($pending)
                $result.ok = $true
            } finally { $client.Close() }
        }
        elseif ($Check.type -eq 'http') {
            $request = [System.Net.HttpWebRequest]::Create([string]$Check.target)
            $request.Method = 'GET'
            $request.AllowAutoRedirect = $false
            $request.Timeout = $timeoutMs
            $request.ReadWriteTimeout = $timeoutMs
            $request.UserAgent = 'nobet-agent/' + $script:Version
            $request.KeepAlive = $false
            if ($Check.verify -eq $false) { $request.ServerCertificateValidationCallback = Get-AcceptAllCallback }
            $response = $null
            try { $response = $request.GetResponse() }
            catch {
                # 4xx/5xx arrive as a WebException (possibly wrapped) that still carries the response.
                $ex = $_.Exception
                while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
                if ($ex -and $ex.Response) { $response = $ex.Response } else { throw }
            }
            $status = [int]$response.StatusCode
            $response.Close()
            $result.status_code = $status
            if ($request.RequestUri.Scheme -eq 'https' -and $Check.verify -ne $false -and $request.ServicePoint.Certificate) {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $request.ServicePoint.Certificate
                $result.cert_days = [Math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 1)
            }
            if ($Check.expect_status) { $result.ok = ($status -eq [int]$Check.expect_status) }
            else { $result.ok = ($status -ge 200 -and $status -lt 400) }
            if (-not $result.ok) { $result.error = 'HTTP ' + $status }
        }
        else { throw 'Unknown check type' }
    } catch {
        $message = [string]$_.Exception.Message
        if ($_.Exception.InnerException) { $message = [string]$_.Exception.InnerException.Message }
        if ($message.Length -gt 160) { $message = $message.Substring(0, 160) }
        $result.error = $message
    }
    $result.latency_ms = [Math]::Round($watch.Elapsed.TotalMilliseconds, 1)
    return $result
}

function Invoke-ServiceChecks {
    # Checks run one after another; a 20 second budget keeps a slow batch from delaying the report.
    $results = @()
    $budget = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($check in @($script:Checks | Select-Object -First 50)) {
        if ($budget.Elapsed.TotalSeconds -gt 20) { break }
        $results += (Invoke-ServiceCheck $check)
    }
    return , $results
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
    if (@($script:Checks).Count -gt 0 -and $cfg.checks -ne $false) { $report.checks = (Invoke-ServiceChecks) }
    if ($cfg.dlp -ne $false) {
        try { Update-UsbDevices } catch { Write-Log ('usb scan failed: ' + $_.Exception.Message) }
        $files = @()
        foreach ($key in @($script:PendingFiles.Keys | Select-Object -First 2000)) {
            $p = $key.Split('|', 4)
            $files += @{ watch_id = [int]$p[0]; action = $p[1]; user = $p[2]; path = $p[3]; count = [int]$script:PendingFiles[$key] }
        }
        if (@($script:PendingUsb).Count -gt 0 -or $files.Count -gt 0 -or @($script:Watches).Count -gt 0) {
            $report.dlp = @{ usb = @($script:PendingUsb); files = $files; watch_status = @($script:WatchStatus.Values) }
        }
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
    $reply = Invoke-RestMethod -Uri ($cfg.manager.TrimEnd('/') + '/api/agent/report') -Method Post -Body $body `
        -ContentType 'application/json' -Headers @{ Authorization = 'Bearer ' + $cfg.token } `
        -UserAgent ('nobet-agent/' + $script:Version) -TimeoutSec 20 -UseBasicParsing
    # The reply carries the checks this server should run (an empty list clears them).
    if ($null -ne $reply -and ($reply.PSObject.Properties.Name -contains 'checks')) { $script:Checks = @($reply.checks) }
    if ($null -ne $reply -and $cfg.dlp -ne $false -and ($reply.PSObject.Properties.Name -contains 'watch_paths')) {
        $incoming = @($reply.watch_paths)
        $signature = (@($incoming | ForEach-Object { '{0}={1}' -f $_.id, $_.path }) -join ';')
        if ($signature -ne $script:WatchSignature) {      # re-apply only when the list changed
            $script:WatchSignature = $signature
            try { Set-WatchedFolders $cfg $incoming } catch { Write-Log ('watch setup failed: ' + $_.Exception.Message) }
        }
    }
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
    $script:PendingUsb = @()
    if ($report.ContainsKey('dlp')) { foreach ($f in @($report.dlp.files)) { $script:PendingFiles.Remove(('{0}|{1}|{2}|{3}' -f $f.watch_id, $f.action, $f.user, $f.path)) } }
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
