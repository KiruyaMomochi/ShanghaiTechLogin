# Set-StrictMode -Version Latest

$Script:Config = @{
    HeartbeatMinutes  = 2
    LoginRetry        = 4
    DnsServer         = "10.15.44.11"
    TestUri           = "http://223.5.5.5"
    InternalProbeHost = "software.lib.shanghaitech.edu.cn"
}

enum LogLevel {
    Debug = 0
    Info = 1
    Success = 2
    Warning = 3
    Error = 4
    Fatal = 5
}

<#
.SYNOPSIS
Write log message to console

.EXAMPLE
Write-Log -Message a -Level Success
#>
function Write-Log {
    param (
        # Log message
        [Parameter(Mandatory)]
        [string]
        $Message,
        # Log level
        [LogLevel]
        $Level = ([LogLevel]::Info),
        $ParameterName,
        # Leading string
        [string]
        $Char = '',
        # Foreground color
        [System.ConsoleColor]
        $Color
    )
    
    $display = switch ($Level) {
        ([LogLevel]::Debug) { 
            @{Char = "i"; Color = [System.ConsoleColor]::Blue }
        }
        ([LogLevel]::Info) { 
            @{Char = "·"; Color = [System.ConsoleColor]::Cyan }
        }
        ([LogLevel]::Success) { 
            @{Char = "●"; Color = [System.ConsoleColor]::Green }
        }
        ([LogLevel]::Warning) { 
            @{Char = "!"; Color = [System.ConsoleColor]::Yellow }
        }
        ([LogLevel]::Error) { 
            @{Char = "●"; Color = [System.ConsoleColor]::Red }
        }
        ([LogLevel]::Fatal) { 
            @{Char = "×"; Color = [System.ConsoleColor]::Red }
        }
    }

    if ($Char.Length -eq 0) {
        $Char = $display.Char
    }
    if ($null -eq $Color) {
        $Color = $display.Color
    }

    Write-Host $Char -ForegroundColor $Color -NoNewline
    Write-Host " " -NoNewline
    Write-Host ([datetime]::Now.ToShortDateString()) -ForegroundColor $Color -NoNewline
    Write-Host " " -NoNewline
    Write-Host ([datetime]::Now.ToLongTimeString()) -ForegroundColor $Color -NoNewline
    Write-Host "`t" -NoNewline
    Write-Host $Message
}

<#
 .SYNOPSIS
  Return true if the host is connected to ShanghaiTech network

 .DESCRIPTION
  Checking if hostname `software.lib.shanghaitech.edu.cn` can be resolved by 10.15.44.11.
#>
function Test-ShanghaiTechNetwork {
    [CmdletBinding()]
    param()

    # TODO
    if ($Configuration.Count -gt 0) {
        try {
            $null = Resolve-DnsName $Script:Config.InternalProbeHost -Server $Script:Config.DnsServer -ErrorAction Stop
        }
        catch [System.ComponentModel.Win32Exception] {
            return $false
        }
        return $true
    }

    return $false
}

function Get-ShanghaiTechLoginResponse {
    [CmdletBinding()]
    param()
    
    try {
        $response = Invoke-WebRequest -Uri $Config.TestUri -MaximumRedirection 0 -ErrorAction Stop
    }
    catch [System.Net.Http.HttpRequestException] {
        $response = $_.Exception.Response
    }
    catch {
        $response = $_.Exception.Response
    }

    if ($response.StatusCode -eq [System.Net.HttpStatusCode]::Redirect -and
        $response.Headers.Location.Host.EndsWith("shanghaitech.edu.cn")) {
        $response
    }
}

function Get-ShanghaiTechLoginParams {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $response = Get-ShanghaiTechLoginResponse
    if (-not $response) { return }

    $location = $response.Headers.Location
    if (-not $location) { return }

    $query = [System.Web.HttpUtility]::ParseQueryString($location.Query)
    $hashtable = @{}
    foreach ($key in $query.AllKeys) {
        $hashtable[$key] = $query[$key]
    }

    $hashtable
}

<#
 .SYNOPSIS
  Return true if need to login to ShanghaiTech network

 .DESCRIPTION
  If we can connect to http://example.com without being redirected to a portal, we don't need to login.
#>
function Test-ShanghaiTechLogin {
    if (Get-ShanghaiTechLoginResponse) {
        return $true
    }

    return $false
}

<#
 .SYNOPSIS
  Send heartbeats to ShanghaiTech wifi controller
#>
function Start-ShanghaiTechHeartbeat {
    [CmdletBinding()]
    param(
        [int]
        $Interval = 120,
        [int]
        $FailMax = 5
    )

    $FailCount = 0
    while ($true) {
        if ($FailCount -gt $FailMax) {
            Write-Log -Level ([LogLevel]::Error) "Failed $FailMax times, stop heartbeat."
            return $false
        }

        $HeartbeatSuccess = -not (Test-ShanghaiTechLogin)
        if (-not $HeartbeatSuccess) {
            # $Response = $_.Exception.Response
            $FailCount++
            $Retry = [math]::Pow(2, $FailCount + 2)
            Write-Log -Level ([LogLevel]::Warning) "Heartbeat failed."
            Start-Sleep -Seconds $Retry
            continue
        }
        
        if ($HeartbeatSuccess) {
            $FailCount = 0
            Write-Log -Level ([LogLevel]::Info) "Heartbeat successful."
        }
        else {
            $FailCount++
            $Retry = [math]::Pow(2, $FailCount)
            Write-Log -Level ([LogLevel]::Warning) "Heartbeat failed, retry in $Retry seconds."
            Start-Sleep -Seconds $Retry
            continue
        }
        Start-Sleep -Seconds $Interval
    }
}

#region Config
<#
 .SYNOPSIS
  Get config directory for storing credentials
#>
function Get-ShanghaiTechConfigDirectory {
    [CmdletBinding()]
    param()
    
    if ($env:XDG_CONFIG_HOME) {
        $Directory = $env:XDG_CONFIG_HOME
    }
    elseif ($env:LOCALAPPDATA) {
        $Directory = $env:LOCALAPPDATA
    }
    elseif ($env:USERPROFILE) {
        $Directory = $env:USERPROFILE
    }
    elseif ($env:HOME) {
        $Directory = $HOME
    }
    else {
        $Directory = Join-Path (Resolve-Path ~) ".config"
    }
    
    if (-not (Test-Path $Directory)) {
        $Directory = New-Item -ItemType Directory $Directory
    }

    $Directory = Join-Path $Directory "stulogin"
    if (-not (Test-Path $Directory)) {
        # If old path exists and new one does not exist, copy it
        $OldDirectory = Join-Path (Resolve-Path ~) ".stulogin"
        if (Test-Path $OldDirectory) {
            Copy-Item -Recurse $OldDirectory $Directory
        }
        else {
            $null = New-Item -ItemType Directory $Directory
        }
    }

    $Directory
}

<#
 .SYNOPSIS
  Get config file for storing credentials
#>
function Get-ShanghaiTechConfigFile {
    [CmdletBinding()]
    param(
        # Directory to store credential, default to $HOME/.config/stulogin
        [Parameter(
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true,
            HelpMessage = 'The directory to save .stulogin file. The file name will be credential_$([Environment]::UserName)_$([Environment]::MachineName).xml')]
        [Alias('dir')]
        [string]
        $Directory = (Get-ShanghaiTechConfigDirectory),
        # Resolve path
        [switch]
        $Resolve = $false
    )
    
    $fileName = "credential_$([Environment]::UserName)_$([Environment]::MachineName).xml"
    Join-Path $Directory $fileName -Resolve:$Resolve
}
#endregion

#region Credential
<#
 .SYNOPSIS
  Export ShanghaiTech login credential to file

 .NOTES
  This function is meant to be used in a pipeline
#>
function Export-ShanghaiTechStore {
    [CmdletBinding()]
    param (
        # Credential to export
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('cred')]
        [ValidateNotNull()]
        [pscredential]
        [System.Management.Automation.Credential()]
        $Credential,
        # Session with cookies to export
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
        # Directory to store credential, default to $HOME/.config/stulogin
        [Parameter(ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The directory to save .stulogin file. The file name will be credential_$([Environment]::UserName)_$([Environment]::MachineName).xml')]
        [Alias('dir')]
        [string]
        $Directory = (Get-ShanghaiTechConfigDirectory)
    )

    $sessionId = if ($Session) { 
        $id = $session.Cookies.GetCookies('https://net-auth.shanghaitech.edu.cn').Item('PSESSIONID')
        if ($id) { $id.Value }
    }
    else {}

    $ExportPath = Get-ShanghaiTechConfigFile -Directory $Directory
    Export-Clixml -InputObject @{ Credential = $Credential; SessionId = $sessionId } -Path $ExportPath
}

<#
 .SYNOPSIS
  Test if ShanghaiTech login credential exists
#>
function Test-ShanghaiTechStore {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to the credential.")]
        [ValidateNotNullOrEmpty()]
        [Alias('dir')]
        [string]
        $Directory = (Get-ShanghaiTechConfigDirectory)
    )
    return (Test-Path (Get-ShanghaiTechConfigFile -Directory $Directory))
}

<#
 .SYNOPSIS
  Import ShanghaiTech login credential and session from file
#>
function Import-ShanghaiTechStore {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to the credential.")]
        [ValidateNotNullOrEmpty()]
        [Alias('dir')]
        [string]
        $Directory = (Get-ShanghaiTechConfigDirectory)
    )
    $path = Get-ShanghaiTechConfigFile -Directory $Directory -Resolve
    $store = Import-Clixml -Path $path
    $result = @{}
    if ($store -is [pscredential]) {
        $result.Credential = $store
    }
    elseif ($store -is [hashtable]) {
        $result.Credential = $store.Item('Credential')
        
        if ($store.Item('SessionId')) {
            $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $session.Cookies.Add([System.Net.Cookie]::new("PSESSIONID", $store.SessionId, "/", "net-auth.shanghaitech.edu.cn"))
            $result.Session = $session
        }
    }

    return $result
}

<#
 .SYNOPSIS
  Remove ShanghaiTech login credential from file
#>
function Remove-ShanghaiTechStore {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to the credential.")]
        [ValidateNotNullOrEmpty()]
        [Alias('dir')]
        [string[]]
        $Directory = (Get-ShanghaiTechConfigDirectory),
        # Force
        [switch]
        $Force
    )

    # Delete old directory if exists
    $OldPath = Join-Path ~ .stulogin
    if (Test-Path $OldPath) {
        Remove-Item -Recurse $OldPath
    }

    $Path = Get-ShanghaiTechConfigFile -Directory $Directory -Resolve
    $Remove = Remove-Item $Path -Force:$Force
    return $Remove
}
#endregion
