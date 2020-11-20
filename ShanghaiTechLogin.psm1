
$Script:PROMPT_TITLE = "上海科技大学网络认证"
$Script:PROMPT_MESSAGE = "ShanghaiTech Network Authentication"
$Script:STUHOST = "controller.shanghaitech.edu.cn"
$Script:LOGIN_URL = "https://controller.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!login.action"
$Script:RESULT_URL = "https://controller.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!syncPortalAuthResult.action"
$Script:LOGOUT_URL = "https://controller.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!logout.action"
$Script:HEARTBEAT_URL = "https://controller.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!hearbeat.action"
$Script:TEST_URI = "http://example.com"

#curl -X POST -F "userName=songfu" -F "password=songfu" -F "hasValidateCode=false" 'https://controller.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!login.action'

function Invoke-STULogin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pscredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    $NetworkCredential = $Credential.GetNetworkCredential()
    $Postdata = @{
        userName        = $NetworkCredential.UserName
        password        = $NetworkCredential.Password
        hasValidateCode = 'false'
        authLan         = 'zh_CN'
    }

    $Login = Invoke-RestMethod -Uri $Script:LOGIN_URL -Method Post -Body $Postdata -SessionVariable LoginSession
    $Token = $Login.token -replace 'token=', ''
    $LoginSession.Headers.Add('X-XSRF-TOKEN', $Token)

    return $LoginSession
}

function Invoke-STULogout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
        [string]
        $UserName = (Get-STULoginAccount -Session $Session)
    )
    $Logout = Invoke-RestMethod -Uri $Script:LOGOUT_URL -Method Post -WebSession $Session -Body @{userName = $UserName }
    return $Logout
}

function Invoke-STUHeartbeat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
        [string]
        $UserName = (Get-STULoginAccount -Session $Session)
    )
    
    $Heartbeat = Invoke-RestMethod -Uri $Script:HEARTBEAT_URL -Method Post -WebSession $Session -Body @{userName = $UserName }
    return $Heartbeat
}

function Get-STULoginStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )
    return (Get-STULoginData -Session $Session).portalAuthStatus
}

function Get-STULoginAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )
    return (Get-STULoginData -Session $Session).account
}

function Get-STULoginData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )
    $Result = Invoke-RestMethod -Uri $Script:RESULT_URL -WebSession $Session
    return $Result.data
}

function Get-STUIPAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )
    return (Get-STULoginData -Session $Session).ip
}

<#
 .SYNOPSIS
  Return true if the host is connected to ShanghaiTech network
#>
function Test-STUNetwork {
    [CmdletBinding()]
    # prarm wlan ethernet
    # https://deploymentresearch.com/detecting-wired-wireless-and-vpn-connections-using-powershell/
    $Configuration = Get-NetIPConfiguration | Where-Object { $_.NetProfile.Name -eq 'ShanghaiTech' }
    if ($Configuration.Count -gt 0) {
        try {
            $null = Resolve-DnsName controller.shanghaitech.edu.cn -Server 10.15.44.1 -ErrorAction Stop
        }
        catch [System.ComponentModel.Win32Exception] {
            return $false
        }
        return $true
    }

    return $false
}

<#
 .SYNOPSIS
  Return true if need to login to ShanghaiTech network
#>
function Test-STULogin {
    try {
        $Response = Invoke-WebRequest -Uri $Script:TEST_URI -MaximumRedirection 0 -ErrorAction Stop
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        $Response = $_.Exception.Response
    }
    catch [System.Net.Http.HttpRequestException] {
        $Response = $_.Exception.Response
    }
    catch {
        $Response = $_.Exception.Response
    }

    if ($Response.StatusCode -eq [System.Net.HttpStatusCode]::Redirect -and
        $Response.Headers.Location.Host -eq $Script:STUHOST) {
        return $true
    }

    return $false
}

function Add-STUConfigDirectory {
    [CmdletBinding()]
    param([string]$Directory)
    if (-not (Test-Path $Directory)) {
        $null = New-Item -ItemType Directory $Directory
    }
}
function Export-STUCredential {
    [CmdletBinding()]
    [CmdletBinding(DefaultParameterSetName = "Credential")]
    param (
        # [Parameter(ParameterSetName = "UserName",
        #     ValueFromPipelineByPropertyName = $true)]
        # [Alias('name')]
        # [string]
        # $UserName,
        [Parameter(ParameterSetName = "Credential",
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('cred')]
        [ValidateNotNull()]
        [pscredential]
        [System.Management.Automation.Credential()]
        $Credential,
        [Parameter(ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The directory to save .stulogin file. The file name will be credential_$([Environment]::UserName)_$([Environment]::MachineName).xml')]
        [Alias('dir')]
        [string]
        $Directory = (Join-Path $HOME .stulogin)
    )

    Add-STUConfigDirectory -Directory $Directory
    $ExportPath = Join-Path $Directory "credential_$([Environment]::UserName)_$([Environment]::MachineName).xml"
    Export-Clixml -InputObject $Credential -Path $ExportPath
}

function Test-STUCredential {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to the credential.")]
        [ValidateNotNullOrEmpty()]
        [Alias('dir')]
        [string[]]
        $Directory = (Join-Path ~ .stulogin)
    )
    $Path = Join-Path $Directory "credential_$([Environment]::UserName)_$([Environment]::MachineName).xml"
    return (Test-Path $Path)
}

function Import-STUCredential {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to the credential.")]
        [ValidateNotNullOrEmpty()]
        [Alias('dir')]
        [string[]]
        $Directory = (Join-Path ~ .stulogin)
    )
    $Path = Join-Path $Directory "credential_$([Environment]::UserName)_$([Environment]::MachineName).xml" -Resolve
    $Credential = Import-Clixml -Path $Path
    return $Credential
}

function Remove-STUCredential {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to the credential.")]
        [ValidateNotNullOrEmpty()]
        [Alias('dir')]
        [string[]]
        $Directory = (Join-Path ~ .stulogin)
    )
    $Path = Join-Path $Directory "credential_$([Environment]::UserName)_$([Environment]::MachineName).xml" -Resolve
    $Remove = Remove-Item $Path
    return $Remove
}

<#
 .SYNOPSIS
  Login to ShanghaiTech Network
#>
function Start-STULogin {
    [CmdletBinding()]
    param(
        [Switch]
        $Preserve,
        [pscredential]
        [System.Management.Automation.Credential()]
        $Credential
    )
    if (-not $Credential) {
        if (Test-STUCredential) {
            $Credential = Import-STUCredential
        }
        else {
            $Credential = Get-Credential -Title $Script:PROMPT_TITLE -Message $Script:PROMPT_MESSAGE
            Export-STUCredential -Credential $Credential
        }
    }

    try {
        $Session = Invoke-STULogin -Credential $Credential
    }
    catch {
        $Response = $_.Exception.Message

        Write-Host "× " -ForegroundColor Red -NoNewline
        Write-Host ([datetime]::Now.ToShortDateString()) -ForegroundColor DarkGray -NoNewline
        Write-Host " " -NoNewline
        Write-Host ([datetime]::Now.ToLongTimeString()) -ForegroundColor DarkGray -NoNewline
        Write-Host "`tLogin failed: " -ForegroundColor Red -NoNewline
        Write-Host $Response

        return $null
    }
    $Data = Get-STULoginData -Session $Session

    Write-Host "> " -ForegroundColor Green -NoNewline
    Write-Host ([datetime]::Now.ToShortDateString()) -ForegroundColor DarkGray -NoNewline
    Write-Host " " -NoNewline
    Write-Host ([datetime]::Now.ToLongTimeString()) -ForegroundColor DarkGray -NoNewline
    Write-Host "`tLogin successful!" -ForegroundColor Green

    Format-List -InputObject $data -Property account, ip, logindate | Out-Host

    return $Session
}

function Test-STUHeartbeat {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [pscustomobject]
        $Heartbeat
    )
    if ($Heartbeat.data -eq 'ONLINE') {
        return $true
    }
    return $false
}

<#
 .SYNOPSIS
  Send heartbeats to ShanghaiTech wifi controller
#>
function Start-STUHeartbeat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
        [int]
        $Interval = 120,
        [string]
        $UserName = (Get-STULoginAccount -Session $Session),
        [int]
        $FailMax = 5
    )

    $FailCount = 0
    while ($true) {
        if ($FailCount -gt $FailMax) {
            Write-Host "● " -ForegroundColor Red -NoNewline
            Write-Host ([datetime]::Now.ToShortDateString()) -ForegroundColor DarkGray -NoNewline
            Write-Host " " -NoNewline
            Write-Host ([datetime]::Now.ToLongTimeString()) -ForegroundColor DarkGray -NoNewline
            Write-Host "`tFailed $FailMax times, stop heartbeat." -ForegroundColor Red
            return $false
        }

        try {
            $HeartbeatSuccess = Invoke-STUHeartbeat -Session $Session -UserName $UserName | Test-STUHeartbeat
        }
        catch {
            # $Response = $_.Exception.Response

            Write-Host "× " -ForegroundColor Red -NoNewline
            $FailCount++
            $Retry = [math]::Pow(2, $FailCount + 2)
            Write-Host ([datetime]::Now.ToShortDateString()) -ForegroundColor DarkGray -NoNewline
            Write-Host " " -NoNewline
            Write-Host ([datetime]::Now.ToLongTimeString()) -ForegroundColor DarkGray -NoNewline
            Write-Host "`tHeartbeat failed"
            Start-Sleep -Seconds $Retry
            continue
        }
        
        if ($HeartbeatSuccess) {
            $FailCount = 0
            Write-Host "· " -ForegroundColor Green -NoNewline
            Write-Host ([datetime]::Now.ToShortDateString()) -ForegroundColor DarkGray -NoNewline
            Write-Host " " -NoNewline
            Write-Host ([datetime]::Now.ToLongTimeString()) -ForegroundColor DarkGray -NoNewline
            Write-Host "`tHeartbeat successful"
        }
        else {
            $FailCount++
            $Retry = [math]::Pow(2, $FailCount)
            Write-Host "· " -ForegroundColor Red -NoNewline
            Write-Host ([datetime]::Now.ToShortDateString()) -ForegroundColor DarkGray -NoNewline
            Write-Host " " -NoNewline
            Write-Host ([datetime]::Now.ToLongTimeString()) -ForegroundColor DarkGray -NoNewline
            Write-Host "`tHeartbeat failed, retry in $Retry seconds."
            Start-Sleep -Seconds $Retry
            continue
        }
        Start-Sleep -Seconds $Interval
    }
}

<#
 .SYNOPSIS
  Login to ShanghaiTech Network, and send heartbeat continously
#>
function Start-STULoginer {
    [CmdletBinding()]
    param(
        [int]
        $RetryMax = 4,
        [int]
        $Interval = 120,
        [pscredential]
        [System.Management.Automation.Credential()]
        $Credential
    )
    
    $TryCount = 0

    if ($Credential) {
        Export-STUCredential -Credential $Credential
    }

    while ($TryCount -lt $RetryMax) {
        $Session = Start-STULogin -Credential $Credential
        if ($null -eq $Session) {
            $TryCount++
        }
        else {
            $Result = Start-STUHeartbeat -Session $Session -Interval $Interval -FailMax $RetryMax
            if ($Result -eq $false) {
                $TryCount++
            }
            else {
                $TryCount = 0
            }
        }
    }
}

Set-Alias -Name stulogin -Value Start-STULoginer
