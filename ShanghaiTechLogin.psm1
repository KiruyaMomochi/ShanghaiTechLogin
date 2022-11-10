# Set-StrictMode -Version Latest

$Script:PROMPT_TITLE = "上海科技大学网络认证"
$Script:PROMPT_MESSAGE = "ShanghaiTech Network Authentication"

#curl -X POST -F "userName=songfu" -F "password=songfu" -F "hasValidateCode=false" 'https://controller.shanghaitech.edu.cn:8445/PortalServer/Webauth/webAuthAction!login.action'

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
        $Credential,
        [string]
        $UserIp,
        # User session
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
        [Parameter()]
        [string]
        $Captcha,
        [switch]
        $ForceRequireCaptcha
    )

    $store = if (Test-ShanghaiTechStore) { Import-ShanghaiTechStore } else { @{} } 

    if (-not $Credential) { $Credential = $store.Item('Credential') }
    if (-not $Credential) { $Credential = Get-Credential -Title $Script:PROMPT_TITLE -Message $Script:PROMPT_MESSAGE }

    if (-not $Session) { $Session = $store.Item('Session') }
    if (-not $Session) { $Session = [Microsoft.PowerShell.Commands.WebRequestSession]::new() }
    
    $extra = @{}
    if (-not $UserIp) {
        $extra = Get-ShanghaiTechLoginResponse
        if ($extra.uaddress) { $UserIp = $extra.uaddress }
        elseif ($ip = Get-ShanghaiTechLocalIPAddress) { $UserIp = $ip }
        else { throw 'Cannot find user ip address' }
    }

    if (-not $UserMac) {
        if ($extra.umac) { $UserMac = $extra.umac }
        else { $UserMac = 'null' }
    }

    $LinkType = Get-ShanghaiTechLinkType -LocalIp $UserIp
    if ($ForceRequireCaptcha -or (($LinkType -ne ([LinkType]::Ethernet)) -and (-not $Captcha))) {
        $Captcha = Read-ShanghaiTechValidCode -UserIpOrUrl $UserIp -UserMac $UserMac
    }

    $data = Invoke-ShanghaiTechLogin -Credential $credential -Captcha $Captcha -Session $session -UserIp $UserIP -UserMac $UserMac -ExtraParameters $response
    
    if ($data.success) {
        Write-Log -Message "Login successful!" -Level ([LogLevel]::Info) 
        Export-ShanghaiTechStore -Credential $Credential -Session $session
    }
    else {
        Write-Log -Message "Login failed ${$data.errorCode}: ${$data.errorMessage}" -Level ([LogLevel]::Error)
    }
    
    return $data
}

<#
 .SYNOPSIS
  Login to ShanghaiTech Network, and send heartbeat continously

 .DESCRIPTION
  Credential save and management is handled here.
#>
function Start-STULoginer {
    [CmdletBinding()]
    param(
        [int]
        $RetryMax = 4,
        [int]
        $Interval = 120,
        [string]
        $UserIp,
        [pscredential]
        [System.Management.Automation.Credential()]
        $Credential
    )
    
    $tryCount = 0
    $forceRequireCaptcha = $false
    while ($tryCount -lt $RetryMax) {
        $data = Start-STULogin -ForceRequireCaptcha:$forceRequireCaptcha -Credential $Credential
        $success = if ($data.PSObject.Properties['success']) { $data.success }
        
        if ($data.errorCode -eq 20401) {
            Write-Log -Message 'Your have reached the maximum number of concurrent logins.' -Level ([LogLevel]::Error)
            break
        }
        if ($data.errorCode -in 3010, 4001, 4002, 4006, 4007, 4008, 4009, 4017) {
            $forceRequireCaptcha = $true
            continue
        }
        elseif (-not $success) {
            $tryCount++
            $retry = [math]::Pow(2, $tryCount)
            Write-Log -Message "Retry in $retry seconds." -Level ([LogLevel]::Warning)
            Start-Sleep -Seconds $retry
        }
        else {
            $data | Format-List | Out-Host

            if ($Credential) {
                Export-ShanghaiTechStore -Credential $Credential
            }
            
            $Result = Start-ShanghaiTechHeartbeat -Interval $Interval -FailMax $RetryMax
            if ($Result -eq $false) {
                $tryCount++
            }
            else {
                $tryCount = 0
            }
        }
    }

    $data
}

Set-Alias -Name stulogin -Value Start-STULoginer
