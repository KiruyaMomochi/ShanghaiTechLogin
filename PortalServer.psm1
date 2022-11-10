# Set-StrictMode -Version Latest

$Script:LEGACY_IPADDR = "10.15.44.172"
$Script:LEGACY_CONTROLLER = "controller.shanghaitech.edu.cn"
$Script:LEGACY_HEADER = [System.Collections.IDictionary]@{Host=${Script:LEGACY_CONTROLLER}}
$Script:LEGACY_LOGIN_URL = "https://${Script:LEGACY_IPADDR}:8445/PortalServer/Webauth/webAuthAction!login.action"
$Script:LEGACY_RESULT_URL = "https://${Script:LEGACY_IPADDR}:8445/PortalServer/Webauth/webAuthAction!syncPortalAuthResult.action"
$Script:LEGACY_LOGOUT_URL = "https://${Script:LEGACY_IPADDR}:8445/PortalServer/Webauth/webAuthAction!logout.action"
$Script:LEGACY_HEARTBEAT_URL = "https://${Script:LEGACY_IPADDR}:8445/PortalServer/Webauth/webAuthAction!hearbeat.action"
$Script:LEGACY_CHANGE_URL = "https://${Script:LEGACY_IPADDR}:8445/PortalServer/Webauth/webAuthAction!modifyPassword.action"

class STURestfulResult {
    [hashtable]$data
    [string]$message
    [bool]$sessionTimeOut
    [bool]$success
    [string]$token
    [int]$total
}

class STULoginData {
    [int]$accessStatus
    [string]$account
    [string]$accountMac
    [int]$accountRemainDays
    [string]$accountexpiredTime
    [bool]$assignedFlow
    [bool]$assignedTime
    [bool]$canRegisterApplication
    [bool]$canVisitorApplication
    [string]$deviceIp
    [int]$failCount
    [bool]$firstFlowLogin
    [bool]$firstTimeLogin
    [string]$hasBindTelFlag
    [bool]$httpPortalAuth
    [string]$httpPortalLoginUrl
    [string]$httpPortalLogoutUrl
    [bool]$includeCharLT
    [bool]$includeNumber
    [bool]$includeSpecialChar
    [string]$ip
    [bool]$isNeedBindTel
    [string]$loginDate
    [int]$loginType
    [string]$message
    [string]$openId
    [bool]$permitUpdatePwd
    [bool]$portalAuth
    [int]$portalAuthStatus
    [int]$portalErrorCode
    [int]$pwdMaxLen
    [int]$pwdMinLen
    [int]$pwdRemainDays
    [string]$pwdexpiredTime
    [string]$redirectUrl
    [int]$residualFlow
    [int]$residualTime
    [string]$sessionId
    [int]$statusCode
    [int]$timeOutPeriod
    [string]$token
    [int]$totalTime
    [string]$userName
    [int]$webHeatbeatPeriod
    [int]$webPortalOvertimePeriod
}

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

    $Login = Invoke-RestMethod -Uri $Script:LEGACY_LOGIN_URL `
             -Method Post -Body $Postdata -Headers $Script:LEGACY_HEADER `
             -SessionVariable LoginSession
    if ($Login.data.accessStatus -eq 0) {
        Remove-ShanghaiTechStore
    }
    if ($Login.data.accessStatus -ne 200) {
        throw $Login.Message
    }
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
    $Logout = Invoke-RestMethod -Uri $Script:LEGACY_LOGOUT_URL -Method Post -WebSession $Session `
              -Headers $Script:LEGACY_HEADER -Body @{userName = $UserName }
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
    
    $Heartbeat = Invoke-RestMethod -Uri $Script:LEGACY_HEARTBEAT_URL -Method Post -WebSession $Session `
                 -Headers $Script:LEGACY_HEADER -Body @{userName = $UserName }
    return $Heartbeat
}

function Invoke-STUChangePassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
        [Parameter(Mandatory = $true)]
        [securestring]
        $OldPassword,
        [Parameter(Mandatory = $true)]
        [securestring]
        $NewPassword
    )
    
    $OldPassword = ConvertFrom-SecureString $OldPassword -AsPlainText
    $NewPassword = ConvertFrom-SecureString $NewPassword -AsPlainText
    
    $Postdata = @{
        userName        = $UserName
        oldPasswd       = $OldPassword
        newPasswd       = $NewPassword
        reNewPasswd     = $NewPassword
        browserFlag     = 'zh'
    }

    $ChangePassword = Invoke-RestMethod -Uri $Script:CHANGE_URL `
             -Method Post -Body $Postdata -Headers $Script:LEGACY_HEADER `
             -SessionVariable LoginSession

    return $ChangePassword
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
    [OutputType([STULoginData])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )
    $Result = Invoke-RestMethod -Uri $Script:LEGACY_RESULT_URL -WebSession $Session -Headers $Script:LEGACY_HEADER
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
