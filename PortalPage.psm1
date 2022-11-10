# Set-StrictMode -Version Latest

# From https://net-auth.shanghaitech.edu.cn:19008/material/custom/lang/common-zh.js

$Script:IPADDR = "10.15.145.16"
$Script:NETAUTH = "net-auth.shanghaitech.edu.cn"
$Script:HEADER = [System.Collections.IDictionary]@{Host = ${Script:NETAUTH} }
$Script:VALIDCODE_URL = "https://${Script:IPADDR}:19008/portalauth/verificationcode"
$Script:LOGIN_URL = "https://${Script:IPADDR}:19008/portalauth/login"
$Script:LOGOUT_URL = "https://${Script:IPADDR}:19008/portalauth/logout"
$Script:SYNC_URL = "https://${Script:IPADDR}:19008/portalauth/syncPortalResult"

$Script:Config = @{
    HeartbeatMinutes = 2
    LoginRetry       = 4
    # Also used for finding interface
    DnsServer        = "10.15.44.11"
    TestUri          = "http://example.com"
}

enum LinkType {
    Ethernet
    Wireless
    Unknown
}

$Script:CachedLang = $null
$Script:CachedL10n = $null

function Get-ShanghaiTechLocalizedString {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Key,
        [Parameter()]
        [string]
        $Language = [cultureinfo]::CurrentCulture.Name
    )

    $lang = Join-Path $PSScriptRoot lang
    if ($Script:CachedLang -ne $Language) {
        $file = Join-Path $lang "$Language.json"
        if (-not (Test-Path $file)) { $file = Join-Path $lang "default.json" }
        $Script:CachedL10n = Get-Content $file | ConvertFrom-Json
    }

    $Script:CachedL10n.$Key
}

function Get-ShanghaiTechLinkType {
    [CmdletBinding()]
    [OutputType([LinkType])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$LocalIp
    )

    # This is a naive implementation, may not work if it-support updates the network topology
    # 10.19 is ethernet, 10.20 is wireless
    if ($LocalIp -like "10.19.*.*") {
        [LinkType]::Ethernet
    }
    elseif ($LocalIp -like "10.20.*.*") {
        [LinkType]::Wireless
    }
    else {
        [LinkType]::Unknown
    }
}

function Get-ShanghaiTechLocalIPAddress {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    # Using cmdlets in NetTCPIP module is more reliable, but need to be cross-platform
    # https://stackoverflow.com/questions/6803073/get-local-ip-address

    try {
        $socket = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, 0)
        $socket.Connect($Script:Config.DnsServer, 53)
        $localIP = $socket.LocalEndPoint.Address.ToString()
    }
    finally {
        if ($socket) {
            $socket.Dispose()
        }
    }
    
    return $localIP
}

function Read-ShanghaiTechValidCode {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # User IP Address or URL to get the image
        [Parameter(
            Mandatory = $true, 
            HelpMessage = "Type your IP Address", 
            ValueFromPipeline = $true)]
        [string]
        $UserIpOrUrl,
        # User MAC Address
        [Parameter(Mandatory = $false)]
        [string]
        $UserMac = "null"
    )

    $url = Out-ShanghaiTechValidCode -UserIpOrUrl $UserIpOrUrl -UserMac $UserMac -OutFormat url
    $displayUrl = $url.Replace($Script:IPADDR, $Script:NETAUTH)

    do {        
        Write-Host "Enter CAPTCHA from $displayUrl"
        Write-Host "or 'i' to get a image, 'q' to show a QR code, 's img.jpg' to save the image"
        $i = Read-Host -Prompt "CAPTCHA"
        switch ($i.Trim().ToLower()) {
            'i' {
                Out-ShanghaiTechValidCode -UserIpOrUrl $url -OutFormat image | Write-Host
                $retry = $true
            }
            'q' { 
                Out-ShanghaiTechValidCode -UserIpOrUrl $url -OutFormat qrcode | Write-Host
                $retry = $true
            }
            { $_ -like 's *' } {
                Out-ShanghaiTechValidCode $url -OutFile $i.Substring(1).Trim() | Write-Host
                $retry = $true
            }
            Default {
                $retry = $i -notmatch "^[0-9a-zA-Z]{4}$"
            }
        }
    } while ($retry)   

    $i
}

function Out-ShanghaiTechValidCode {
    param (
        # User IP Address or URL to get the image
        [Parameter(
            Mandatory = $true, 
            HelpMessage = "Type your IP Address", 
            ValueFromPipeline = $true)]
        [string]
        $UserIpOrUrl,
        # User MAC Address
        [Parameter(Mandatory = $false)]
        [string]
        $UserMac = "null",
        [Parameter()]
        [string]
        $OutFile,
        # Display format
        [Parameter()]
        [ValidateSet("url", "image", "qrcode")]
        $OutFormat = "url"
    )

    if ([ipaddress]::TryParse($UserIpOrUrl, [ref]0)) {
        $Url = Get-ShanghaiTechValidCode -UserIp $UserIpOrUrl -UserMac $UserMac
    }
    elseif ([uri]::TryCreate($UserIpOrUrl, [urikind]::Absolute, [ref]0)) {
        $Url = $UserIpOrUrl
    }
    else {
        throw "Invalid IP Address or URL: $UserIpOrUrl"
    }

    if ($OutFile) {
        Invoke-RestMethod -Uri $Url -Headers $Script:HEADER -OutFile $OutFile
    }
    switch ($OutFormat) {
        "url" {
            $Url
        }
        "image" {
            $image = (Invoke-WebRequest -Uri $Url -Headers $Script:HEADER).Content
            [System.Drawing.ImageConverter]::new().ConvertFrom($image) | Out-ConsolePicture
        }
        "qrcode" {
            $qrGenerater = [QRCoder.QRCodeGenerator]::new()
            $qrCodeData = $qrGenerater.CreateQrCode($Url, [QRCoder.QRCodeGenerator+ECCLevel]::M)
            $asciiQRCode = [QRCoder.AsciiQRCode]::new($qrCodeData)
            $asciiQRCode.GetGraphic(1)
        }
        Default {
            Write-Error "Invalid OutFormat: $OutFormat"
        }
    }
}

function Get-ShanghaiTechValidCode {
    param (
        # User IP Address
        [Parameter(Mandatory = $true, HelpMessage = "Type your IP Address", ValueFromPipeline = $true)]
        [ValidateScript(
            { [ipaddress]::TryParse($_, [ref]0) }
            # , ErrorMessage = "Invalid IP Address: {0}"
        )]
        [string]
        $UserIp,
        # User MAC Address
        [Parameter(Mandatory = $false)]
        [string]
        $UserMac = "null",
        # Write Output to File. If not specified, output will be written to console.
        [Parameter()]
        [string]
        $OutFile
    )
    
    $date = [System.DateTimeOffset]::Now.ToUnixTimeMilliseconds()
    $url = "${Script:VALIDCODE_URL}?date=${date}&uaddress=${UserIp}&umac=${UserMac}"

    if ($OutFile) {
        Invoke-RestMethod -Uri $url -Headers $Script:HEADER -OutFile $OutFile
    }
    else {
        $url
    }
}

function Get-ShanghaiTechLoginSSID {
    param (
        # Link type
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [LinkType]
        $LinkType
    )

    switch ($LinkType) {
        ([LinkType]::Ethernet) {
            [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('=LswSsidPlaceholder='))
        }
        ([LinkType]::Wireless) {
            "ShanghaiTech"
        }
        Default {
            Write-Warning "Unknown link type $LinkType, assuming Ethernet. If failed, please manually specify the SSID."
            [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('=LswSsidPlaceholder='))
        }
    }
}

# May not correct
enum AuthType {
    VIP = 1
    SMS = 3
    FacebookTwitter = 4
    WeChat = 5
    Passcode = 6
    Twitter = 12
    Google = 13
    QQ = 14
    Weibo = 15
    QRCode = 16
    PublicQRCode = 22
}

#region API

function ParseNetAuthResult {
    [CmdletBinding()]
    param (
        # Payload
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [pscustomobject]
        $Payload,
        # Session
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )
    process {
        if (-not $Payload) { return }

        if ($Payload.PSObject.Properties['errorcode']) {
            $errorMessage = Get-ShanghaiTechLocalizedString $Payload.errorcode
            if ($errorMessage) {
                Add-Member -InputObject $Payload -MemberType NoteProperty -Name "errorMessage" -Value $errorMessage
            }
        }

        if ($Payload.PSObject.Properties['psessionid'] -and $Session) {
            $Session.Cookies.Add([System.Net.Cookie]::new("PSESSIONID", $Payload.psessionid, "/", $Script:NETAUTH))
        }

        if ($Payload.PSObject.Properties['token']) {
            $Session.Headers.Add("X-CSRF-TOKEN", $Payload.token)
        }
    }
}

function SetSession {
    [CmdletBinding()]
    [OutputType([Microsoft.PowerShell.Commands.WebRequestSession])]
    param (
        # Session
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
        # Session ID
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $SessionId
    )
    
    if (-not $Session) {
        $Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    }
    if ($SessionId) {
        $Session.Cookies.Add([System.Net.Cookie]::new("PSESSIONID", $SessionId, "/", $Script:NETAUTH))
    }

    $Session
}

function Invoke-ShanghaiTechLogin {
    [CmdletBinding()]
    # https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/add-credentials-to-powershell-functions
    
    param (
        # Credential
        [Parameter(Mandatory = $true, HelpMessage = "Type your username and password")]
        [ValidateNotNull()]
        [pscredential]
        [System.Management.Automation.Credential()]
        $Credential,
        # # User IP Address
        # [Parameter(Mandatory = $true, HelpMessage = "Type your IP Address", ValueFromPipeline = $true)]
        # [ValidateScript(
        #     { [ipaddress]::TryParse($_, [ref]0) }
        #     # , ErrorMessage = "Invalid IP Address: {0}"
        # )]
        # [Alias('uaddress')]
        # [string]
        # $UserIp,
        # # User MAC Address
        # [Parameter(Mandatory = $false)]
        # [ValidateScript(
        #     { [regex]::IsMatch($_, "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$") }
        #     # , ErrorMessage = "Invalid MAC Address: {0}"
        # )]
        # [string]
        # $UserMac = $null,
        # # Link Type
        # [Parameter(Mandatory = $false)]
        # [string]
        # [Alias('ssid')]
        # $SSID,
        # Captcha
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [AllowNull()]
        $Captcha = $null,
        # Session ID
        [Parameter(HelpMessage = "Type your session ID")]
        [ValidateNotNullOrEmpty()]
        [Alias('psessionid')]
        [string]
        $SessionId,
        # User session
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
        # Extra parameters
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [hashtable]
        $ExtraParameters = @{}
    )

    dynamicparam {

        $userIpAttribute = [System.Collections.ObjectModel.Collection[System.Attribute]]@(
            $parameterAttribute = [System.Management.Automation.ParameterAttribute]@{
                Mandatory         = -not ($ExtraParameters -and $ExtraParameters.Contains('uaddress'))
                ValueFromPipeline = $true
                HelpMessage       = "Type your IP Address"
            }
            $parameterAttribute
            [System.Management.Automation.ValidateScriptAttribute] {
                [ipaddress]::TryParse($_, [ref]0)
            }
            [System.Management.Automation.AliasAttribute]::new('uaddress')
        )
        $userIpParameter = [System.Management.Automation.RuntimeDefinedParameter]::new('UserIp', [string], $userIpAttribute)
        
        $userMacAttribute = [System.Collections.ObjectModel.Collection[System.Attribute]]@(
            $parameterAttribute = [System.Management.Automation.ParameterAttribute]@{
                Mandatory   = $true
                HelpMessage = "Type your MAC Address"
            }
            $parameterAttribute
            [System.Management.Automation.AliasAttribute]::new('umac')
        )
        $userMacParameter = [System.Management.Automation.RuntimeDefinedParameter]::new('UserMac', [string], $userMacAttribute)

        $ssidAttribute = [System.Collections.ObjectModel.Collection[System.Attribute]]@(
            $parameterAttribute = [System.Management.Automation.ParameterAttribute]@{
                Mandatory   = $false
                HelpMessage = "Type your SSID"
            }
            $parameterAttribute
        )
        $ssidParameter = [System.Management.Automation.RuntimeDefinedParameter]::new('SSID', [string], $ssidAttribute)

        $paramDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        $paramDictionary.Add('UserIp', $userIpParameter)
        $paramDictionary.Add('UserMac', $userMacParameter)
        $paramDictionary.Add('SSID', $ssidParameter)

        return $paramDictionary
    }

    begin {
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserIp = $PSBoundParameters['UserIp']
        $UserMac = $PSBoundParameters['UserMac']
        $SSID = $PSBoundParameters['SSID']
        $Session = SetSession -Session $Session -SessionId $SessionId
    }

    process {
        # Set PostData

        $PostData = @{
            userName = $NetworkCredential.UserName
            userPass = $NetworkCredential.Password
            authType = [int][AuthType]::VIP
            agreed   = 1
        }

        if ($ExtraParameters -is [hashtable]) {
            foreach ($key in $ExtraParameters.Keys) {
                $PostData[$key] = $ExtraParameters[$key]
            }
        }
        elseif ($ExtraParameters -is [pscustomobject]) {
            foreach ($p in $ExtraParameters.PSObject.Properties) {
                $PostData[$p.Name] = $p.Value
            }
        }
        elseif ($ExtraParameters) {
            Write-Warning "ExtraParameters is not a hashtable or pscustomobject, ignored."
        }

        if ($UserIp) { $PostData.uaddress = $UserIp }
        if ($UserMac) { $PostData.umac = $UserMac }
        # elseif ($null -eq $PostData.Item('umac')) { $PostData.umac = "null" }
        if ($SSID) { $PostData.ssid = $SSID } elseif ($PostData.uaddress) {
            $PostData.ssid = Get-ShanghaiTechLinkType -LocalIp $PostData.uaddress | Get-ShanghaiTechLoginSSID
        }

        $PostData.validCode = $Captcha

        Write-Verbose ($PostData | ConvertTo-Json -Compress)

        # Post request

        $login = Invoke-RestMethod -Uri $Script:LOGIN_URL -Method Post -Headers $Script:HEADER -Body $PostData -SessionVariable $Session
        ParseNetAuthResult -Payload $login -Session $Session

        $login
    }
}
function Invoke-ShanghaiTechLogout {
    [CmdletBinding()]
    
    param (
        # Session ID
        [Parameter(ValueFromPipelineByPropertyName = $true, HelpMessage = "Type your session ID")]
        [ValidateNotNullOrEmpty()]
        [Alias('psessionid')]
        [string]
        $SessionId,
        # User session
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )

    $Session = SetSession -Session $Session -SessionId $SessionId

    $logout = Invoke-RestMethod -Uri $Script:LOGOUT_URL -Method Post -Headers $Script:HEADER -SessionVariable $Session
    ParseNetAuthResult -Payload $logout -Session $Session

    $logout
}
function Invoke-ShanghaiTechSync {
    [CmdletBinding()]
    
    param (
        # Session ID
        [Parameter(ValueFromPipelineByPropertyName = $true, HelpMessage = "Type your session ID")]
        [ValidateNotNullOrEmpty()]
        [Alias('psessionid')]
        [string]
        $SessionId,
        # User session
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )

    $Session = SetSession -Session $Session -SessionId $SessionId

    $sync = Invoke-RestMethod -Uri $Script:SYNC_URL -Method Post -Headers $Script:HEADER -SessionVariable $Session
    ParseNetAuthResult -Payload $sync -Session $Session

    $sync
}

#endregion
