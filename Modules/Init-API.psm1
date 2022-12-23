Function Test-Uri ([string]$uri) {
    try {
        $r = Invoke-WebRequest -URI $uri -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $a = [int]$r.StatusCode
    }
    catch {
        $a = [int]$_.Exception.Response.StatusCode
    }
    return ($a -ge 200 -and $a -le 400)
}

function Get-RandomString ([int]$len =86) {
    return (-join (((48..57)+(65..90)+(97..122)) * 80 | Get-Random -Count $len |%{[char]$_}))
}

function ConvertTo-UrlBase64 {
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName="FromString")]
        [ValidateNotNullOrEmpty()]
        [string] $InputText,

        [Parameter(Mandatory = $true, ParameterSetName="FromByteArray")]
        [ValidateNotNullOrEmpty()]
        [byte[]] $InputBytes
    )
    if($PSCmdlet.ParameterSetName -eq "FromString") {
        $InputBytes = [System.Text.Encoding]::UTF8.GetBytes($InputText);
    }
    $e = [System.Convert]::ToBase64String($InputBytes);
    $e = $e.TrimEnd('=');
    $e = $e.Replace('+', '-');
    $e = $e.Replace('/', '_');
    return $e;
}

function Get-CodeChallenge ([string]$validator) {
    $s = [IO.MemoryStream]::new([byte[]][char[]]$validator)
    return (Get-FileHash -InputStream $s -Algorithm SHA256).Hash | ConvertTo-UrlBase64
}

Function Get-ApiRegistryValue {
    return $(Get-ItemProperty -Path $reg_key -Name $reg_val).access_token
}

Function Test-ApiRegistryValue {
    return $(Get-ItemProperty -Path $reg_key -Name $reg_val -ErrorAction SilentlyContinue) -ne $null
}

Function Save-ApiAccessToken([string]$token) {
    if (-not (Test-Path -Path $reg_key)){
        New-Item -Path $reg_key | Out-Null
    }
    try {
        New-ItemProperty -Path $reg_key -Name $reg_val -value $token -PropertyType "String" -ErrorAction Stop
    }
    catch {
        Set-ItemProperty -Path $reg_key -Name $reg_val -value $token
    }
}

Function Confirm-ApiAccess([string]$token) {
    $u = 'https://owner-api.teslamotors.com/api/1/vehicles'
    $h = @{ Authorization = "Bearer $token" }
    try {
        $s = (Invoke-WebRequest -Headers $h -Uri $u -Method Get).StatusCode
    }
    catch {
        $s = $false
    }
    return $s -eq 200
}

Function Get-Tokens {
    ##
    ## TESLA API
    ## ----------
    ##
    ## Source: https://github.com/timdorr/tesla-api
    #


    #
    ##
    ########################################
    ##
    ## CONSTANTS
    ## --------------------------
    ## 
    ## client_id             => 'ownerapi'
    ## code_challenge_method => 'S256'
    ## redirect_uri          => 'https://auth.tesla.com/void/callback'
    ## response_type         => 'code'
    ## scope =>              => 'openid email offline_access'
    ##

    $client_id             = 'ownerapi'
    $code_challenge_method = 'S256'
    $redirect_uri          = 'https://auth.tesla.com/void/callback'
    $response_type         = 'code'
    $scope                 = 'openid email offline_access'


    Add-Type -AssemblyName System.Web

    #
    ##
    ########################################
    ##
    ## Step 1: User-Login
    ## --------------------------
    ##
    ## Description : Have the user log into the Tesla Authentication page, then have
    ##               the user provide the redirect URL
    ##
    ## Request Parameters:
    ##
    ##    FIELD                    TYPE     RQR'D   DESCRIPTION
    ##    ------                   -----    ------  ------------
    ##    client_id                string      Y    The OAuth Client ID.  Always "ownerapi"
    ##    code_challenge           string      Y    The "code challenge"
    ##    code_challenge_method    string      Y    Code challenge method.  Always "S256" (sha-256)
    ##    redirect_uri             string      Y    Redirect URL. Always "https://auth.tesla.com/void/callback"
    ##    response_type            string      Y    Type of expected response.  Always "code"
    ##    scope                    string      Y    The Authentication scope.  Always "openid email offline_access"
    ##    state                    string      Y    The OAuth state value.  Any random string.
    ##    login_hint               string      N    The email for the authenticating Tesla account
    ##

    ## Assign variables
    $code_verifier         = Get-RandomString
    $code_challenge        = Get-CodeChallenge -validator $code_verifier
    $state                 = Get-RandomString -len 12


    ## Generate the URL that the user will log into
    $query = [ordered]@{
        client_id             = $client_id             ;
        code_challenge        = $code_challenge        ;
        code_challenge_method = $code_challenge_method ;
        redirect_uri          = $redirect_uri          ;
        response_type         = $response_type         ;
        scope                 = $scope                 ;
        state                 = $state                 ;
    }
    $nvCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    Foreach ($param in $query.GetEnumerator()) {
        #$uri_query += "$($param.Name)=$($param.Value)&"
        $nvCollection.Add($($param.Name),$($param.Value))
    }
    $uriRequest = [System.UriBuilder]'https://auth.tesla.com/oauth2/v3/authorize'
    $uriRequest.Query = $nvCollection.ToString()


    ## Instruct user of what will happen next
    Write-Host
    $msg  = "A Microsoft Edge browser will open up and load a Tesla login page.  When it opens, complete the following steps:`n"
    $msg += "`n"
    $msg += "`t [1] Log in with your Tesla Credentials.`n"
    $msg += "`t [2] The browser will redirect you and display 'Page Not Found'.`n"
    $msg += "`t [3] Copy the URL of that page.`n"
    Write-Host $msg
    pause


    ## Open the generated Tesla Login URL in MS Edge
    $browser = [system.Diagnostics.Process]::Start("msedge",$uriRequest.Uri.OriginalString)


    ## Ask the user for the URL that they landed at after they log in and grab the 'code' parameter
    Write-Host
    $returned_URI = [uri]$(Read-Host "Paste the Browswer's URL here")
    $code = [System.Web.HttpUtility]::ParseQueryString($returned_URI.Query)['code']


    #
    ##
    ########################################
    ##
    ## Step 2: Get user's tokens
    ## --------------------------
    ##
    ## Description : Using the User-provided URL, grab the user's Access, Refresh, and ID Tokens
    ##
    ## Request Parameters:
    ##
    ##    FIELD                    TYPE     RQR'D   DESCRIPTION
    ##    ------                   -----    ------  ------------
    ##    client_id                string      Y    The OAuth Client ID.  Always "ownerapi"
    ##    code_challenge           string      Y    The "code challenge"
    ##    code_challenge_method    string      Y    Code challenge method.  Always "S256" (sha-256)
    ##    redirect_uri             string      Y    Redirect URL. Always "https://auth.tesla.com/void/callback"
    ##    response_type            string      Y    Type of expected response.  Always "code"
    ##    scope                    string      Y    The Authentication scope.  Always "openid email offline_access"
    ##    state                    string      Y    The OAuth state value.  Any random string.
    ##    login_hint               string      N    The email for the authenticating Tesla account
    ##


    ## Generate the Web Request query that will be used to retrieve the user's tokens
    $grant_type = 'authorization_code'
    $body = @{
        client_id     = $client_id     ;
        code          = $code          ;
        code_verifier = $code_verifier ;
        grant_type    = $grant_type    ;
        redirect_uri  = $redirect_uri  ;
    }
    

    ## Send the WebRequest and get the web content that contains the Bearer Token
    $content = (Invoke-WebRequest         `
                    -UserAgent $useragent `
                    -Uri       $uri_sso_token       `
                    -Method    Post       `
                    -Body      $body      `
                ).Content | ConvertFrom-Json
    
    ## Return a hashtable with the tokens
    $tokens = @{
        access_token  = $content.access_token
        id_token      = $content.refresh_token
        refresh_token = $content.id_token
    }

return $tokens
    
}


Function Initialize-Api {
    ##
    ## TESLA API
    ## ----------
    ##
    ## Source: https://github.com/timdorr/tesla-api
    #


    #
    ##
    ########################################
    ##
    ## Step 1: Obtain Login Page
    ## --------------------------
    ## 
    ## WebRequest  : GET https://auth.tesla.com/oauth2/v3/authorize
    ##
    ## Description : Get a hidden form which contains hidden fields that will be
    ##               used in the next step.
    ##
    ## Request Parameters:
    ##
    ##    FIELD                    TYPE     RQR'D   DESCRIPTION
    ##    ------                   -----    ------  ------------
    ##    client_id                string      Y    The OAuth Client ID.  Always "ownerapi"
    ##    code_challenge           string      Y    The "code challenge"
    ##    code_challenge_method    string      Y    Code challenge method.  Always "S256" (sha-256)
    ##    redirect_uri             string      Y    Redirect URL. Always "https://auth.tesla.com/void/callback"
    ##    response_type            string      Y    Type of expected response.  Always "code"
    ##    scope                    string      Y    The Authentication scope.  Always "openid email offline_access"
    ##    state                    string      Y    The OAuth state value.  Any random string.
    ##    login_hint               string      N    The email for the authenticating Tesla account
    ##

    Write-Host "    - Obtaining Login Page... " -NoNewline -ForegroundColor Green
    $uri = $uri_sso_auth

    ## Build the Body of the WebRequest
    $client_id             = 'ownerapi'
    $code_verifier         = Get-RandomString
    $code_challenge        = Get-CodeChallenge -validator $code_verifier
    $code_challenge_method = 'S256'
    $redirect_uri          = 'https://auth.tesla.com/void/callback'
    $response_type         = 'code'
    $scope                 = 'openid email offline_access'
    $state                 = Get-RandomString -len 12

    $body = @{
        client_id             = $client_id             ;
        code_challenge        = $code_challenge        ;
        code_challenge_method = $code_challenge_method ;
        redirect_uri          = $redirect_uri          ;
        response_type         = $response_type         ;
        scope                 = $scope                 ;
        state                 = $state                 ;
    }

    $query = [ordered]@{
        client_id             = $client_id             ;
        code_challenge        = $code_challenge        ;
        code_challenge_method = $code_challenge_method ;
        redirect_uri          = $redirect_uri          ;
        response_type         = $response_type         ;
        scope                 = $scope                 ;
        state                 = $state                 ;

    }

    Add-Type -AssemblyName System.Web
    $nvCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

    Foreach ($param in $query.GetEnumerator()) {
        #$uri_query += "$($param.Name)=$($param.Value)&"
        $nvCollection.Add($($param.Name),$($param.Value))
    }
    $uriRequest = [System.UriBuilder]'https://auth.tesla.com/oauth2/v3/authorize'
    $uriRequest.Query = $nvCollection.ToString()
    $browser = [system.Diagnostics.Process]::Start("msedge",$uriRequest.Uri.OriginalString)

    Write-Host
    $returned_URI = [uri]$(Read-Host "Browswer URL")
    $code       = [System.Web.HttpUtility]::ParseQueryString($returned_URI.Query)['code']


    $nvCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    $grant_type = 'authorization_code'
    $body = @{
        grant_type    = $grant_type    ;
        client_id     = $client_id     ;
        code          = $code          ;
        code_verifier = $code_verifier ;
        redirect_uri  = $redirect_uri  ;
    }
    
    ## Send the WebRequest and get the web content that contains the Bearer Token
    $uri = $uri_sso_token
    $content = (Invoke-WebRequest         `
                    -UserAgent $useragent `
                    -Uri       $uri       `
                    -Method    Post       `
                    -Body      $body      `
                ).Content | ConvertFrom-Json

    $access_token  = $content.access_token
    $refresh_token = $content.refresh_token
    $id_token      = $content.id_token

    Write-Host
    Write-Host "Access Token:",$access_token
    Write-Host
    Write-Host "Refresh Token:",$refresh_token
    Write-Host
    Write-Host "ID Token:",$id_token
    Write-Host


###################################

    ## Send the WebRequest and get the hidden form
    $response = Invoke-WebRequest                  `
                    -Uri             $uri       `
                    -UserAgent       $useragent `
                    -Method          Get        `
                    -Body            $body      `
                    -SessionVariable session
    $cookie = $response.Headers.Item("Set-Cookie")
    $form = $response.Forms.Item("form")
    #$form = (Invoke-WebRequest                  `
    #                -Uri             $uri       `
    #                -UserAgent       $useragent `
    #                -Method          Get        `
    #                -Body            $body      `
    #                -SessionVariable session    `
    #        ).Forms.Item("form")
    Write-Host "DONE!" -ForegroundColor Green
    
    #
    ##
    ############################################
    ##
    ## Step 2: Obtain an SSO Authorization Code
    ## -----------------------------------------
    ##
    ## WebRequest  : POST https://auth.tesla.com/oauth2/v3/authorize
    ##
    ## Description : Using the hidden fields from the previous step, obtain
    ##               the Location Header which contains the SSO Authorization
    ##               Code which will be used in the next step. 
    ##
    ## Request Parameters:
    ##
    ##    FIELD             TYPE     RQR'D   DESCRIPTION
    ##    ------            -----    ------  ------------
    ##    _csrf             string      Y    From the '_csrf' field of the previous response
    ##    _phase            string      Y    From the '_phase' field of the previous response
    ##    _process          string      Y    From the '_process' field of the previous response
    ##    transaction_id    string      Y    From the 'transaction_id' field of the previous response
    ##    cancel            string      Y    From the 'cancel' field of the previous response
    ##    identity          string      Y    Email address for the authenticating account. 
    ##    credential        string      Y    Password for the authenticating account.
    ##
    #
    
    $uri = $uri_sso_auth

    ## Prompt for login credentials
    Write-Host "    - Please enter your Tesla Account credentials." -ForegroundColor Yellow
    do {
        $identity = Read-Host "Tesla Account Email"
    } until ($identity -ne $null)
    do {
        $credential = Read-Host "Tesla Account Password" -AsSecureString
    } until ($credential -ne $null)
    $credential = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential))

    ## Build the Body of the WebRequest
    $csrf           = $form.fields['_csrf']
    $phase          = $form.fields['_phase']
    $process        = $form.fields['_process']
    $transaction_id = $form.fields['transaction_id']
    $cancel         = $form.fields['form-input-cancel']
    #$identity       = 'jennifrailey@gmail.com'
    #$credential     = 'Cam1Kyl@'

    $body           = @{
        #_csrf          = $csrf           ;
        _phase         = $phase          ;
        _process       = $process        ;
        transaction_id = $transaction_id ;
        cancel         = $cancel         ;
        identity       = $identity       ;
        credential     = $credential     ;
    }

    ## Set the content type
    $content_type = 'application/x-www-form-urlencoded'

    ## Send the WebRequest and get the Location Header
    $headers = [uri](Invoke-WebRequest                       `
                        -MaximumRedirection 0                `
                        -ContentType        $content_type    `
                        -Uri                $uri        `
                        -UserAgent          $useragent       `
                        -Method             Post             `
                        -Body               $body            `
                        -WebSession         $session         `
                        -ErrorAction        SilentlyContinue `
                    ).Headers['Location']
    Write-Host "    - Login Successful!" -ForegroundColor Green
    
    #
    ##
    ########################################################
    ##
    ## Step 3: Obtain the Bearer/SSO Access Token
    ## -----------------------------------------------------
    ##
    ## WebRequest  : POST https://auth.tesla.com/oauth2/v3/token
    ##
    ## Description : Using the Location header from the previous step, parse out
    ##               the SSO Authorization Code and use it to obtain web content
    ##               that contains the Bearer/SSO Access Token used in the next step.
    ##
    ## Request Parameters:
    ##
    ##    FIELD            TYPE     RQR'D   DESCRIPTION
    ##    ------           -----    ------  ------------
    ##    grant_type       string      Y    The type of OAuth grant. Always "authorization_code"
    ##    client_id        string      Y    The OAuth Client ID.  Always "ownerapi"
    ##    code             string      Y    The SSO Authorization Code from the last request.
    ##    code_verifier    string      Y    The code verifier string generated previously
    ##    redirect_uri     string      Y    Redirect URL. Always "https://auth.tesla.com/void/callback"
    ##
    #
    
    Write-Host "    - Obtaining SSO Authorization Token... " -NoNewline -ForegroundColor Green
    $uri = $uri_sso_token

    ## Build the Body of the WebRequest
    $grant_type = 'authorization_code'
    $code       = [System.Web.HttpUtility]::ParseQueryString($headers.Query)['code']
    $body       = @{
        grant_type    = $grant_type    ;
        client_id     = $client_id     ;
        code          = $code          ;
        code_verifier = $code_verifier ;
        redirect_uri  = $redirect_uri  ;
    }

    ## Send the WebRequest and get the web content that contains the Bearer Token
    $content = (Invoke-WebRequest         `
                    -UserAgent $useragent `
                    -Uri       $uri       `
                    -Method    Post       `
                    -Body      $body      `
                ).Content | ConvertFrom-Json

    #
    ##
    ##############################################################
    ##
    ## Step 4: Obtain the API Access Token
    ## -----------------------------------------------------------
    ##
    ## WebRequest  : POST https://owner-api.teslamotors.com/oauth/token
    ##
    ## Description : Using the web content from the previous step, parse out
    ##               the Bearer/SSO Access Token in order to obtain the API Access
    ##               Token which is required for all of the API queries and 
    ##               commands.
    ## 
    ##               This endpoint follows RFC 7523 to exchange a JWT access 
    ##               token from the SSO service for an access token usable by 
    ##               the Owner API.
    ##
    ##               The current client ID and secret are available at
    ##               https://pastebin.com/pS7Z6yyP.
    ##
    ##               You will get back an API access_token which is treated as 
    ##               an OAuth 2.0 Bearer Token. This token is passed along in an 
    ##               Authorization header with all future requests:
    ##
    ##                      Authorization: Bearer {access_token_sso}
    ##
    ##               The API Access Token has a 45-day expiration.
    ##
    ## Request Parameters:
    ##
    ##    FIELD            TYPE     RQR'D   DESCRIPTION
    ##    ------           -----    ------  ------------
    ##    grant_type       string      Y    The type of OAuth grant. Always "urn:ietf:params:oauth:grant-type:jwt-bearer"
    ##    client_id        string      Y    The OAuth Client ID.
    ##    client_secret    string      Y    The OAuth client secret
    ##
    #

    $uri = $uri_api_token

    ## Build the Body of the WebRequest
    $grant_type    = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
    $client_id     = '81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384'
    $client_secret = 'c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3'
    $body          = @{
        grant_type    = $grant_type    ;
        client_id     = $client_id     ;
        client_secret = $client_secret ;
    }

    ## Get the Bearer/SSO Access Token and construct the Authorization Header
    Write-Host "DONE!" -ForegroundColor Green
    $acc_tok_sso = $content.access_token
    $auth        = "Bearer $acc_tok_sso"
    $header      = @{ Authorization = $auth }

    ## Send the WebRequest and get the web content that contains the API Access Token
    Write-Host "    - Obtaining API Access Token... " -NoNewline -ForegroundColor Green
    $content = (Invoke-WebRequest         `
                    -UserAgent $useragent `
                    -Uri       $uri       `
                    -Method    Post       `
                    -Body      $body      `
                    -Headers   $header    `
                ).Content
    
    ## Return API Access Token
    Write-Host "DONE!" -ForegroundColor Green
    return ($content | ConvertFrom-Json).access_token
    
}