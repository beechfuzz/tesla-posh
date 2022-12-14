
Function Get-ApiResponse([string]$uri) {
    $uri = $base_uri_api + $uri
    $c = (Invoke-WebRequest -Headers $header_api -Uri $uri -Method Get).Content
    return ($c | ConvertFrom-Json).response
}

Function Send-ApiCommand([string]$uri) {
    $uri = $base_uri + $uri
    $c = (Invoke-WebRequest -Headers $header_api -Uri $uri -Method Post).Content
    return ($c | ConvertFrom-Json).response
}

#
##
########################################
##
## CONFIGURATION (BASIC)
## ----------------------
##
## c
#


# Directory that contains all the needed modules
$modules_dir = "Modules"

# Registry key that holds the API Access Token
$reg_key = "HKCU:\SOFTWARE\PowerShell TeslaAPI"

# Registry value that contains the API Access Token
$reg_val = "access_token"


#
##
########################################
##
## CONFIGURATION (ADVANCED)
## -------------------------
##
## 
#


# User-Agent for API Calls
$useragent = 'PowerShell/TeslaAPI Query'

# URI for SSO Authorization
$uri_sso_auth  = 'https://auth.tesla.com/oauth2/v3/authorize'

# URI for SSO Bearer Token
$uri_sso_token = 'https://auth.tesla.com/oauth2/v3/token'

# Base URI for API calls
$base_uri_api  = 'https://owner-api.teslamotors.com'

# URI for API Access Token
$uri_api_token = "$base_uri_api/oauth/token"

# Hashtable of required URIs
$required_uris = @(
    $uri_sso_auth,
    $uri_sso_token
    #$uri_api_token
)

#
##
########################################
##
## INITIALIZATION
## ---------------
##
## 
#

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#
## Remove and Import Modules
#
Write-Host "- Refreshing/Importing necessary modules... " -ForegroundColor Green -NoNewline
Remove-Module Init-API, Command, State -ErrorAction SilentlyContinue
$modules = Get-ChildItem $modules_dir
foreach ($module in $modules) {
    Import-Module $module.FullName
}
Write-Host "DONE!" -ForegroundColor Green


#
## Test connectivity to necessary URLs
#
Write-Host "- Connectivity check... " -ForegroundColor Green
foreach($uri in $required_uris) {
    Write-Host "    - Testing '$uri'... " -ForegroundColor Green -NoNewline
    if (Test-Uri $uri) {
         Write-Host "PASS!" -ForegroundColor Green
    }
    else {
        Write-Host "FAIL!" -ForegroundColor Yellow -BackgroundColor Red
        Write-Host "`nExiting..." -ForegroundColor Yellow -BackgroundColor Red
        Break Outer
    }
}
Write-Host "- All URI's are good!" -ForegroundColor Green


#
## Get API Access Token from Registry if it exists
#
Write-Host "- Checking for existing API Access... " -ForegroundColor Green -NoNewline
if (Test-ApiRegistryValue) {
    $access_token_api = Get-ApiRegistryValue
}

#
## Aqcuire new API Access Token if it doesn't exist or has expired
#
if ($(Confirm-ApiAccess $access_token_api) -eq $false) {
    Write-Host "No existing access!" -ForegroundColor Yellow
    Write-Host "- Initializing API access... " -ForegroundColor Green
    $access_token_api = Initialize-Api
}
else {
    Write-Host "GOOD!" -ForegroundColor Green
}


#
## Authorization header required for API calls
#
Write-Host "- Setting Authorization Header needed for API calls... " -ForegroundColor Green -NoNewline
$header_api = @{ Authorization = "Bearer $access_token_api" }
Write-Host "DONE!" -ForegroundColor Green


exit


$vehicles = Invoke-WebRequest      `
                -Headers   $header `
                -Uri       $uri    `
                -Method    Get

exit