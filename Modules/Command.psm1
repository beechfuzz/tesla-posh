Function Invoke-Wake([string]$id) {
    $uri = "/api/1/vehicles/$id/wake_up"
    Send-ApiCommand -uri $uri
}

Function Invoke-Honk([string]$id) {
    $uri = "/api/1/vehicles/$id/command/honk_horn"
    Send-ApiCommand -uri $uri
}

