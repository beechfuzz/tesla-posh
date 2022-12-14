Function Get-Vehicles {
    $uri = "/api/1/vehicles"
    return Get-ApiResponse -uri $uri
}

Function Get-Vehicle([string]$id) {
    $uri = "/api/1/vehicles/$id"
    return Get-ApiResponse -uri $uri
}