<#
.SYNOPSIS
    Auto-discovers and continuously tracks ALL OV/EV Certificate Enrollments in Akamai CPS.
.DESCRIPTION
    Scans Akamai CPS for OV Single, OV SAN, OV Wildcard, OV Wildcard SAN, EV, and EV SAN 
    certificates, saves them to state, and polls all active lifecycles in a batch loop.
    Extracts exact Control Center UI fields (State, Status, More Info).
.PARAMETER ConfigSection
    The credential section inside your ~/.edgerc file (e.g. "akamaio").
.PARAMETER AccountSwitchKey
    The Akamai Account Switch Key for multi-account management (e.g. "B-F-JOGRRP:1-8BYUX").
.PARAMETER ContractId
    The Akamai Contract ID to scope the enrollment query (e.g. "ctr_F-JOGRS2").
.PARAMETER PollIntervalSeconds
    Polling interval in seconds between cycles (default: 60).
.PARAMETER StateFile
    Local JSON file to store tracked enrollment metadata (default: "./tracked_enrollments.json").
.PARAMETER IgnoredFile
    Local JSON file to store evaluated non-target/DV enrollment IDs (default: "./ignored_enrollments.json").
.PARAMETER DebugLog
    Prints raw API payloads and filtering diagnostics.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ConfigSection,

    [Parameter(Mandatory = $false)]
    [string]$AccountSwitchKey = "",

    [Parameter(Mandatory = $false)]
    [string]$ContractId = "",

    [Parameter(Mandatory = $false)]
    [int]$PollIntervalSeconds = 60,

    [Parameter(Mandatory = $false)]
    [string]$StateFile = "./tracked_enrollments.json",

    [Parameter(Mandatory = $false)]
    [string]$IgnoredFile = "./ignored_enrollments.json",

    [Parameter(Mandatory = $false)]
    [switch]$DebugLog
)

$ErrorActionPreference = "Stop"

function Read-JsonState($filePath) {
    $arr = [System.Collections.ArrayList]::new()
    if (Test-Path $filePath) {
        try {
            $raw = Get-Content $filePath -Raw -ErrorAction SilentlyContinue
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $content = $raw | ConvertFrom-Json
                if ($null -ne $content) {
                    foreach ($item in @($content)) {
                        [void]$arr.Add($item)
                    }
                }
            }
        }
        catch {}
    }
    return $arr
}

function Save-JsonState($filePath, $listData) {
    @($listData) | ConvertTo-Json -Depth 5 | Set-Content $filePath -Force
}

function Invoke-EdgeGridApi($path, $acceptHeader = "application/json") {
    $pyScript = @"
import json, sys, time
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from urllib.parse import urljoin
import requests

try:
    edgerc = EdgeRc("~/.edgerc")
    section = "$ConfigSection"
    baseurl = f"https://{edgerc.get(section, 'host')}"
    
    session = requests.Session()
    session.auth = EdgeGridAuth.from_edgerc(edgerc, section)
    
    headers = {
        "Accept": "$acceptHeader"
    }
    url = urljoin(baseurl, "$path")
    
    # Simple retry loop for HTTP 429
    for attempt in range(3):
        res = session.get(url, headers=headers)
        if res.status_code == 429:
            time.sleep(5)
            continue
        if res.status_code >= 400:
            print(f"API_HTTP_ERROR: {res.status_code} - {res.text}")
            break
        else:
            print(res.text)
            break
except Exception as e:
    print(f"PYTHON_EXCEPTION: {e}")
"@

    $rawOut = python -c "$pyScript" 2>&1 | Out-String
    if ($DebugLog -and ($rawOut -match "PYTHON_EXCEPTION" -or ($rawOut -match "API_HTTP_ERROR" -and $rawOut -notmatch "406"))) {
        Write-Host "  [API DIAGNOSTIC LOG] $rawOut" -ForegroundColor Red
    }
    return $rawOut
}

function Format-RaName($rawRa) {
    if (-not $rawRa) { return "Unknown" }
    $raStr = $rawRa.ToString().ToLower()
    if ($raStr -eq "symantec" -or $raStr -eq "digicert") {
        return "DigiCert"
    }
    if ($raStr -eq "lets-encrypt") {
        return "Let's Encrypt"
    }
    return $rawRa
}

function Format-CertTypeName($validationType, $certificateType) {
    $vType = if ($validationType) { $validationType.ToString().ToUpper() } else { "OV" }
    $cType = if ($certificateType) { $certificateType.ToString().ToLower() } else { "san" }

    switch -Regex ($cType) {
        "san" { return "$vType SAN" }
        "wildcard" { return "$vType Wildcard" }
        "single" { return "$vType Single" }
        "third" { return "$vType Third-Party" }
        default { return "$vType $($cType.ToUpper())" }
    }
}

function Is-OvEvEnrollment($item) {
    $certType = if ($item.certificateType) { $item.certificateType.ToString().ToLower() } else { "" }
    $valType = if ($item.validationType) { $item.validationType.ToString().ToLower() } else { "" }
    $ra = if ($item.ra) { $item.ra.ToString().ToLower() } else { "" }

    $combined = "$certType $valType $ra"

    if ($combined -match "dv" -or $combined -match "lets-encrypt" -or $ra -eq "lets-encrypt") {
        return $false
    }

    if ($combined -match "ov" -or 
        $combined -match "ev" -or 
        $combined -match "third-party" -or 
        $combined -match "symantec" -or 
        $combined -match "digicert" -or 
        $combined -match "san" -or 
        $combined -match "wildcard") {
        return $true
    }

    return $false
}

function Extract-CommonName($detailObj, $id) {
    if ($detailObj.csr -and $detailObj.csr.cn) { return $detailObj.csr.cn }
    if ($detailObj.cn) { return $detailObj.cn }
    if ($detailObj.commonName) { return $detailObj.commonName }
    if ($detailObj.sans -and $detailObj.sans.Count -gt 0) { return $detailObj.sans[0] }
    return "CN-$id"
}

function Check-EnrollmentStatus($EnrollmentId, $CommonName) {
    $timestamp = (Get-Date).ToString("HH:mm:ss")

    try {
        # 1. Fetch Root Enrollment Details
        $qPath = "/cps/v2/enrollments/$EnrollmentId"
        if ($AccountSwitchKey) { $qPath += "?accountSwitchKey=$AccountSwitchKey" }

        $enrollmentAccept = "application/vnd.akamai.cps.enrollment.v11+json"
        $enrollmentRaw = Invoke-EdgeGridApi -path $qPath -acceptHeader $enrollmentAccept
        
        # If API returned an HTTP error payload or rate-limit error, abort update to prevent false flapping
        if (-not $enrollmentRaw -or -not $enrollmentRaw.Contains("{") -or $enrollmentRaw -match "API_HTTP_ERROR") {
            Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
            Write-Host "[$timestamp] [$CommonName | ID $EnrollmentId]" -ForegroundColor Cyan
            Write-Host "  Status     : API Throttled / Retrying Next Loop..." -ForegroundColor DarkYellow
            return $false
        }

        $jsonStart = $enrollmentRaw.IndexOf('{')
        $cleanJson = $enrollmentRaw.Substring($jsonStart)
        $enrollmentObj = $cleanJson | ConvertFrom-Json

        $state = "Complete"
        $status = "Active / No Pending Changes"
        $moreInfo = ""

        # Active change in progress
        if ($enrollmentObj.pendingChanges -and $enrollmentObj.pendingChanges.Count -gt 0) {
            $changeHeader = $enrollmentObj.pendingChanges[0]
            $parentState = if ($changeHeader.state) { $changeHeader.state } else { "" }
            $changeLocation = if ($changeHeader -is [string]) { $changeHeader } else { $changeHeader.location }

            $state = if ($parentState) { $parentState } else { "Running" }

            Start-Sleep -Milliseconds 500

            # Query active pending change sub-resource
            if ($changeLocation) {
                $cPath = $changeLocation
                if ($AccountSwitchKey) {
                    $sep = if ($cPath.Contains("?")) { "&" } else { "?" }
                    $cPath += "${sep}accountSwitchKey=$AccountSwitchKey"
                }

                $changeAccept = "application/vnd.akamai.cps.change.v11+json"
                $changeRaw = Invoke-EdgeGridApi -path $cPath -acceptHeader $changeAccept

                if ($changeRaw -and $changeRaw.Contains("{")) {
                    $cJsonStart = $changeRaw.IndexOf('{')
                    $cleanCJson = $changeRaw.Substring($cJsonStart)
                    $changeObj = $cleanCJson | ConvertFrom-Json

                    if ($changeObj.statusInfo -and $changeObj.statusInfo.status) {
                        $status = $changeObj.statusInfo.status
                    }
                    elseif ($changeObj.status) {
                        $status = $changeObj.status
                    }
                    else {
                        $status = "Checking with your certificate authority for your signed certificate."
                    }

                    if ($changeObj.statusInfo) {
                        if ($changeObj.statusInfo.errorWarningReason) {
                            $moreInfo = $changeObj.statusInfo.errorWarningReason
                        }
                        elseif ($changeObj.statusInfo.description) {
                            $moreInfo = $changeObj.statusInfo.description
                        }
                    }
                }
            }

            Start-Sleep -Milliseconds 500

            # Query History Changes ONLY when active pending changes exist
            $historyPath = "/cps/v2/enrollments/$EnrollmentId/history/changes"
            if ($AccountSwitchKey) { $historyPath += "?accountSwitchKey=$AccountSwitchKey" }

            $historyAccept = "application/vnd.akamai.cps.change-history.v5+json"
            $historyRaw = Invoke-EdgeGridApi -path $historyPath -acceptHeader $historyAccept

            if ($historyRaw -and $historyRaw.Contains("{")) {
                $hJsonStart = $historyRaw.IndexOf('{')
                $cleanHJson = $historyRaw.Substring($hJsonStart)
                $historyObj = $cleanHJson | ConvertFrom-Json

                if ($historyObj.changes -and $historyObj.changes.Count -gt 0) {
                    $activeIncompleteChange = $historyObj.changes | Where-Object { $_.status -eq "incomplete" } | Select-Object -First 1

                    if ($activeIncompleteChange -and $activeIncompleteChange.status) {
                        $state = $activeIncompleteChange.status

                        if ($activeIncompleteChange.actionDescription) {
                            $status = $activeIncompleteChange.actionDescription
                        }

                        if ($activeIncompleteChange.primaryCertificateOrderDetails -and $activeIncompleteChange.primaryCertificateOrderDetails.orderId) {
                            $orderId = $activeIncompleteChange.primaryCertificateOrderDetails.orderId
                            if (-not $moreInfo) {
                                $moreInfo = "CA Order ID: $orderId. The Admin or Technical contact can obtain more information directly from the CA."
                            }
                        }
                    }
                }
            }

            if (($state -eq "Suspended" -or $state -eq "Error" -or $state -eq "incomplete") -and -not $moreInfo) {
                $moreInfo = 'The Admin or Technical contact can obtain more information directly from the CA. The "Certificate Authority Order ID" or the certificate "Common Name" is required.'
            }
        }

        # 2. Network Deployment Status
        $stagingStatus = "not-started"
        $productionStatus = "not-started"
        $isComplete = $false

        if ($state -eq "Complete" -and $status -eq "Active / No Pending Changes") {
            $stagingStatus = "active"
            $productionStatus = "active"
            $isComplete = $true
        }
        elseif ($state -ne "incomplete" -and $state -eq "Running") {
            Start-Sleep -Milliseconds 500
            $dPath = "/cps/v2/enrollments/$EnrollmentId/deployments"
            if ($AccountSwitchKey) { $dPath += "?accountSwitchKey=$AccountSwitchKey" }

            $deployAccept = "application/vnd.akamai.cps.deployment.v7+json"
            $deployRaw = Invoke-EdgeGridApi -path $dPath -acceptHeader $deployAccept

            if ($deployRaw -and $deployRaw.Contains("{")) {
                $jsonStart = $deployRaw.IndexOf('{')
                $cleanJson = $deployRaw.Substring($jsonStart)
                $deploymentObj = $cleanJson | ConvertFrom-Json

                if ($deploymentObj.staging -and $deploymentObj.staging.status) { 
                    $stagingStatus = $deploymentObj.staging.status 
                }
                if ($deploymentObj.production -and $deploymentObj.production.status) { 
                    $productionStatus = $deploymentObj.production.status 
                }
            }

            if ($stagingStatus -eq "active" -and $productionStatus -eq "active") {
                $isComplete = $true
            }
        }

        # Terminal Output Formatting
        Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "[$timestamp] [$CommonName | ID $EnrollmentId]" -ForegroundColor Cyan
        if ($state -eq "Error" -or $state -eq "Suspended" -or $state -eq "cancelled" -or $state -eq "incomplete") {
            Write-Host "  State      : $state" -ForegroundColor Red
        }
        else {
            Write-Host "  State      : $state" -ForegroundColor Yellow
        }
        Write-Host "  Status     : $status" -ForegroundColor White
        if ($moreInfo) {
            Write-Host "  More Info  : $moreInfo" -ForegroundColor Red
        }
        Write-Host "  Deployment : Staging [$stagingStatus] | Production [$productionStatus]" -ForegroundColor DarkGray

        return $isComplete
    }
    catch {
        Write-Host "[$timestamp] Query warning for ${EnrollmentId}: $_" -ForegroundColor DarkGray
        return $false
    }
}

# ==============================================================================
# MAIN DISCOVERY & TRACKING LOOP
# ==============================================================================

Write-Host "==========================================================================" -ForegroundColor Green
Write-Host " Akamai CPS OV/EV Certificate Auto-Discovery Service Started" -ForegroundColor Green
Write-Host " Credential Section : $ConfigSection" -ForegroundColor Yellow
if ($AccountSwitchKey) {
    Write-Host " Account Switch Key: $AccountSwitchKey" -ForegroundColor Yellow
}
if ($ContractId) {
    Write-Host " Contract ID       : $ContractId" -ForegroundColor Yellow
}
Write-Host "==========================================================================" -ForegroundColor Green

while ($true) {
    $timestamp = (Get-Date).ToString("HH:mm:ss")

    # Reload state files dynamically on every loop cycle
    $knownState = Read-JsonState $StateFile
    $ignoredEnrollments = Read-JsonState $IgnoredFile

    Write-Host "--------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "[$timestamp] Running discovery scan for new OV/EV enrollments..." -ForegroundColor Gray

    try {
        $queryParams = @()
        if ($ContractId) {
            $cleanCtr = $ContractId -replace '^ctr_', ''
            $queryParams += "contractId=$cleanCtr"
        }
        if ($AccountSwitchKey) {
            $queryParams += "accountSwitchKey=$AccountSwitchKey"
        }

        $apiPath = "/cps/v2/enrollments"
        if ($queryParams.Count -gt 0) {
            $apiPath += "?" + ($queryParams -join "&")
        }

        $listAccept = "application/vnd.akamai.cps.enrollments.v11+json"
        $responseRaw = Invoke-EdgeGridApi -path $apiPath -acceptHeader $listAccept

        if ($responseRaw -and $responseRaw.Contains("{")) {
            $jsonStart = $responseRaw.IndexOf('{')
            $cleanJson = $responseRaw.Substring($jsonStart)
            $parsed = $cleanJson | ConvertFrom-Json

            $enrollmentsList = if ($parsed.enrollments) { $parsed.enrollments } else { @($parsed) }

            foreach ($item in $enrollmentsList) {
                $id = $null
                if ($item -is [string]) {
                    $id = $item.Split('/')[-1]
                }
                elseif ($item.id) {
                    $id = $item.id.ToString()
                }
                elseif ($item.location) {
                    $id = $item.location.Split('/')[-1]
                }

                if (-not $id) { continue }

                # Skip if already tracked or ignored
                $alreadyTracked = @($knownState) | Where-Object { $_.id -eq $id }
                if ($alreadyTracked -or (@($ignoredEnrollments) -contains $id)) {
                    continue
                }

                # Query full details to evaluate validationType
                $detailPath = "/cps/v2/enrollments/$id"
                if ($AccountSwitchKey) { $detailPath += "?accountSwitchKey=$AccountSwitchKey" }

                $detailAccept = "application/vnd.akamai.cps.enrollment.v11+json"
                $detailRaw = Invoke-EdgeGridApi -path $detailPath -acceptHeader $detailAccept
                if (-not $detailRaw -or -not $detailRaw.Contains("{")) { continue }

                $detailJsonStart = $detailRaw.IndexOf('{')
                $cleanDetailJson = $detailRaw.Substring($detailJsonStart)

                $detailObj = $cleanDetailJson | ConvertFrom-Json
                $cn = Extract-CommonName $detailObj $id
                $displayRa = Format-RaName $detailObj.ra
                $displayCertType = Format-CertTypeName $detailObj.validationType $detailObj.certificateType

                if (Is-OvEvEnrollment $detailObj) {
                    Write-Host "--------------------------------------------------------------------------" -ForegroundColor Yellow
                    Write-Host " NEW OV/EV ENROLLMENT DISCOVERED & ADDED TO TRACKING!" -ForegroundColor Yellow
                    Write-Host " Enrollment ID : $id" -ForegroundColor White
                    Write-Host " Common Name   : $cn" -ForegroundColor White
                    Write-Host " Certificate   : $displayCertType / RA: $displayRa" -ForegroundColor White
                    Write-Host "--------------------------------------------------------------------------" -ForegroundColor Yellow

                    $newItem = [PSCustomObject]@{
                        id   = $id
                        cn   = $cn
                        type = $displayCertType
                    }
                    if ($null -eq $knownState) { $knownState = [System.Collections.ArrayList]::new() }
                    [void]$knownState.Add($newItem)
                    Save-JsonState $StateFile $knownState
                }
                else {
                    if ($DebugLog) {
                        Write-Host "[$timestamp] [SKIPPED] ID: $id ($cn) is DV/Let's Encrypt." -ForegroundColor DarkYellow
                    }
                    if ($null -eq $ignoredEnrollments) { $ignoredEnrollments = [System.Collections.ArrayList]::new() }
                    [void]$ignoredEnrollments.Add($id)
                    Save-JsonState $IgnoredFile $ignoredEnrollments
                }

                # Throttle API discovery queries to avoid HTTP 429 Rate Limits
                Start-Sleep -Milliseconds 500
            }
        }
    }
    catch {
        Write-Host "[$timestamp] Discovery scan error: $_" -ForegroundColor Red
    }

    # BATCH MONITORING PHASE
    if ($knownState -and $knownState.Count -gt 0) {
        Write-Host "[$timestamp] Monitoring status for $($knownState.Count) active OV/EV enrollments..." -ForegroundColor Cyan
        foreach ($entry in $knownState) {
            $complete = Check-EnrollmentStatus -EnrollmentId $entry.id -CommonName $entry.cn
            if ($complete) {
                Write-Host " SUCCESS: Enrollment $($entry.id) ($($entry.cn)) is fully active on Staging & Production!" -ForegroundColor Green
            }

            # Throttle API monitoring queries to avoid HTTP 429 Rate Limits
            Start-Sleep -Milliseconds 1500
        }
    }
    else {
        Write-Host "[$timestamp] No OV/EV enrollments currently registered for tracking." -ForegroundColor DarkGray
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}