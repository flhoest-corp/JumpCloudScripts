<#
     ____.                    _________ .__                   .___
    |    |__ __  _____ ______ \_   ___ \|  |   ____  __ __  __| _/
    |    |  |  \/     \\____ \/    \  \/|  |  /  _ \|  |  \/ __ |
/\__|    |  |  /  Y Y  \  |_> >     \___|  |_(  <_> )  |  / /_/ |
\________|____/|__|_|  /   __/ \______  /____/\____/|____/\____ |
                     \/|__|           \/                       \/
                          (c) 2026 - Frederic Lhoest - PCCW Global
Create a JumpCloud device group (System Group) and add devices from a list.

- Loads $ApiKey and $OrgId from .\apiKey_EU.ps1
- Creates a static system group
- Fetches systems inventory from /api/systems (paginated) WITHOUT the 'fields' parameter
- Builds a case-insensitive lookup table locally on hostname and displayName
- Matches your device list against hostname/displayName (case-insensitive)
- Adds matched systems to the group with progress + logging
#>

# -------------------------------
# Config
# -------------------------------
$AuthFilePath      = ".\apiKey_EU.ps1"
$GroupName         = "Devices with Acrobat 2017"
$BaseUrl           = "https://console.eu.jumpcloud.com"
$RequestTimeoutSec = 30

# -------------------------------
# Device list (raw)
# -------------------------------
$DeviceNamesRaw = @(
    "DiveshGupta",
    "ISD01551927",
    "ISD1465333",
    "ISD1485186",
    "ISD1513717",
    "ISD1540676",
    "ISD1584536",
    "ISD1590516",
    "ISD1605654",
    "ISD1613193",
    "ISD1683451a",
    "ISD1700357",
    "ISD1702319",
    "isd1705978",
    "ISD1708477",
    "ISD1714315",
    "ISD1718032",
    "ISD1718681",
    "ISD1718967",
    "ISD1720637",
    "ISD1720656",
    "ISD1723897",
    "ISD1730457",
    "ISD1734610",
    "ISD1734842",
    "ISD1740948",
    "ISD1742102",
    "ISD1742951",
    "ISD1743241",
    "ISD1743242",
    "ISD1743815",
    "ISD1743825",
    "ISD1752525a",
    "ISD1752577",
    "ISD1755531",
    "ISD1756945",
    "ISD1757253",
    "ISD1757767",
    "ISD1762394",
    "ISD1767555",
    "ISD1773780",
    "ISD1773782",
    "ISD1773797n",
    "ISD1774152",
    "ISD1775625",
    "ISD1777850",
    "ISD1777851",
    "ISD1785131",
    "ISD1792463",
    "ISD1792464",
    "ISD1792466",
    "ISD1792467",
    "ISD1798803",
    "ISD1798808",
    "ISD1799665",
    "ISD1799686d",
    "ISD1800037",
    "ISD1800040",
    "ISD1807285",
    "ISD1807313",
    "ISD1808873",
    "ISD1808966",
    "ISD1813669",
    "ISD1814137",
    "ISD1816607",
    "ISD1819578",
    "ISD1821103",
    "ISD1821357",
    "ISD1821358",
    "ISD1821359",
    "ISD1821362",
    "ISD1821363",
    "ISD1821364",
    "ISD1821365",
    "ISD1824079",
    "ISD1825530",
    "ISD1825535",
    "isd1825536s",
    "ISD1826040",
    "ISD1826043",
    "ISD1826045",
    "ISD1826046",
    "ISD1826048",
    "ISD1827405",
    "ISD1827406",
    "ISD1827407",
    "ISD1827408",
    "ISD1827409",
    "ISD1827411",
    "ISD1828698",
    "ISD1828815",
    "ISD1828823",
    "ISD1831033",
    "ISD1837264",
    "ISD1838268",
    "ISD1838269",
    "ISD1838281",
    "ISD1839789",
    "ISD1839790",
    "ISD1839791",
    "ISD1839793",
    "ISD1839828a",
    "ISD1840578",
    "ISD1840579",
    "ISD1840608",
    "ISD1840609",
    "ISD1840611",
    "ISD1840627",
    "ISD1841432",
    "ISD1841874",
    "ISD1841875",
    "ISD1841929",
    "ISD1841930",
    "ISD1841931",
    "ISD1841932",
    "ISD1845143",
    "ISD1846004",
    "ISD1846441",
    "ISD1846897",
    "ISD1846900",
    "ISD1849194",
    "ISD1849243",
    "ISD1849246",
    "ISD1850132",
    "ISD1853020",
    "ISD1853021",
    "ISD1853024",
    "ISD1853025",
    "ISD1853026",
    "ISD1853027",
    "ISD1855457",
    "ISD1855458",
    "ISD1856345",
    "ISD1856472",
    "ISD1857591",
    "ISD1857866",
    "ISD1857917",
    "ISD1859515",
    "ISD1863958",
    "ISD1863962",
    "ISD1863987",
    "ISD1863996",
    "ISD1864006",
    "ISD1866355",
    "ISD1866704",
    "ISD1866707",
    "ISD1866708",
    "ISD1866709",
    "ISD1866716",
    "ISD1867125",
    "ISD1870844",
    "ISD1874620",
    "ISD1877168",
    "ISD1878811",
    "ISD1878815",
    "ISD1878816",
    "ISD1878818",
    "ISD1878820",
    "ISD1879884",
    "ISD1880524",
    "ISD1884018",
    "ISD1888182",
    "ISD1888186a",
    "ISD1888188",
    "isd1888196",
    "ISD1888214",
    "ISD1889961",
    "ISD1894586",
    "ISD1894755",
    "ISD1894764",
    "ISD1894765",
    "ISD1894769",
    "ISD1894770",
    "ISD1894773",
    "ISD1894776",
    "ISD1894777",
    "ISD1894779",
    "ISD1894780",
    "ISD1894781",
    "ISD1894782",
    "ISD1894783",
    "ISD1894784",
    "ISD1894785",
    "ISD1894786",
    "ISD1894787",
    "ISD1894791",
    "ISD1894792",
    "ISD1894794",
    "ISD1894795",
    "ISD1894798",
    "ISD1894809",
    "ISD1894899",
    "ISD1894900",
    "ISD1895054",
    "ISD1895075",
    "ISD1895568",
    "ISD1896654",
    "ISD1898168",
    "ISD1899335",
    "ISD1899850",
    "ISD1901120",
    "ISD1901124",
    "ISD1902828",
    "ISD1903222",
    "ISD1903307",
    "ISD1905035",
    "ISD1907494",
    "LAPTOP-T6RR8A4C",
    "PC01686682"
)

# Unique (case-insensitive) while keeping original casing of first occurrence
$seen = @{}
$DeviceNames = foreach ($d in $DeviceNamesRaw)
{
    if ([string]::IsNullOrWhiteSpace($d)) { continue }
    $k = $d.Trim().ToLowerInvariant()
    if (-not $seen.ContainsKey($k))
    {
        $seen[$k] = $true
        $d.Trim()
    }
}

# -------------------------------
# Load Auth
# -------------------------------
if (-not (Test-Path -Path $AuthFilePath))
{
    throw "Auth file not found: $AuthFilePath"
}

. $AuthFilePath

if ([string]::IsNullOrWhiteSpace($ApiKey))
{
    throw "Auth file did not define a valid `$ApiKey variable."
}

if ([string]::IsNullOrWhiteSpace($OrgId))
{
    throw "Auth file did not define a valid `$OrgId variable."
}

Write-Host "Auth loaded. BaseUrl=$BaseUrl"
Write-Host ("Devices to process (unique): {0}" -f $DeviceNames.Count)

# -------------------------------
# Helper: Invoke JumpCloud API (timeout + retry)
# -------------------------------
function Invoke-JcApi
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET","POST","PUT","PATCH","DELETE")]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Url,

        [Parameter(Mandatory = $false)]
        [object] $Body,

        [Parameter(Mandatory = $false)]
        [int] $RetryCount = 2
    )

    $headers = @{
        "x-api-key"    = $ApiKey
        "x-org-id"     = $OrgId
        "Accept"       = "application/json"
        "Content-Type" = "application/json"
    }

    $attempt = 0

    while ($true)
    {
        $attempt++

        try
        {
            if ($null -ne $Body)
            {
                $json = $Body | ConvertTo-Json -Depth 10
                return Invoke-RestMethod -Method $Method -Uri $Url -Headers $headers -Body $json -TimeoutSec $RequestTimeoutSec
            }

            return Invoke-RestMethod -Method $Method -Uri $Url -Headers $headers -TimeoutSec $RequestTimeoutSec
        }
        catch
        {
            if ($attempt -ge $RetryCount)
            {
                $msg = $_.Exception.Message
                throw "JumpCloud API call failed (attempt $attempt/$RetryCount): $Method $Url - $msg"
            }

            Write-Warning "API call failed (attempt $attempt/$RetryCount): $Method $Url - retrying..."
            Start-Sleep -Seconds 1
        }
    }
}

# -------------------------------
# Fetch systems inventory (limit capped + stable sort)
# -------------------------------
function Get-JcAllSystems
{
    # JumpCloud systems list commonly enforces a maximum limit of 100.
    $limit = 100
    $skip  = 0
    $all   = New-Object System.Collections.Generic.List[object]

    Write-Host ""
    Write-Host "Fetching systems inventory from JumpCloud..."

    while ($true)
    {
        # Add sort=_id for stable pagination when using skip
        $url = "$BaseUrl/api/systems?limit=$limit&skip=$skip&sort=_id"
        $res = Invoke-JcApi -Method "GET" -Url $url

        if ($null -eq $res -or -not ($res.PSObject.Properties.Name -contains "results"))
        {
            throw "Unexpected response shape while listing systems (missing 'results')."
        }

        foreach ($s in $res.results)
        {
            $all.Add($s)
        }

        $total = 0
        if ($res.PSObject.Properties.Name -contains "totalCount")
        {
            $total = [int]$res.totalCount
        }

        $skip += $limit
        Write-Host ("  Retrieved {0}/{1}..." -f $all.Count, $total)

        if ($res.results.Count -lt $limit) { break }
        if ($total -gt 0 -and $all.Count -ge $total) { break }
    }

    return $all
}

# -------------------------------
# Build lookup on hostname + displayName (case-insensitive)
# -------------------------------
function Build-SystemLookup
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object[]] $Systems
    )

    $lookup = @{}

    foreach ($s in $Systems)
    {
        if ($s.hostname)
        {
            $k = $s.hostname.ToString().Trim().ToLowerInvariant()
            if (-not $lookup.ContainsKey($k)) { $lookup[$k] = $s }
        }

        # Some tenants use 'displayName', some might expose 'display_name' style;
        # we try displayName first and ignore if missing.
        if ($s.PSObject.Properties.Name -contains "displayName")
        {
            if ($s.displayName)
            {
                $k = $s.displayName.ToString().Trim().ToLowerInvariant()
                if (-not $lookup.ContainsKey($k)) { $lookup[$k] = $s }
            }
        }
    }

    return $lookup
}

$systems = Get-JcAllSystems
Write-Host ("Systems fetched: {0}" -f $systems.Count)

$systemLookup = Build-SystemLookup -Systems $systems
Write-Host ("Lookup keys built (hostname + displayName): {0}" -f $systemLookup.Count)

# -------------------------------
# Create System Group
# -------------------------------
Write-Host ""
Write-Host "Creating group '$GroupName'..."

$groupBody = @{
    name = $GroupName
    type = "static"
}

$group = Invoke-JcApi -Method "POST" -Url "$BaseUrl/api/v2/systemgroups" -Body $groupBody

if (-not $group.id)
{
    throw "Group creation did not return an id. Response: $($group | ConvertTo-Json -Depth 5)"
}

Write-Host ("Group created: {0} (id: {1})" -f $group.name, $group.id)

# -------------------------------
# Match + Add Members (progress)
# -------------------------------
$notFound   = New-Object System.Collections.Generic.List[string]
$added      = New-Object System.Collections.Generic.List[string]
$failedAdds = New-Object System.Collections.Generic.List[object]

$total = $DeviceNames.Count
$index = 0

Write-Host ""
Write-Host "Processing devices (local match -> add to group)..."

foreach ($name in $DeviceNames)
{
    $index++
    $pct = [int](($index / $total) * 100)
    Write-Progress -Activity "JumpCloud Group Population" -Status ("{0}/{1} - {2}" -f $index, $total, $name) -PercentComplete $pct

    $key = $name.Trim().ToLowerInvariant()

    if (-not $systemLookup.ContainsKey($key))
    {
        Write-Host ("  NOT FOUND: {0}" -f $name)
        $notFound.Add($name)
        continue
    }

    $sys = $systemLookup[$key]

    $memberBody = @{
        op   = "add"
        type = "system"
        id   = $sys.id
    }

    $memberUrl = "$BaseUrl/api/v2/systemgroups/$($group.id)/members"

    try
    {
        Write-Host ("  ADD: {0} -> id={1} (hostname='{2}')" -f $name, $sys.id, $sys.hostname)
        [void](Invoke-JcApi -Method "POST" -Url $memberUrl -Body $memberBody)
        $added.Add($name)
    }
    catch
    {
        $failedAdds.Add([pscustomobject]@{
            DeviceName = $name
            SystemId   = $sys.id
            Error      = $_.Exception.Message
        })
        Write-Host ("  FAILED: {0} - {1}" -f $name, $_.Exception.Message)
    }
}

Write-Progress -Activity "JumpCloud Group Population" -Completed

# -------------------------------
# Summary
# -------------------------------
Write-Host ""
Write-Host "Summary"
Write-Host "-------"
Write-Host ("Added:     {0}" -f $added.Count)
Write-Host ("Not found: {0}" -f $notFound.Count)
Write-Host ("Failed:    {0}" -f $failedAdds.Count)

if ($notFound.Count -gt 0)
{
    Write-Host ""
    Write-Host "NOT FOUND (no hostname/displayName match in JumpCloud inventory):"
    $notFound | Sort-Object | ForEach-Object { Write-Host " - $_" }
}

if ($failedAdds.Count -gt 0)
{
    Write-Host ""
    Write-Host "FAILED ADDS:"
    $failedAdds | Format-Table -AutoSize
}
