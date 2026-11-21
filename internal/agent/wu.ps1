# netio.patchman Windows Update helper, run by the agent with -EncodedCommand.
# Input comes from environment variables, output is one JSON document on stdout:
#   PATCHMAN_WU_MODE    scan | install
#   PATCHMAN_WU_ONLINE  1: search against the update service, otherwise the
#                       local cache of the last automatic detection is used
#   PATCHMAN_WU_KBS     install: comma separated update names (KB5044281)
#   PATCHMAN_WU_KIND    install without names: security | all
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

# Definition updates (Defender signatures) and feature upgrades are left out.
$skipCategories = @('E0789628-CE08-4437-BE74-2495B842F43B', '3689BDC8-B205-4AF4-8D4A-A63924C5E9D5')
$securityCategory = '0FA1201D-4330-4FA8-8AE9-B877473B6441'

function Get-UpdateName($u) {
    if ($u.KBArticleIDs.Count -gt 0) { return 'KB' + $u.KBArticleIDs.Item(0) }
    return $u.Identity.UpdateID
}

function Get-UpdateInfo($u) {
    $cats = @(); $ids = @(); $cves = @(); $class = ''
    foreach ($c in $u.Categories) {
        $cats += [string]$c.Name; $ids += ([string]$c.CategoryID).ToUpperInvariant()
        if ($c.Type -eq 'UpdateClassification' -and -not $class) { $class = [string]$c.Name }
    }
    foreach ($c in $u.CveIDs) { $cves += [string]$c }
    $date = ''
    try { $date = $u.LastDeploymentChangeTime.ToString('yyyy-MM-dd') } catch { }
    [ordered]@{
        name         = (Get-UpdateName $u)
        title        = [string]$u.Title
        severity     = [string]$u.MsrcSeverity
        categories   = $cats
        class        = $class
        category_ids = $ids
        cves         = $cves
        date         = $date
        security     = ($ids -contains $securityCategory) -or ([string]$u.MsrcSeverity -ne '')
    }
}

function Test-RebootPending {
    try { if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired) { return $true } } catch { }
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
        if (Test-Path -LiteralPath $k) { return $true }
    }
    return $false
}

$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'netio.patchman'

function Find-Updates([bool]$online) {
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $online
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $script:found = New-Object System.Collections.ArrayList
    foreach ($u in $result.Updates) {
        $skip = $false
        foreach ($c in $u.Categories) { if ($skipCategories -contains ([string]$c.CategoryID).ToUpperInvariant()) { $skip = $true } }
        if (-not $skip) { [void]$script:found.Add($u) }
    }
}

try {
    if ($env:PATCHMAN_WU_MODE -eq 'install') {
        Find-Updates $true
        $names = @()
        if ($env:PATCHMAN_WU_KBS) { $names = $env:PATCHMAN_WU_KBS -split ',' | Where-Object { $_ } }
        $coll = New-Object -ComObject Microsoft.Update.UpdateColl
        $picked = @()
        foreach ($u in $script:found) {
            $info = Get-UpdateInfo $u
            $take = $false
            if ($names.Count -gt 0) { $take = $names -contains $info.name }
            elseif ($env:PATCHMAN_WU_KIND -eq 'security') { $take = $info.security }
            else { $take = $true }
            if ($take) {
                if (-not $u.EulaAccepted) { $u.AcceptEula() }
                [void]$coll.Add($u)
                $picked += $info
            }
        }
        $missing = @()
        foreach ($n in $names) { if (-not ($picked | Where-Object { $_.name -eq $n })) { $missing += $n } }
        $results = @()
        $reboot = $false
        if ($coll.Count -gt 0) {
            $downloader = $session.CreateUpdateDownloader()
            $downloader.Updates = $coll
            [void]$downloader.Download()
            $ready = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($u in $coll) { if ($u.IsDownloaded) { [void]$ready.Add($u) } }
            $installRes = $null
            if ($ready.Count -gt 0) {
                $installer = $session.CreateUpdateInstaller()
                try { $installer.ForceQuiet = $true } catch { }
                $installer.Updates = $ready
                $installRes = $installer.Install()
                $reboot = [bool]$installRes.RebootRequired
            }
            $idx = 0
            foreach ($u in $ready) {
                $r = $installRes.GetUpdateResult($idx)
                $results += [ordered]@{ name = (Get-UpdateName $u); title = [string]$u.Title; result = [int]$r.ResultCode; hresult = ('0x{0:X8}' -f $r.HResult) }
                $idx++
            }
            foreach ($u in $coll) {
                if (-not $u.IsDownloaded) {
                    $results += [ordered]@{ name = (Get-UpdateName $u); title = [string]$u.Title; result = 4; hresult = 'download' }
                }
            }
        }
        $out = [ordered]@{ results = $results; missing = $missing; reboot_required = ($reboot -or (Test-RebootPending)) }
    } else {
        Find-Updates ($env:PATCHMAN_WU_ONLINE -eq '1')
        $list = @()
        foreach ($u in $script:found) { $list += Get-UpdateInfo $u }
        $out = [ordered]@{ updates = $list; reboot_required = (Test-RebootPending) }
    }
    $out | ConvertTo-Json -Depth 5 -Compress
} catch {
    [ordered]@{ error = $_.Exception.Message; hresult = ('0x{0:X8}' -f $_.Exception.HResult) } | ConvertTo-Json -Compress
    exit 1
}
