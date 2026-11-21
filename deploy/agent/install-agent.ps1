# netio.patchman Windows ajan kurulum betiği
#
# Sunucudan indirerek kurulum (yönetici PowerShell veya komut istemi):
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm 'https://patchman.your-domain/downloads/install-agent.ps1').TrimStart([char]65279))) -ServerUrl 'https://patchman.your-domain' -Token '<kayıt-anahtarı>'"
#
# Çevrimdışı kurulum: netio-patchman-agent-windows-amd64.exe dosyasını bu
# betikle birlikte kopyalayın ve -Binary seçeneğini kullanın:
#   .\install-agent.ps1 -ServerUrl https://patchman.your-domain -Token <kayıt-anahtarı> -Binary .\netio-patchman-agent-windows-amd64.exe
#
# Kaldırma: .\install-agent.ps1 -Uninstall
[CmdletBinding()]
param(
    [string]$ServerUrl,
    [string]$Token,
    [string]$Binary,
    [string]$CaFile,
    [switch]$DisableRemoteUpdates,
    [switch]$DisableAutoUpdate,
    [string]$Locale,
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ServiceName = 'netio-patchman-agent'
$DistName = 'netio-patchman-agent-windows-amd64.exe'
$InstallDir = Join-Path $env:ProgramFiles 'netio-patchman'
$ExePath = Join-Path $InstallDir 'netio-patchman-agent.exe'
$DataDir = Join-Path $env:ProgramData 'netio-patchman'
$ConfigFile = Join-Path $DataDir 'agent.env'
$Credentials = Join-Path $DataDir 'credentials.json'
$LogFile = Join-Path $DataDir 'agent.log'

function Write-Info([string]$Message) { Write-Host "[netio.patchman] $Message" }
function Stop-WithError([string]$Message) {
    Write-Host "[netio.patchman] HATA: $Message" -ForegroundColor Red
    exit 1
}

function Show-Usage {
    @"
netio.patchman Windows ajan kurulumu

Kullanım:
  .\install-agent.ps1 -ServerUrl <adres> -Token <kayıt-anahtarı> [seçenekler]
  (yönetici yetkisi gerekir: PowerShell'i "Yönetici olarak çalıştır" ile açın)

Seçenekler:
  -ServerUrl <adres>        Merkezi netio.patchman sunucusunun adresi (zorunlu)
  -Token <anahtar>          Ajan kayıt anahtarı (yeni kurulumda zorunlu)
  -Binary <dosya>           Ajanı sunucudan indirmek yerine bu dosyadan kur
  -CaFile <dosya>           Ajanın sunucu sertifikasını doğrulaması için ek CA dosyası (PEM)
  -DisableRemoteUpdates     Panelden başlatılan güncelleme işlerini bu sunucuda kapat
  -DisableAutoUpdate        Ajanın kendini otomatik güncellemesini bu sunucuda kapat
  -Locale <dil>             Ajan mesajlarının dili: tr-TR (varsayılan), en-US, de-DE, ru-RU
  -Uninstall                Ajanı, hizmeti ve yapılandırmayı kaldır
  -Help                     Bu yardım metnini gösterir
"@ | Write-Host
}

function Wait-ServiceStatus([string]$Status, [int]$Seconds) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        $s = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $s -or [string]$s.Status -eq $Status) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Stop-Agent {
    $s = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Stopped') {
        Write-Info "Çalışan ajan durduruluyor."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        if (-not (Wait-ServiceStatus 'Stopped' 30)) { Stop-WithError "Ajan hizmeti durdurulamadı: $ServiceName" }
    }
}

if ($Help) { Show-Usage; exit 0 }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-WithError "Bu betik yönetici yetkisiyle çalıştırılmalıdır: PowerShell'i veya komut istemini `"Yönetici olarak çalıştır`" ile açın."
}

if ($Uninstall) {
    Stop-Agent
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        & sc.exe delete $ServiceName | Out-Null
        Write-Info "Hizmet kaldırıldı: $ServiceName"
    }
    foreach ($d in @($InstallDir, $DataDir)) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force; Write-Info "Silindi: $d" }
    }
    Write-Info "Ajan kaldırıldı. Sunucu kaydını panelde Sunucu Envanteri sayfasından silebilirsiniz."
    exit 0
}

if ([Environment]::OSVersion.Version.Major -lt 10) {
    Stop-WithError "Ajan Windows 10, Windows 11 ve Windows Server 2016 veya daha yeni sürümlerde çalışır."
}
$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
if ($arch -ne 'AMD64') { Stop-WithError "Desteklenmeyen işlemci mimarisi: $arch (yalnızca x64 / AMD64 desteklenir)." }

if (-not $ServerUrl) { Show-Usage; Stop-WithError "Merkezi sunucu adresi (-ServerUrl) zorunludur." }
$ServerUrl = $ServerUrl.TrimEnd('/')
if ($ServerUrl -match '^http://') {
    Write-Info "UYARI: Sunucu adresi şifrelenmemiş HTTP kullanıyor. Üretim ortamında HTTPS kullanın."
} elseif ($ServerUrl -notmatch '^https://') {
    Stop-WithError "Sunucu adresi http:// veya https:// ile başlamalıdır: $ServerUrl"
}
if ($Locale -and $Locale -cnotmatch '^[a-z]{2}-[A-Z]{2}$') {
    Stop-WithError "Geçersiz dil: $Locale (örnek: tr-TR, en-US, de-DE, ru-RU)"
}
if (-not $Token -and -not (Test-Path -LiteralPath $Credentials)) {
    Stop-WithError "Ajan kayıt anahtarı (-Token) zorunludur. Anahtarı yönetim panelindeki Ajan Yönetimi sayfasından oluşturabilirsiniz."
}
if ($CaFile -and -not (Test-Path -LiteralPath $CaFile -PathType Leaf)) { Stop-WithError "CA dosyası bulunamadı: $CaFile" }

$wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($wu -and [string]$wu.StartType -eq 'Disabled') {
    Write-Info "UYARI: Windows Update hizmeti (wuauserv) devre dışı. Bekleyen güncellemeler okunamaz ve kurulamaz; hizmeti El ile veya Otomatik başlatmaya alın."
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("netio-patchman-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
try {
    if (-not $Binary) {
        $url = "$ServerUrl/downloads/agent/$DistName"
        $Binary = Join-Path $tmpDir $DistName
        Write-Info "Ajan indiriliyor: $url"
        try { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $Binary } catch { Stop-WithError "Ajan dosyası indirilemedi: $($_.Exception.Message)" }
        $sumText = $null
        try { $sumText = (Invoke-WebRequest -UseBasicParsing -Uri "$url.sha256").Content } catch { }
        if ($sumText) {
            if ($sumText -is [byte[]]) { $sumText = [Text.Encoding]::ASCII.GetString($sumText) }
            $expected = ([string]$sumText).Trim().Split(' ')[0].ToLowerInvariant()
            $actual = (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($expected -ne $actual) { Stop-WithError "İndirilen dosyanın SHA-256 özeti eşleşmiyor." }
            Write-Info "SHA-256 doğrulaması başarılı."
        }
    }
    if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { Stop-WithError "Ajan dosyası bulunamadı: $Binary" }
    $Binary = (Resolve-Path -LiteralPath $Binary).Path

    $out = & $Binary -version 2>&1
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Ajan dosyası çalıştırılamadı. Dosyayı ve mimariyi kontrol edin. Çıktı: $out" }

    Stop-Agent
    Write-Info "Ajan kuruluyor: $ExePath"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -LiteralPath $Binary -Destination $ExePath -Force

    # Configuration, credentials and logs: SYSTEM and Administrators only.
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Yapılandırma dizininin izinleri ayarlanamadı: $DataDir" }

    if (Test-Path -LiteralPath $ConfigFile) {
        Copy-Item -LiteralPath $ConfigFile -Destination ("$ConfigFile." + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '.bak')
        Write-Info "Mevcut yapılandırma yedeklendi."
    }
    $lines = @('# netio.patchman ajan yapılandırması', "PATCHMAN_SERVER_URL=$ServerUrl")
    if ($Token) { $lines += "PATCHMAN_ENROLLMENT_TOKEN=$Token" }
    if ($CaFile) {
        $caDest = Join-Path $DataDir 'ca.pem'
        Copy-Item -LiteralPath $CaFile -Destination $caDest -Force
        $lines += "PATCHMAN_CA_FILE=$caDest"
    }
    $lines += "PATCHMAN_REMOTE_UPDATES=$((-not $DisableRemoteUpdates).ToString().ToLowerInvariant())"
    $lines += "PATCHMAN_AUTO_UPDATE=$((-not $DisableAutoUpdate).ToString().ToLowerInvariant())"
    if ($Locale) { $lines += "PATCHMAN_LOCALE=$Locale" }
    Write-Info "Yapılandırma yazılıyor: $ConfigFile"
    [IO.File]::WriteAllText($ConfigFile, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))

    if ($Token -and (Test-Path -LiteralPath $Credentials)) {
        Write-Info "Yeni kayıt anahtarı verildiği için mevcut ajan kimliği yenilenecek."
        Remove-Item -LiteralPath $Credentials -Force
    }

    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Info "Windows hizmeti oluşturuluyor: $ServiceName"
        New-Service -Name $ServiceName -BinaryPathName "`"$ExePath`"" -DisplayName 'netio.patchman agent' `
            -Description 'netio.patchman: envanter, Windows Update ve güvenlik açığı takibi' -StartupType Automatic | Out-Null
    } else {
        Set-Service -Name $ServiceName -StartupType Automatic
    }
    # Restart after failures and after a self-update (non-zero exit code).
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
    & sc.exe failureflag $ServiceName 1 | Out-Null

    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    if ([string](Get-Service -Name $ServiceName).Status -eq 'Running') {
        Write-Info "Kurulum tamamlandı. Ajan çalışıyor ve sunucuya kaydoluyor."
        Write-Info "Durum: Get-Service $ServiceName"
        Write-Info "Kayıtlar: Get-Content '$LogFile' -Tail 50 -Wait"
    } else {
        Stop-WithError "Ajan başlatılamadı. Ayrıntılar için: Get-Content '$LogFile' -Tail 50"
    }
} finally {
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
