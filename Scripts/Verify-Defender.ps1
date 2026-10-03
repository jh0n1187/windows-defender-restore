#Requires -Version 5.1
<#
.SYNOPSIS
  Verificacao (SOMENTE LEITURA) do Microsoft Defender restaurado pelo kit. Grava Logs\Verify-<data>.log.

.DESCRIPTION
  [PASS]/[WARN]/[FAIL] para: arquivos, registro, servicos (registro, SCM, execucao), grupo svchost, politicas/bloqueios,
  WMI + Get-MpComputerStatus, Central de Seguranca, app Seguranca do Windows, tarefas, canal de eventos e catalogos.
  Codigo de saida: 0 = sem FAIL, 1 = ha FAIL.

.PARAMETER Functional
  Teste funcional com o arquivo de teste padrao EICAR (inofensivo): grava-o em %TEMP% e confirma que a protecao em tempo
  real o bloqueia. Gera uma notificacao/entrada de "ameaca" no historico do Defender - por isso e opcional.
#>
[CmdletBinding()]
param([switch]$Functional, [string]$KitRoot = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Continue'
$LogDir = Join-Path $KitRoot 'Logs'; New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Log = Join-Path $LogDir ("Verify-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$script:fail = 0; $script:warn = 0
function Out([string]$m, [string]$c = 'Gray') { Add-Content -Path $Log -Value $m -Encoding UTF8; Write-Host $m -ForegroundColor $c }
function Res([string]$status, [string]$item, [string]$det = '') {
    if ($status -eq 'FAIL') { $script:fail++ } elseif ($status -eq 'WARN') { $script:warn++ }
    $c = switch ($status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'INFO' { 'Gray' } default { 'Red' } }
    Out ("[{0}] {1}{2}" -f $status, $item, $(if ($det) { " - $det" })) $c
}

. (Join-Path $PSScriptRoot 'KitDefender.ps1')
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Out ("Verify-Defender | {0} | {1} {2} build {3}.{4} | {5}" -f $env:COMPUTERNAME, $cv.ProductName, $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) 'Cyan'
$KP = Get-KitProfile -KitRoot $KitRoot
if (-not $KP) { Res 'FAIL' 'Perfil' "nenhum perfil cobre o build $($cv.CurrentBuild)"; Out 'Overall ...................... FAIL' 'Red'; exit 1 }
$data = Get-KitData $KP
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) { [void](Set-KitPrivileges $true) } else { Res 'WARN' 'Elevacao' 'sem Administrador: chaves protegidas nao podem ser lidas (resultado parcial)' }
$st = Get-KitDefenderState $KP $data
if ($isAdmin) { [void](Set-KitPrivileges $false) }

# ---- componentes
if ($st.FilesMissing.Count) { Res 'FAIL' 'Files' ("{0} de {1} ausente(s): {2}{3}" -f $st.FilesMissing.Count, $st.FilesTotal, (($st.FilesMissing | Select-Object -First 5 | ForEach-Object { Split-Path $_.RelPath -Leaf }) -join ', '), $(if ($st.FilesMissing.Count -gt 5) { ', ...' })) }
else { Res 'PASS' 'Files' "$($st.FilesPresent) arquivo(s) presentes" }
if ($st.RegKeysMissing.Count -or $st.RegValuesMissing) { Res 'FAIL' 'Registry' ("{0} chave(s) e {1} valor(es) ausentes (ex.: {2})" -f $st.RegKeysMissing.Count, $st.RegValuesMissing, ($st.RegKeysMissing | Select-Object -First 1)) }
else { Res 'PASS' 'Registry' ("$($st.RegValuesPresent) valor(es) presentes" + $(if ($st.RegValuesManaged) { " ($($st.RegValuesManaged) removido(s)/administrado(s) pelo proprio Defender em execucao)" })) }
foreach ($g in $st.Svchost) { Res $(if ($g.Ok) { 'PASS' } else { 'FAIL' }) 'Svchost group' "$($g.Group) contem $($g.Service): $($g.Ok)" }

# ---- servicos
$pendingScm = @()
foreach ($s in $st.Services) {
    if (-not $s.RegOk) { Res 'FAIL' 'Service config' "$($s.Name): chave do servico ausente/incompleta"; continue }
    if ($s.Disabled) { Res 'FAIL' 'Service config' "$($s.Name): desativado (Start=$($s.Start))"; continue }
    if (-not $s.InScm) { $pendingScm += $s.Name; continue }
    $mustRun = $s.Name -in 'WinDefend', 'WdFilter', 'wscsvc'
    if ($s.State -eq 'Running') { Res 'PASS' 'Service start' "$($s.Name): em execucao" }
    elseif ($mustRun) { Res 'FAIL' 'Service start' "$($s.Name): $($s.State)" }
    else { Res 'INFO' 'Service start' "$($s.Name): $($s.State) (inicio sob demanda)" }
}
if ($pendingScm) { Res 'FAIL' 'Service registration' ("{0}: no registro, mas ainda nao carregado(s) pelo SCM - reinicie o Windows" -f ($pendingScm -join ', ')) }
elseif (-not ($st.Services | Where-Object { -not $_.RegOk })) { Res 'PASS' 'Service registration' 'todos os servicos do Defender registrados no SCM' }

# ---- bloqueios
if ($st.Policies) { foreach ($p in $st.Policies) { Res 'FAIL' 'Policies' "$($p.Key): $($p.Values) valor(es) de politica (desativam o Defender)" } } else { Res 'PASS' 'Policies' 'sem politicas do Windows Defender' }
if ($st.DisableValues) { Res 'FAIL' 'Disable values' (($st.DisableValues | ForEach-Object { "$($_.Name)=1" }) -join ', ') }
if ($null -ne $st.SmartScreenPolicy -and $st.SmartScreenPolicy -eq 0) { Res 'WARN' 'SmartScreen policy' 'EnableSmartScreen = 0 (SmartScreen desativado por politica)' }
if ($null -ne $st.AttachScan -and $st.AttachScan -ne 3) { Res 'WARN' 'Attachment scan' "Policies\Attachments\ScanWithAntiVirus = $($st.AttachScan) (anexos/downloads nao sao verificados; original = 3)" }
$tp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection
Res 'INFO' 'Tamper Protection' $(if ($null -eq $tp) { 'valor ausente' } elseif ($tp -band 1) { "ligada (valor $tp)" } else { "desligada (valor $tp) - pode ser ligada em Seguranca do Windows > Protecao contra virus e ameacas" })

# ---- WMI / estado do antivirus
if (-not $st.WmiClass) { Res 'FAIL' 'WMI' 'classe MSFT_MpComputerStatus ausente em root\Microsoft\Windows\Defender' }
else {
    try {
        $mp = Get-CimInstance -Namespace 'root\Microsoft\Windows\Defender' -ClassName MSFT_MpComputerStatus -ErrorAction Stop
        Res $(if ($mp.AMServiceEnabled -and $mp.AntivirusEnabled) { 'PASS' } else { 'FAIL' }) 'Antivirus' ("AMService={0} Antivirus={1} modo={2} plataforma={3} motor={4}" -f $mp.AMServiceEnabled, $mp.AntivirusEnabled, $mp.AMRunningMode, $mp.AMProductVersion, $mp.AMEngineVersion)
        Res $(if ($mp.RealTimeProtectionEnabled) { 'PASS' } else { 'WARN' }) 'Real-time protection' ("RealTime={0} OnAccess={1} Behavior={2} IOAV={3}" -f $mp.RealTimeProtectionEnabled, $mp.OnAccessProtectionEnabled, $mp.BehaviorMonitorEnabled, $mp.IoavProtectionEnabled)
        $age = $mp.AntivirusSignatureAge
        Res $(if ($age -le 7) { 'PASS' } else { 'WARN' }) 'Signatures' ("versao {0}, idade {1} dia(s){2}" -f $mp.AntivirusSignatureVersion, $age, $(if ($age -gt 7) { ' - atualize (Seguranca do Windows > Atualizacoes de protecao, ou MpCmdRun -SignatureUpdate)' }))
        if ($mp.AMProductVersion -and ([version]$mp.AMProductVersion) -lt [version]'4.18.2000.0') { Res 'WARN' 'Platform' "plataforma $($mp.AMProductVersion) e a da imagem original - o Windows Update (KB4052623) ou Updates\updateplatform.exe instala a atual" }
    } catch {
        $msg = ($_.Exception.Message -split "`n")[0]
        if ($pendingScm) { Res 'WARN' 'Antivirus' "Get-MpComputerStatus indisponivel antes do reinicio ($msg)" } else { Res 'FAIL' 'Antivirus' "Get-MpComputerStatus falhou: $msg" }
    }
}
try {
    $av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
    if ($av | Where-Object { $_.displayName -match 'Defender' }) { Res 'PASS' 'Security Center' (($av | ForEach-Object { "$($_.displayName) (0x{0:X})" -f $_.productState }) -join '; ') }
    else { Res 'WARN' 'Security Center' ("Windows Defender ainda nao registrado na Central de Seguranca" + $(if ($av) { ' - outros: ' + (($av | ForEach-Object displayName) -join ', ') })) }
} catch { Res 'WARN' 'Security Center' "root\SecurityCenter2 indisponivel: $(($_.Exception.Message -split "`n")[0])" }

# ---- app, tarefas, eventos, catalogos
if ($st.AppBlocked) { Res 'FAIL' 'Security app' ("marcado como removido: " + ($st.AppBlocked -join ', ')) }
elseif (-not (Test-Path -LiteralPath $st.AppManifest)) { Res 'FAIL' 'Security app' 'AppxManifest.xml do SecHealthUI ausente' }
elseif ($st.AppRegistered) { Res 'PASS' 'Security app' 'Seguranca do Windows registrado para o usuario atual' }
else { Res 'WARN' 'Security app' 'arquivos presentes, mas o app nao esta registrado para este usuario (sera registrado no proximo logon)' }
if ($st.StartupDisabled) { Res 'WARN' 'Tray icon' 'item de inicializacao SecurityHealth desabilitado (StartupApproved) - o SecurityHealthService nao e disparado no logon' }
$tm = @($st.Tasks | Where-Object { -not $_.Ok })
if ($tm) { Res 'WARN' 'Scheduled tasks' ("ausente(s): " + (($tm | ForEach-Object Name) -join ', ')) } else { Res 'PASS' 'Scheduled tasks' "$($st.Tasks.Count) tarefa(s) em \Microsoft\Windows\Windows Defender\" }
try { $ch = Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction Stop; Res 'PASS' 'Event channel' "Windows Defender/Operational habilitado=$($ch.IsEnabled) registros=$($ch.RecordCount)" }
catch { Res $(if ($pendingScm) { 'INFO' } else { 'WARN' }) 'Event channel' 'Windows Defender/Operational ainda nao disponivel (o servico de log le os canais no boot)' }
$cm = @($st.Catalogs | Where-Object { -not $_.Ok })
if ($cm) { Res 'WARN' 'Catalogs' "$($cm.Count) catalogo(s) de assinatura nao registrados" } elseif ($st.Catalogs.Count) { Res 'PASS' 'Catalogs' "$($st.Catalogs.Count) catalogo(s) registrados" }

# ---- teste funcional (EICAR)
if ($Functional) {
    $rt = $false; try { $rt = [bool](Get-CimInstance -Namespace 'root\Microsoft\Windows\Defender' -ClassName MSFT_MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { }
    if (-not $rt) { Res 'WARN' 'Functional (EICAR)' 'protecao em tempo real desligada/indisponivel - teste nao executado' }
    else {
        $f = Join-Path $env:TEMP ("kit-eicar-{0}.com" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
        $s = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        $blocked = $false
        try { [IO.File]::WriteAllText($f, $s, [Text.Encoding]::ASCII) } catch { $blocked = $true }
        for ($i = 0; $i -lt 20 -and -not $blocked; $i++) {
            Start-Sleep -Milliseconds 750
            if (-not (Test-Path -LiteralPath $f)) { $blocked = $true; break }
            try { [void][IO.File]::ReadAllBytes($f) } catch { $blocked = $true }
        }
        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
        Res $(if ($blocked) { 'PASS' } else { 'FAIL' }) 'Functional (EICAR)' $(if ($blocked) { 'arquivo de teste bloqueado/removido pela protecao em tempo real' } else { 'arquivo de teste NAO foi bloqueado em 15 s' })
    }
}

$overall = if ($script:fail) { 'FAIL' } elseif ($script:warn) { 'PASS (com avisos)' } else { 'PASS' }
Out ("Overall ...................... {0}   (FAIL={1} WARN={2})" -f $overall, $script:fail, $script:warn) $(if ($script:fail) { 'Red' } elseif ($script:warn) { 'Yellow' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
