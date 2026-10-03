#Requires -Version 5.1
<#
.SYNOPSIS
  Etapa B do kit: remove os BLOQUEIOS do debloat e LIGA o Microsoft Defender.

.DESCRIPTION
  1. Politicas:   remove HKLM\SOFTWARE\Policies\Microsoft\Windows Defender (DisableAntiSpyware, DisableRealtimeMonitoring...)
                  e Policies\Microsoft\Windows\System\EnableSmartScreen = 0 (exceto com -KeepSmartScreenPolicy).
  2. Produto:     remove DisableAntiSpyware/DisableAntiVirus e Real-Time Protection\Disable* = 1 em SOFTWARE\Microsoft\Windows Defender;
                  Policies\Attachments\ScanWithAntiVirus volta a 3 (verificar anexos/downloads).
  3. Servicos:    servico do Defender com Start = 4 (Desativado) volta ao valor original da imagem.
  4. App/bandeja: reabilita o item de inicializacao SecurityHealth (icone da bandeja) se estiver desabilitado;
                  remove a marca Deprovisioned/EndOfLife do app Seguranca do Windows, registra o app para o usuario atual
                  e cria uma entrada Active Setup que o registra no proximo logon dos demais usuarios.
  5. Ativacao:    (somente quando os servicos ja existem no SCM, ou seja, apos o reinicio) inicia wscsvc/SecurityHealthService/
                  WinDefend, atualiza assinaturas (MpCmdRun -SignatureUpdate) e, se existirem, instala os pacotes offline
                  de Updates\ (mpam-fe.exe, updateplatform*.exe - somente se assinados pela Microsoft).
  Tudo que e removido e exportado antes para Backup\Enable-<timestamp>\ (.reg) - Rollback-Defender.ps1 reimporta.

.PARAMETER KeepSmartScreenPolicy  Nao remove a politica EnableSmartScreen.
.PARAMETER NoUpdate               Nao atualiza assinaturas (sem acesso a rede).
.PARAMETER WhatIf                 Mostra o que seria feito, sem alterar o sistema.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$KeepSmartScreenPolicy,
    [switch]$NoUpdate,
    [string]$KitRoot = (Split-Path $PSScriptRoot -Parent)
)
$ErrorActionPreference = 'Continue'
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir = Join-Path $KitRoot 'Logs'; New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Log = Join-Path $LogDir "Enable-$ts.log"
$History = Join-Path $LogDir 'Repair-History.log'
$DryRun = [bool]$WhatIfPreference
$WhatIfPreference = $false   # o modo simulacao e tratado por $DryRun; o log precisa ser gravado
function L([string]$m, [string]$c = 'Gray') {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Add-Content -Path $Log -Value $line -Encoding UTF8
    Write-Host $line -ForegroundColor $c
}
function Hist([string]$m) { "[{0}] {1}" -f (Get-Date -Format 's'), $m | Out-File -FilePath $History -Append -Encoding UTF8 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'ERRO: execute como Administrador.' -ForegroundColor Red; exit 2 }
if (-not [Environment]::Is64BitProcess) { Write-Host 'ERRO: use o PowerShell 64-bit.' -ForegroundColor Red; exit 2 }
. (Join-Path $PSScriptRoot 'KitDefender.ps1')
$KP = Get-KitProfile -KitRoot $KitRoot
if (-not $KP) { L 'INCOMPATIVEL: nenhum perfil cobre este build. Abortando.' 'Red'; exit 3 }
if (-not $KP.Features.Enable) { L "Perfil $($KP.Name) nao suporta a etapa de habilitacao. Nada alterado." 'Yellow'; exit 0 }
$data = Get-KitData $KP
L ("Enable-Defender | perfil {0} | Modo: {1}" -f $KP.Name, $(if ($DryRun) { 'WHATIF (sem alteracoes)' } else { 'EXECUCAO' })) 'Cyan'
if (-not (Set-KitPrivileges $true)) { L 'ERRO: nao foi possivel ativar SeRestorePrivilege.' 'Red'; exit 2 }

$Backup = Join-Path $KitRoot "Backup\Enable-$ts"
New-Item -ItemType Directory -Path $Backup -Force | Out-Null
$changes = Join-Path $Backup 'changes.txt'
$errors = 0; $changed = 0; $needReboot = $false
function Export-KitKey([string]$sub, [string]$file) {
    & reg.exe export "HKLM\$sub" (Join-Path $Backup $file) /y 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

# ------------------------------------------------------------------ 1) politicas
$polSub = 'SOFTWARE\Policies\Microsoft\Windows Defender'
if (Test-Path "HKLM:\$polSub") {
    $n = 0; foreach ($x in @(Get-Item "HKLM:\$polSub") + @(Get-ChildItem "HKLM:\$polSub" -Recurse -ErrorAction SilentlyContinue)) { $n += $x.ValueCount }
    if ($n -eq 0) { L 'POLITICA Windows Defender: chave sem valores - nada a remover' 'Green' }
    elseif ($DryRun) { L "WHATIF POLITICA HKLM\$polSub seria removida ($n valor(es))" 'Yellow' }
    elseif (-not (Export-KitKey $polSub 'policy-WindowsDefender.reg')) { L "ERRO  POLITICA: falha ao exportar HKLM\$polSub - NAO removida" 'Red'; $errors++ }
    else {
        try { [KitReg]::DeleteKey($polSub, $true); Add-Content $changes "POLICYKEY HKLM\$polSub|policy-WindowsDefender.reg" -Encoding UTF8
              L "POLITICA HKLM\$polSub removida ($n valor(es); backup policy-WindowsDefender.reg)" 'Cyan'; $changed++ }
        catch { L "ERRO  POLITICA HKLM\${polSub}: $($_.Exception.Message)" 'Red'; $errors++ }
    }
} else { L 'POLITICA Windows Defender: ausente - nada a remover' 'Green' }

$ssKey = 'SOFTWARE\Policies\Microsoft\Windows\System'
$ss = (Get-ItemProperty "HKLM:\$ssKey" -Name EnableSmartScreen -ErrorAction SilentlyContinue).EnableSmartScreen
if ($null -ne $ss -and $ss -eq 0) {
    if ($KeepSmartScreenPolicy) { L 'POLITICA EnableSmartScreen = 0 mantida (-KeepSmartScreenPolicy)' 'DarkYellow' }
    elseif ($DryRun) { L 'WHATIF POLITICA EnableSmartScreen = 0 seria removida' 'Yellow' }
    else {
        try { [KitReg]::DeleteValue($ssKey, 'EnableSmartScreen'); Add-Content $changes "POLICYVAL HKLM\$ssKey|EnableSmartScreen|dword|0" -Encoding UTF8
              L 'POLITICA EnableSmartScreen = 0 removida (SmartScreen volta a ser controlado em Seguranca do Windows)' 'Cyan'; $changed++ }
        catch { L "ERRO  POLITICA EnableSmartScreen: $($_.Exception.Message)" 'Red'; $errors++ }
    }
}

# ------------------------------------------------------------------ 2) valores de desativacao na chave do produto
$wd = 'SOFTWARE\Microsoft\Windows Defender'
foreach ($pair in @(@($wd, 'DisableAntiSpyware'), @($wd, 'DisableAntiVirus'), @("$wd\Real-Time Protection", 'DisableRealtimeMonitoring'), @("$wd\Real-Time Protection", 'DisableBehaviorMonitoring'),
                    @("$wd\Real-Time Protection", 'DisableOnAccessProtection'), @("$wd\Real-Time Protection", 'DisableScanOnRealtimeEnable'), @("$wd\Real-Time Protection", 'DisableIOAVProtection'))) {
    if (-not [KitReg]::KeyExists($pair[0])) { continue }
    $t = 0; $b = [KitReg]::GetValue($pair[0], $pair[1], [ref]$t)
    if (-not $b -or $b.Length -lt 4 -or [BitConverter]::ToUInt32($b, 0) -ne 1) { continue }
    if ($DryRun) { L "WHATIF HKLM\$($pair[0])\$($pair[1]) = 1 seria removido" 'Yellow'; continue }
    try { [KitReg]::DeleteValue($pair[0], $pair[1]); Add-Content $changes "POLICYVAL HKLM\$($pair[0])|$($pair[1])|dword|1" -Encoding UTF8
          L "DESATIVACAO HKLM\$($pair[0])\$($pair[1]) = 1 removido" 'Cyan'; $changed++ }
    catch { L "ERRO  HKLM\$($pair[0])\$($pair[1]): $($_.Exception.Message)" 'Red'; $errors++ }
}

# verificacao de anexos/downloads: o debloat grava ScanWithAntiVirus = 1 (nao verificar); o valor original da imagem e 3
$atKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
$at = (Get-ItemProperty "HKLM:\$atKey" -Name ScanWithAntiVirus -ErrorAction SilentlyContinue).ScanWithAntiVirus
if ($null -ne $at -and $at -ne 3) {
    if ($DryRun) { L "WHATIF HKLM\$atKey\ScanWithAntiVirus = $at voltaria a 3 (verificar anexos)" 'Yellow' }
    else {
        try { [KitReg]::SetValue($atKey, 'ScanWithAntiVirus', 4, [BitConverter]::GetBytes([uint32]3)); Add-Content $changes "SETVAL HKLM\$atKey|ScanWithAntiVirus|$at|3" -Encoding UTF8
              L "DESATIVACAO Attachments\ScanWithAntiVirus = $at -> 3 (anexos/downloads voltam a ser verificados)" 'Cyan'; $changed++ }
        catch { L "ERRO  Attachments\ScanWithAntiVirus: $($_.Exception.Message)" 'Red'; $errors++ }
    }
}

# ------------------------------------------------------------------ 3) servicos desativados
foreach ($s in @($data.Services)) {
    $sub = "SYSTEM\CurrentControlSet\Services\$s"
    if (-not [KitReg]::KeyExists($sub)) { continue }
    $want = ($data.Keys | Where-Object { $_.Hive -eq 'SYSTEM' -and $_.Path -ieq "ControlSet001\Services\$s" } | Select-Object -First 1).Values | Where-Object Name -eq 'Start' | Select-Object -First 1
    $t = 0; $b = [KitReg]::GetValue($sub, 'Start', [ref]$t)
    if (-not $want -or -not $b -or [BitConverter]::ToUInt32($b, 0) -ne 4) { continue }
    if ($DryRun) { L "WHATIF SERVICO ${s}: Start 4 (Desativado) voltaria a $($want.Data)" 'Yellow'; continue }
    try { [KitReg]::SetValue($sub, 'Start', 4, [BitConverter]::GetBytes([uint32]$want.Data)); Add-Content $changes "SVCSTART $s|4|$($want.Data)" -Encoding UTF8
          L "SERVICO ${s}: Start 4 (Desativado) -> $($want.Data) (valor original)" 'Cyan'; $changed++; $needReboot = $true }
    catch { L "ERRO  SERVICO ${s}: $($_.Exception.Message)" 'Red'; $errors++ }
}

# ------------------------------------------------------------------ 4) app Seguranca do Windows
$ax = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$blocked = @(@(Get-ChildItem "HKLM:\$ax\Deprovisioned" -ErrorAction SilentlyContinue) + @(Get-ChildItem "HKLM:\$ax\EndOfLife" -Recurse -ErrorAction SilentlyContinue) |
    Where-Object { $_.PSChildName -like 'Microsoft.Windows.SecHealthUI*' } | ForEach-Object { $_.Name -replace '^HKEY_LOCAL_MACHINE\\', '' })
$bi = 0
foreach ($bk in $blocked) {
    $bi++
    if ($DryRun) { L "WHATIF APP marca de remocao HKLM\$bk seria apagada" 'Yellow'; continue }
    if (-not (Export-KitKey $bk "appx-blocked-$bi.reg")) { L "ERRO  APP: falha ao exportar HKLM\$bk" 'Red'; $errors++; continue }
    try { [KitReg]::DeleteKey($bk, $true); Add-Content $changes "APPXKEY HKLM\$bk|appx-blocked-$bi.reg" -Encoding UTF8; L "APP   marca de remocao apagada: HKLM\$bk" 'Cyan'; $changed++ }
    catch { L "ERRO  APP HKLM\${bk}: $($_.Exception.Message)" 'Red'; $errors++ }
}
$appManifest = Join-Path $env:SystemRoot 'SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\AppxManifest.xml'
if (Test-Path -LiteralPath $appManifest) {
    if (Get-AppxPackage -Name 'Microsoft.Windows.SecHealthUI' -ErrorAction SilentlyContinue) { L 'APP   Seguranca do Windows ja registrado para o usuario atual' 'Green' }
    elseif ($DryRun) { L 'WHATIF APP Seguranca do Windows seria registrado (Add-AppxPackage -Register)' 'Yellow' }
    else {
        try { Add-AppxPackage -Register $appManifest -DisableDevelopmentMode -ErrorAction Stop; L "APP   Seguranca do Windows registrado para $env:USERNAME" 'Cyan'; Add-Content $changes "APPXREG $env:USERNAME" -Encoding UTF8; $changed++ }
        catch { L "AVISO APP: registro falhou agora ($(($_.Exception.Message -split "`n")[0])) - sera tentado de novo no proximo logon (Active Setup)" 'Yellow' }
    }
    # demais usuarios (e este, se falhou): registro no proximo logon de cada um, uma unica vez
    $as = 'SOFTWARE\Microsoft\Active Setup\Installed Components\{6E1F5B2A-3C47-4E0B-9D53-5A1B7D0C8F21}'
    if (-not [KitReg]::KeyExists($as)) {
        if ($DryRun) { L 'WHATIF APP entrada Active Setup (registro do app no logon de cada usuario) seria criada' 'Yellow' }
        else {
            try {
                $stub = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Add-AppxPackage -Register $env:SystemRoot\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\AppxManifest.xml -DisableDevelopmentMode"'
                [void][KitReg]::CreateKeyChain($as)
                [KitReg]::SetValue($as, '', 1, [Text.Encoding]::Unicode.GetBytes("Restore-Defender: registrar app Seguranca do Windows`0"))
                [KitReg]::SetValue($as, 'StubPath', 1, [Text.Encoding]::Unicode.GetBytes($stub + "`0"))
                [KitReg]::SetValue($as, 'Version', 1, [Text.Encoding]::Unicode.GetBytes("1,0,0,0`0"))
                Add-Content $changes "ACTIVESETUP HKLM\$as" -Encoding UTF8
                L 'APP   Active Setup criado: o app sera registrado no proximo logon de cada usuario' 'Cyan'; $changed++
            } catch { L "ERRO  APP Active Setup: $($_.Exception.Message)" 'Red'; $errors++ }
        }
    }
} else { L 'APP   AppxManifest.xml do SecHealthUI ausente (etapa A nao restaurou o grupo 6) - registro ignorado' 'DarkYellow' }

# icone da bandeja (SecurityHealthSystray): e ele que, no logon, dispara o SecurityHealthService - sem o servico o Defender
# nao aparece na Central de Seguranca. O debloat deixa o item de inicializacao desabilitado em StartupApproved\Run.
if (Test-KitStartupDisabled) {
    if ($DryRun) { L 'WHATIF INICIALIZACAO item SecurityHealth (icone da bandeja) seria reabilitado' 'Yellow' }
    else {
        try {
            $old = (Get-ItemProperty "HKLM:\$KitStartupApprovedKey" -Name SecurityHealth).SecurityHealth
            [KitReg]::SetValue($KitStartupApprovedKey, 'SecurityHealth', 3, [byte[]](2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
            Add-Content $changes ("SETBIN HKLM\{0}|SecurityHealth|{1}" -f $KitStartupApprovedKey, (-join ($old | ForEach-Object { $_.ToString('x2') }))) -Encoding UTF8
            L 'INICIALIZACAO item SecurityHealth (icone da bandeja) reabilitado em StartupApproved\Run' 'Cyan'; $changed++
        } catch { L "ERRO  INICIALIZACAO StartupApproved: $($_.Exception.Message)" 'Red'; $errors++ }
    }
}

# ------------------------------------------------------------------ 5) ativacao (so com os servicos carregados pelo SCM)
$wdSvc = Get-SvcStartInfo 'WinDefend'
if (-not $wdSvc.InScm) {
    if ($wdSvc.Reg -ne $null) { L 'ATIVACAO: servico WinDefend existe no registro mas ainda nao no SCM - REINICIE o Windows e execute o kit de novo.' 'Yellow'; $needReboot = $true }
    else { L 'ATIVACAO: servico WinDefend inexistente (etapa A nao executada?) - nada a iniciar.' 'Yellow' }
} elseif ($DryRun) { L 'WHATIF ATIVACAO: servicos seriam iniciados e as assinaturas atualizadas' 'Yellow' }
else {
    foreach ($s in 'wscsvc', 'SecurityHealthService', 'WinDefend') {
        $i = Get-SvcStartInfo $s
        if (-not $i.InScm -or $i.State -eq 'Running') { continue }
        & sc.exe start $s 2>&1 | Out-Null
        for ($w = 0; $w -lt 15; $w++) { Start-Sleep 1; if ((Get-SvcStartInfo $s).State -eq 'Running') { break } }
        $st = (Get-SvcStartInfo $s).State
        L "SERVICO ${s}: $st" $(if ($st -eq 'Running') { 'Green' } else { 'Yellow' })
    }
    # registro do Defender na Central de Seguranca (feito pelo SecurityHealthService / wscsvc depois de iniciados)
    $wsc = $false
    for ($w = 0; $w -lt 20 -and -not $wsc; $w++) {
        try { $wsc = [bool](Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Where-Object { $_.displayName -match 'Defender' }) } catch { }
        if (-not $wsc) { Start-Sleep 2 }
    }
    L ("CENTRAL DE SEGURANCA: Defender {0}" -f $(if ($wsc) { 'registrado' } else { 'ainda nao registrado (pode levar alguns minutos apos o logon)' })) $(if ($wsc) { 'Green' } else { 'Yellow' })
    $mp = Get-KitMpCmdRun
    # pacotes offline opcionais (baixados pelo usuario do site da Microsoft) - so executa se a assinatura for valida e da Microsoft
    foreach ($pkg in @(Get-ChildItem (Join-Path $KitRoot 'Updates') -File -Include 'updateplatform*.exe', 'mpam-fe*.exe' -Recurse -ErrorAction SilentlyContinue | Sort-Object { $_.Name -notlike 'updateplatform*' })) {
        $sig = Get-AuthenticodeSignature -LiteralPath $pkg.FullName
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { L "AVISO Updates\$($pkg.Name): assinatura '$($sig.Status)' nao e da Microsoft - NAO executado" 'Yellow'; continue }
        L "UPDATE executando pacote offline Updates\$($pkg.Name) ..."
        $p = Start-Process -FilePath $pkg.FullName -Wait -PassThru
        L "UPDATE Updates\$($pkg.Name): codigo $($p.ExitCode)" $(if ($p.ExitCode -eq 0) { 'Cyan' } else { 'Yellow' })
    }
    if ($NoUpdate) { L 'ASSINATURAS: atualizacao ignorada (-NoUpdate)' 'DarkYellow' }
    elseif (-not $mp) { L 'AVISO ASSINATURAS: MpCmdRun.exe nao encontrado' 'Yellow' }
    elseif ((Get-SvcStartInfo 'WinDefend').State -ne 'Running') { L 'AVISO ASSINATURAS: WinDefend nao esta em execucao - atualizacao ignorada' 'Yellow' }
    else {
        L "ASSINATURAS: $mp -SignatureUpdate (pode levar alguns minutos) ..."
        $o = & $mp -SignatureUpdate 2>&1 | Out-String; $rc = $LASTEXITCODE
        if ($rc -ne 0) { L "ASSINATURAS: Windows Update indisponivel (codigo $rc) - tentando direto do Microsoft Malware Protection Center (-MMPC) ..." 'Yellow'; $o = & $mp -SignatureUpdate -MMPC 2>&1 | Out-String; $rc = $LASTEXITCODE }
        if ($rc -eq 0) { L 'ASSINATURAS: atualizadas' 'Green' }
        else { L ("AVISO ASSINATURAS: falha (codigo $rc) - " + (($o -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -Last 2) -join ' ') + ' | Alternativa: baixe mpam-fe.exe da Microsoft e coloque em Updates\') 'Yellow' }
    }
}
[void](Set-KitPrivileges $false)

L ''
L ("RESUMO: alteracoes={0} erros={1}" -f $changed, $errors) 'Cyan'
if ($needReboot -and -not $DryRun) { L 'REINICIALIZACAO NECESSARIA para concluir a ativacao do Defender.' 'Yellow' }
Hist ("Enable-Defender concluido: alteracoes={0} erros={1} reboot={2} (backup {3})" -f $changed, $errors, $needReboot, $Backup)
if ((-not $DryRun) -and (Test-Path $changes)) { Copy-Item $Log $Backup -ErrorAction SilentlyContinue }
else { Remove-Item -LiteralPath $Backup -Recurse -Force -ErrorAction SilentlyContinue }
if ($errors) { exit 1 } else { exit 0 }
