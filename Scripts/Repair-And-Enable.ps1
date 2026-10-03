#Requires -Version 5.1
<#
.SYNOPSIS
  Execucao completa e INTELIGENTE do kit Restore-Defender: primeiro DIAGNOSTICA o que falta na maquina e
  depois executa SOMENTE as etapas necessarias.

  Etapas possiveis (cada uma so roda se o diagnostico apontar necessidade):
    A) Restore-Defender.ps1  - arquivos, pastas de dados, registro (servicos/COM/eventos), svchost, catalogos, WMI, tarefas
    B) Enable-Defender.ps1   - remove politicas/bloqueios do debloat, libera o app Seguranca do Windows, inicia os
                               servicos e atualiza as assinaturas
    C) Verify-Defender.ps1   - sempre (somente leitura)
    D) Limpeza final         - sempre, exceto -CheckOnly: descarta backups sem alteracoes e logs antigos

  O reparo tem DUAS passagens: a 1a recria servicos e drivers no registro (o Windows so os carrega no boot) e termina
  com "REINICIO NECESSARIO"; apos reiniciar, a 2a passagem inicia a protecao, atualiza as assinaturas e verifica.

.PARAMETER CheckOnly   So diagnostica e mostra o plano; nao altera nada.
.PARAMETER NoEnable    Nao executa B (nao mexe em politicas nem liga a protecao).
.PARAMETER NoUpdate    Nao atualiza assinaturas (sem rede).
.PARAMETER Functional  Inclui o teste funcional com o arquivo EICAR na verificacao.
.PARAMETER Force       Executa A e B mesmo sem necessidade (continuam idempotentes).
#>
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$NoEnable, [switch]$NoUpdate, [switch]$Functional, [switch]$Force)
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
$KitRoot = Split-Path $PSScriptRoot -Parent
New-Item -ItemType Directory -Path (Join-Path $KitRoot 'Logs') -Force | Out-Null
$hist = Join-Path $KitRoot 'Logs\Repair-History.log'
function Hist([string]$m) { "[{0}] {1}" -f (Get-Date -Format 's'), $m | Out-File $hist -Append -Encoding UTF8 }

# ---- status final (sempre a ultima coisa no log)
$runStart = Get-Date
$steps = New-Object System.Collections.Generic.List[object]
function Step([string]$name, [string]$res, [string]$det = '') { $steps.Add([pscustomobject]@{ Etapa = $name; Resultado = $res; Detalhe = $det }) }
function Write-FinalStatus([string]$status, [string[]]$motivos = @(), [string[]]$acoes = @(), [int]$code = 0) {
    $cor = switch -Wildcard ($status) { 'SUCESSO COM*' { 'Yellow'; break } 'REINICIO*' { 'Yellow'; break } 'SUCESSO*' { 'Green'; break } 'DIAGNOSTICO*' { 'Cyan'; break } default { 'Red' } }
    Write-Host ''
    Write-Host '==================================================================' -ForegroundColor $cor
    Write-Host ("  RESULTADO FINAL: {0}" -f $status) -ForegroundColor $cor
    Write-Host '==================================================================' -ForegroundColor $cor
    Write-Host ("  Maquina: {0} | build {1} | perfil {2} | {3}" -f $env:COMPUTERNAME, $(if ($cv) { "$($cv.CurrentBuild).$($cv.UBR)" } else { '?' }), $(if ($KP) { $KP.Name } else { '-' }), (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    if ($steps.Count) {
        Write-Host '  Etapas:'
        foreach ($st in ($steps | Sort-Object Etapa)) {
            $c = switch -Wildcard ($st.Resultado) { '*avisos*' { 'Yellow'; break } 'OK*' { 'Green'; break } 'PASS*' { 'Green'; break } 'IGNORADO*' { 'DarkGray'; break } 'NAO NECESSARIO*' { 'DarkGray'; break } default { 'Red' } }
            Write-Host ("    {0} {1}{2}" -f ($st.Etapa + ' ').PadRight(38, '.'), $st.Resultado, $(if ($st.Detalhe) { " - $($st.Detalhe)" })) -ForegroundColor $c
        }
    }
    if ($motivos) { Write-Host $(if ($status -like 'SUCESSO*' -or $status -like 'REINICIO*') { '  Avisos:' } else { '  Motivos:' }) -ForegroundColor $cor; $motivos | ForEach-Object { Write-Host "    - $_" -ForegroundColor $cor } }
    if ($acoes)   { Write-Host '  Proximos passos:' -ForegroundColor Yellow; $acoes | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow } }
    Write-Host ("  Codigo de saida: {0} (0 = sucesso, 3010 = sucesso - falta reiniciar, 1 = falha, 2/3 = abortado)" -f $code)
    Write-Host '==================================================================' -ForegroundColor $cor
    Hist ("RESULTADO FINAL: {0} (codigo {1}){2}" -f $status, $code, $(if ($motivos) { ' | ' + ($motivos -join '; ') }))
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'ERRO: execute como Administrador.' -ForegroundColor Red; Write-FinalStatus 'FALHA (ABORTADO)' @('Sem privilegio de Administrador') @('Execute o REPARAR-E-HABILITAR.cmd e aceite o UAC') 2; exit 2 }
if (-not [Environment]::Is64BitProcess) { Write-Host 'ERRO: use o PowerShell 64-bit.' -ForegroundColor Red; Write-FinalStatus 'FALHA (ABORTADO)' @('PowerShell 32-bit') @('Use o PowerShell 64-bit') 2; exit 2 }

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Write-Host ("Maquina: {0} | {1} {2} build {3}.{4} {5}" -f $env:COMPUTERNAME, $cv.ProductName, $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR, $env:PROCESSOR_ARCHITECTURE) -ForegroundColor Cyan
. (Join-Path $PSScriptRoot 'KitDefender.ps1')
$KP = Get-KitProfile -KitRoot $KitRoot
if (-not $KP) { Write-Host "INCOMPATIVEL: nenhum perfil em Profiles\ cobre o build $($cv.CurrentBuild) ($env:PROCESSOR_ARCHITECTURE). Nada foi alterado." -ForegroundColor Red; Write-FinalStatus 'FALHA (ABORTADO)' @("Nenhum perfil cobre o build $($cv.CurrentBuild)") @('Nada foi alterado') 3; exit 3 }
Write-KitProfileBanner $KP
$data = Get-KitData $KP
if (-not $data -or -not (Test-Path $KP.ManifestPath)) { Write-FinalStatus 'FALHA (ABORTADO)' @("Perfil $($KP.Name) incompleto (manifest.csv / defender-registry.json ausentes)") @('Nada foi alterado') 3; exit 3 }

# outro antivirus instalado: o Windows mantem o Defender desligado de proposito
try {
    $other = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Where-Object { $_.displayName -notmatch 'Defender' })
    if ($other) { Write-Host ("AVISO: outro antivirus registrado ({0}) - com ele ativo o Defender fica em modo passivo/desligado." -f (($other | ForEach-Object displayName) -join ', ')) -ForegroundColor Yellow }
} catch { }

# =====================================================================  DIAGNOSTICO
Write-Host "`n========== DIAGNOSTICO (somente leitura) ==========" -ForegroundColor Cyan
[void](Set-KitPrivileges $true)
$st = Get-KitDefenderState $KP $data
[void](Set-KitPrivileges $false)
$findings = New-Object System.Collections.Generic.List[object]
function F([string]$area, [string]$item, [bool]$ok, [string]$step) { $findings.Add([pscustomobject]@{ Area = $area; Item = $item; Status = $(if ($ok) { 'OK' } else { 'FALTA' }); Etapa = $(if ($ok) { '' } else { $step }) }) }
$binMissing = @($st.FilesMissing | Where-Object { -not (Test-Path -LiteralPath (Join-Path $KP.FilesRoot $_.RelPath)) })
F 'Arquivos' ("{0} de {1} presentes{2}" -f $st.FilesPresent, $st.FilesTotal, $(if ($st.FilesMissing.Count) { " ($($st.FilesMissing.Count) ausentes)" })) ($st.FilesMissing.Count -eq 0) 'A'
F 'Registro' ("chaves ausentes: {0} | valores ausentes: {1}{2}" -f $st.RegKeysMissing.Count, $st.RegValuesMissing, $(if ($st.RegValuesManaged) { " | administrados pelo Defender: $($st.RegValuesManaged)" })) ($st.RegKeysMissing.Count -eq 0 -and $st.RegValuesMissing -eq 0) 'A'
foreach ($s in $st.Services) { F 'Servico' ("{0} no registro (Start={1})" -f $s.Name, $(if ($null -ne $s.Start) { $s.Start } else { '-' })) $s.RegOk 'A'; if ($s.RegOk -and $s.Start -eq 4) { F 'Servico' "$($s.Name) nao desativado" $false 'B' } }
foreach ($g in $st.Svchost) { F 'Servico' "Svchost\$($g.Group) contem $($g.Service)" $g.Ok 'A' }
F 'WMI' 'classes MSFT_Mp* (root\Microsoft\Windows\Defender)' $st.WmiClass 'A'
F 'Tarefas' ("{0} de {1} tarefas agendadas" -f @($st.Tasks | Where-Object Ok).Count, $st.Tasks.Count) (-not ($st.Tasks | Where-Object { -not $_.Ok })) 'A'
F 'Catalogos' ("{0} de {1} catalogos de assinatura" -f @($st.Catalogs | Where-Object Ok).Count, $st.Catalogs.Count) (-not ($st.Catalogs | Where-Object { -not $_.Ok })) 'A'
F 'Politicas' ('Policies\Microsoft\Windows Defender ausente' + $(if ($st.Policies) { " ($(($st.Policies | Measure-Object Values -Sum).Sum) valor(es) presentes)" })) (-not $st.Policies) 'B'
F 'Politicas' ('valores Disable*=1 na chave do produto ausentes' + $(if ($st.DisableValues) { ' (' + (($st.DisableValues | ForEach-Object Name) -join ', ') + ')' })) (-not $st.DisableValues) 'B'
F 'Politicas' 'EnableSmartScreen = 0 ausente' (-not ($null -ne $st.SmartScreenPolicy -and $st.SmartScreenPolicy -eq 0)) 'B'
F 'Politicas' 'Attachments\ScanWithAntiVirus = 3 (anexos/downloads verificados)' ($null -eq $st.AttachScan -or $st.AttachScan -eq 3) 'B'
F 'App' 'Seguranca do Windows sem marca de remocao (Deprovisioned/EndOfLife)' (-not $st.AppBlocked) 'B'
F 'App' 'Seguranca do Windows registrado para o usuario atual' $st.AppRegistered 'B'
F 'App' 'icone da bandeja habilitado na inicializacao (StartupApproved)' (-not $st.StartupDisabled) 'B'
$wdI = $st.Services | Where-Object Name -eq 'WinDefend'
$scmPending = @($st.Services | Where-Object { $_.RegOk -and -not $_.InScm })
if ($wdI.InScm) { F 'Protecao' "servico WinDefend em execucao (estado: $($wdI.State))" ($wdI.State -eq 'Running') 'B'; F 'Protecao' 'Defender registrado na Central de Seguranca' $st.WscRegistered 'B' }
$findings | Format-Table Area, Item, Status, Etapa -AutoSize | Out-String -Width 200 | Write-Host

$need = @{ A = [bool]($findings | Where-Object Etapa -eq 'A'); B = [bool]($findings | Where-Object Etapa -eq 'B') }
# assinaturas antigas tambem pedem a etapa B (atualizacao), mesmo com tudo presente
$sigAge = $null
if ($wdI.InScm -and $st.WmiClass) { try { $sigAge = (Get-CimInstance -Namespace 'root\Microsoft\Windows\Defender' -ClassName MSFT_MpComputerStatus -ErrorAction Stop).AntivirusSignatureAge } catch { } }
if ($null -ne $sigAge -and $sigAge -gt 7 -and -not $NoUpdate) { $need.B = $true; Write-Host "Assinaturas com $sigAge dia(s): a etapa B vai atualiza-las." -ForegroundColor Yellow }
if ($Force) { $need.A = $true; $need.B = $true }
if ($NoEnable) { $need.B = $false }
if (-not ($KP.Features.Files -or $KP.Features.Registry)) { $need.A = $false }
if (-not $KP.Features.Enable) { $need.B = $false }

Write-Host '========== PLANO ==========' -ForegroundColor Cyan
Write-Host ("A) Restaurar componentes (arquivos/registro) .. {0}" -f $(if ($need.A) { 'EXECUTAR' } else { 'nao necessario' }))
Write-Host ("B) Remover bloqueios e ligar a protecao ....... {0}" -f $(if ($need.B) { 'EXECUTAR' } elseif ($NoEnable) { 'ignorado (-NoEnable)' } else { 'nao necessario' }))
Write-Host  "C) Verificacao final .......................... sempre (somente leitura)"
Write-Host  "D) Limpeza final ............................. sempre (exceto -CheckOnly)"
if ($need.A -and $binMissing) {
    Write-Host ("`nATENCAO: {0} binario(s) ausentes nesta maquina tambem NAO estao em Profiles\{1}\Files (ex.: {2})." -f $binMissing.Count, $KP.Name, $binMissing[0].RelPath) -ForegroundColor Yellow
    Write-Host '         O kit esta incompleto: copie de novo a pasta Profiles\ inteira (os binarios fazem parte do kit).' -ForegroundColor Yellow
}
Hist ("Repair-And-Enable diagnostico: A={0} B={1} (CheckOnly={2} Force={3} NoEnable={4})" -f $need.A, $need.B, [bool]$CheckOnly, [bool]$Force, [bool]$NoEnable)

if ($CheckOnly) {
    Write-Host "`n-CheckOnly: nada foi alterado." -ForegroundColor Yellow
    $pend = @($findings | Where-Object { $_.Status -ne 'OK' })
    Write-FinalStatus 'DIAGNOSTICO (nada alterado)' @($pend | ForEach-Object { "$($_.Area): $($_.Item) [$($_.Status)]" }) @($(if ($pend) { 'Rode sem -CheckOnly para corrigir' })) 0
    exit 0
}

# =====================================================================  EXECUCAO
$changed = $false
if ($need.A) {
    Write-Host "`n========== A) Restore-Defender ==========" -ForegroundColor Cyan
    & .\Restore-Defender.ps1
    $rc = $LASTEXITCODE
    if ($rc -ge 2) {
        Write-Host "Restore-Defender abortou (codigo ${rc}). Nada mais sera feito." -ForegroundColor Red
        Step 'A) Restaurar componentes' 'ABORTADO' "codigo $rc"
        Write-FinalStatus 'FALHA (ABORTADO)' @("Restore-Defender abortou com codigo $rc (sistema incompativel, perfil incompleto ou sem permissao)") @('Veja a secao A) acima no log') $rc
        exit $rc
    }
    if ($rc -eq 1) { Write-Host 'Restore-Defender terminou com erros - veja o log acima.' -ForegroundColor Yellow; Step 'A) Restaurar componentes' 'ERRO' 'veja a secao A) no log' }
    else { Step 'A) Restaurar componentes' 'OK' }
    $changed = $true
} else { Step 'A) Restaurar componentes' 'NAO NECESSARIO' }
if ($need.B) {
    Write-Host "`n========== B) Enable-Defender ==========" -ForegroundColor Cyan
    & .\Enable-Defender.ps1 -NoUpdate:$NoUpdate
    if ($LASTEXITCODE -eq 0) { Step 'B) Remover bloqueios / ligar' 'OK' } else { Step 'B) Remover bloqueios / ligar' 'ERRO' "codigo $LASTEXITCODE - veja a secao B) no log" }
    $changed = $true
} else { Step 'B) Remover bloqueios / ligar' $(if ($NoEnable) { 'IGNORADO (-NoEnable)' } else { 'NAO NECESSARIO' }) }
if (-not $changed) { Write-Host "`nNenhuma correcao necessaria - o Defender ja esta restaurado." -ForegroundColor Green }

Write-Host "`n========== C) Verify-Defender ==========" -ForegroundColor Cyan
& .\Verify-Defender.ps1 -Functional:$Functional
$vrc = $LASTEXITCODE
Write-Host "`n========== D) Limpeza final ==========" -ForegroundColor Cyan
Invoke-KitHousekeeping -KitRoot $KitRoot
Hist ("Repair-And-Enable concluido: A={0} B={1} verify_exit={2}" -f $need.A, $need.B, $vrc)

# ---- consolidacao do resultado
$vLog = Get-ChildItem (Join-Path $KitRoot 'Logs') -Filter 'Verify-*.log' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $runStart } | Sort-Object LastWriteTime | Select-Object -Last 1
$vOverall = $null; $vProblems = @()
if ($vLog) {
    $vt = Get-Content $vLog.FullName -Encoding UTF8
    $m = $vt | Select-String -Pattern '^Overall \.+ (PASS \(com avisos\)|PASS|FAIL)' | Select-Object -Last 1
    if ($m) { $vOverall = $m.Matches[0].Groups[1].Value.Trim() }
    $vProblems = @($vt | Where-Object { $_ -match '^\s*\[(FAIL|WARN)\]' } | ForEach-Object { $_.Trim() })
}
if (-not $vOverall) { $vOverall = $(if ($vrc -eq 0) { 'PASS' } else { 'FAIL' }) }
Step 'C) Verificacao final' $vOverall $(if ($vLog) { $vLog.Name })

$erros = @($steps | Where-Object { $_.Resultado -match '^(ERRO|ABORTADO)' })
# servicos recriados pelo registro so entram no SCM no boot: enquanto isso, as falhas de "servico/antivirus" sao so reinicio pendente
$stillPending = @($data.Services | Where-Object { $i = Get-SvcStartInfo $_; ($null -ne $i.Reg) -and -not $i.InScm })
$reboot = [bool]$stillPending
$motivos = @(); $acoes = @()
$motivos += @($erros | ForEach-Object { "$($_.Etapa): $($_.Resultado) $($_.Detalhe)".Trim() })
$motivos += $vProblems
$vFails = @($vProblems | Where-Object { $_ -match '^\[FAIL\]' })
$onlyPending = $reboot -and -not ($vFails | Where-Object { $_ -notmatch '^\[FAIL\] (Service (registration|start|config)|Antivirus|WMI)' })
if (-not $erros -and $onlyPending) {
    $status = 'REINICIO NECESSARIO'; $code = 3010
    $motivos = @('Componentes restaurados e bloqueios removidos; os servicos/drivers do Defender foram recriados no registro e o Windows so os carrega apos reiniciar') + @($motivos | Where-Object { $_ -notmatch '^\[FAIL\] (Service|Antivirus|WMI)' })
    $acoes += 'REINICIE o Windows e execute o REPARAR-E-HABILITAR.cmd de novo (2a passagem: inicia a protecao, atualiza as assinaturas e verifica)'
} elseif ($erros -or $vOverall -eq 'FAIL' -or $vrc -ne 0) {
    $status = 'FALHA'; $code = 1
    if ($reboot) { $acoes += 'Reinicie o Windows e execute o REPARAR-E-HABILITAR.cmd de novo' }
    $acoes += 'Se persistir, envie o log desta execucao para analise'
} elseif ($vOverall -like '*avisos*') { $status = 'SUCESSO COM AVISOS'; $code = 0 }
else { $status = 'SUCESSO'; $code = 0 }
Write-FinalStatus $status $motivos $acoes $code
exit $code
