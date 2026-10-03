#Requires -Version 5.1
<#
.SYNOPSIS
  Etapa A do kit: restaura os COMPONENTES do Microsoft Defender removidos por debloat (Windows 10 2004-22H2 x64).

.DESCRIPTION
  Fonte: Profiles\<perfil>\ (binarios validados por SHA256 + registro extraido da imagem original).
  - Arquivos: restaura apenas o que esta AUSENTE (nunca sobrescreve); aplica dono/ACL de arquivo protegido do Windows.
  - Pastas de dados (ProgramData\Microsoft\Windows Defender ...): cria as ausentes com a ACL do manifesto.
  - Registro: cria apenas chaves/valores AUSENTES (servicos WinDefend/WdFilter/WdBoot/WdNisDrv/WdNisSvc/wscsvc/
    SecurityHealthService, COM, eventos, firewall, Run...), com o dono/ACL originais nas chaves criadas.
  - Svchost: acrescenta wscsvc ao grupo LocalServiceNetworkRestricted se faltar (preserva o resto).
  - Catalogos de assinatura, classes WMI (mofcomp) e tarefas agendadas: registra os ausentes.
  - NAO remove politicas nem liga a protecao: isso e a etapa B (Enable-Defender.ps1).
  - Backup\<timestamp>\ registra tudo que foi criado (usado por Rollback-Defender.ps1). Idempotente.

.PARAMETER Group
  Grupos a restaurar (padrao 1-7): 1 antivirus  2 WMI/PowerShell  3 menu de contexto  4 Central de Seguranca
  5 SecurityHealthService/bandeja  6 app Seguranca do Windows  7 SmartScreen/AMSI
.PARAMETER IncludeOptional  Inclui o grupo 9 (modelos ADMX do Defender).
.PARAMETER WhatIf           Mostra o que seria feito, sem alterar o sistema.

.EXAMPLE
  .\Restore-Defender.ps1 -WhatIf
  .\Restore-Defender.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [int[]]$Group = @(1, 2, 3, 4, 5, 6, 7),
    [switch]$IncludeOptional,
    [switch]$ForceMof,
    [string]$KitRoot = (Split-Path $PSScriptRoot -Parent)
)
$ErrorActionPreference = 'Continue'   # nativos (reg/sc/mofcomp) escrevem em stderr; erros tratados com try/catch
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir = Join-Path $KitRoot 'Logs'; New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Log = Join-Path $LogDir "Restore-$ts.log"
$History = Join-Path $LogDir 'Repair-History.log'
$DryRun = [bool]$WhatIfPreference
$WhatIfPreference = $false   # o modo simulacao e tratado por $DryRun; o log e o backup da propria execucao precisam ser gravados

function L([string]$m, [string]$c = 'Gray') {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Add-Content -Path $Log -Value $line -Encoding UTF8
    Write-Host $line -ForegroundColor $c
}
function Hist([string]$m) { "[{0}] {1}" -f (Get-Date -Format 's'), $m | Out-File -FilePath $History -Append -Encoding UTF8 }

# ------------------------------------------------------------------ pre-requisitos
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'ERRO: execute como Administrador.' -ForegroundColor Red; exit 2 }
if (-not [Environment]::Is64BitProcess) { Write-Host 'ERRO: use o PowerShell 64-bit.' -ForegroundColor Red; exit 2 }

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
L ("Restore-Defender | {0} {1} build {2}.{3} {4} | UI {5} | Modo: {6}" -f $cv.ProductName, $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR, $env:PROCESSOR_ARCHITECTURE, (Get-UICulture).Name, $(if ($DryRun) { 'WHATIF (sem alteracoes)' } else { 'EXECUCAO' })) 'Cyan'

. (Join-Path $PSScriptRoot 'KitDefender.ps1')
$KP = Get-KitProfile -KitRoot $KitRoot
if (-not $KP) { L "INCOMPATIVEL: nenhum perfil em $KitRoot\Profiles cobre o build $($cv.CurrentBuild) ($env:PROCESSOR_ARCHITECTURE). Abortando." 'Red'; exit 3 }
Write-KitProfileBanner $KP
if (-not ($KP.Features.Files -or $KP.Features.Registry)) { L "Perfil $($KP.Name) nao suporta restauracao (somente diagnostico). Nada alterado." 'Yellow'; exit 0 }
$data = Get-KitData $KP
if (-not $data) { L "ERRO: $($KP.RegistryData) nao encontrado." 'Red'; exit 4 }
if (-not (Test-Path $KP.ManifestPath)) { L "ERRO: manifest.csv nao encontrado em $($KP.ManifestPath)" 'Red'; exit 4 }
$groups = @($Group); if ($IncludeOptional) { $groups += 9 }
$manifest = @(Import-Csv $KP.ManifestPath | Where-Object { $groups -contains [int]$_.Group })
$langOk = Test-KitLanguage $KP
L ("Grupos selecionados: {0} ({1} arquivos, {2} chaves de registro) | idioma {3} instalado: {4}" -f ($groups -join ','), $manifest.Count, @($data.Keys | Where-Object { $groups -contains [int]$_.Group }).Count, $KP.Language, $langOk)

if (-not (Set-KitPrivileges $true)) { L 'ERRO: nao foi possivel ativar SeRestorePrivilege (o processo esta mesmo elevado?).' 'Red'; exit 2 }

# ------------------------------------------------------------------ backup (registro do que for criado)
$Backup = Join-Path $KitRoot "Backup\$ts"
$i = 1; while (Test-Path $Backup) { $Backup = Join-Path $KitRoot "Backup\$ts-$i"; $i++ }
New-Item -ItemType Directory -Path $Backup -Force | Out-Null
L "Backup: $Backup"
$createdFiles = Join-Path $Backup 'created-files.txt'
$createdDirs = Join-Path $Backup 'created-dirs.txt'
$createdReg = Join-Path $Backup 'created-registry.txt'
$changes = Join-Path $Backup 'changes.txt'
Hist "Restore-Defender iniciado ($(if ($DryRun) {'WhatIf'} else {'execucao'})) grupos $($groups -join ','). Backup: $Backup"
$errors = 0; $needReboot = $false

# cria a pasta e os niveis ausentes (registrando cada um para o rollback); devolve $true se criou algo
function New-KitDirectory([string]$Path, [string]$Sddl) {
    $chain = @(); $p = $Path
    while ($p -and -not (Test-Path -LiteralPath $p)) { $chain = , $p + $chain; $p = Split-Path $p -Parent }
    foreach ($d in $chain) {
        [KitFile]::CreateDirectory($d)
        Add-Content $createdDirs $d -Encoding UTF8
    }
    if ($chain.Count -and $Sddl) { [KitFile]::SetSddl($Path, $Sddl) }
    return [bool]$chain.Count
}

# ------------------------------------------------------------------ pastas de dados com ACL propria
$dirNew = 0
foreach ($d in @($data.Directories | Where-Object { $groups -contains [int]$_.Group })) {
    $path = Resolve-KitRel $d.RelPath
    if (Test-Path -LiteralPath $path) { continue }
    if ($DryRun) { L "WHATIF DIR  $($d.RelPath) : seria criada$(if ($d.Sddl) { ' (ACL do manifesto)' })" 'Yellow'; $dirNew++; continue }
    try { if (New-KitDirectory $path $d.Sddl) { $dirNew++; L "NEW   DIR  $($d.RelPath)$(if ($d.Sddl) { ' (ACL do manifesto aplicada)' })" 'Cyan' } }
    catch { L "ERRO  DIR  $($d.RelPath) : $($_.Exception.Message)" 'Red'; $errors++ }
}

# ------------------------------------------------------------------ arquivos
$created = 0; $kept = 0; $skipped = 0
foreach ($m in $manifest) {
    $src = Join-Path $KP.FilesRoot $m.RelPath
    $dest = Resolve-KitRel $m.RelPath
    $tag = "G$($m.Group) $($m.RelPath)"
    if ($m.Required -eq 'Language' -and -not $langOk) { $skipped++; continue }
    if (Test-Path -LiteralPath $dest) {
        $h = (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if ($h -ne $m.SHA256) { L ("KEEP  $tag : ja presente, versao {0} (difere do kit {1}) - preservado, NAO sobrescrito" -f (Get-Item -LiteralPath $dest).VersionInfo.FileVersion, $m.Version) 'Green' }
        $kept++; continue
    }
    if (-not (Test-Path -LiteralPath $src)) { L "ERRO  $tag : ausente no kit (pasta Profiles\ incompleta - copie o kit inteiro de novo)" 'Red'; $errors++; continue }
    if ((Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash -ne $m.SHA256) { L "ERRO  $tag : hash do arquivo do kit nao confere com o manifest.csv" 'Red'; $errors++; continue }
    if ($DryRun) { Add-Content -Path $Log -Value "WHATIF $tag : seria restaurado (v$($m.Version))" -Encoding UTF8; $created++; continue }   # lista completa so no arquivo de log
    try {
        [void](New-KitDirectory (Split-Path $dest -Parent) $null)
        [KitFile]::CopyNew($src, $dest)
        Add-Content -Path $createdFiles -Value $dest -Encoding UTF8
        if ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ne $m.SHA256) { throw 'hash apos a copia nao confere' }
        # arquivos de programa: dono TrustedInstaller + ACL de arquivo protegido; dados em ProgramData herdam a ACL da pasta
        if ($m.RelPath -notlike 'ProgramData\*') { [KitFile]::SetSddl($dest, $KitWrpFileSddl) }
        L "NEW   $tag (v$($m.Version))" 'Cyan'; $created++
        if ($dest -like '*.sys') { $needReboot = $true }
    } catch { L "ERRO  $tag : $($_.Exception.Message)" 'Red'; $errors++ }
}
L ("ARQUIVOS: {0}={1} | ja presentes={2} | ignorados (idioma)={3}" -f $(if ($DryRun) { 'a restaurar' } else { 'restaurados' }), $created, $kept, $skipped) $(if ($created) { 'Cyan' } else { 'Green' })

# ------------------------------------------------------------------ registro (aditivo)
# Regras: cria somente chaves/valores AUSENTES; nunca altera valor existente; chave criada recebe dono/ACL da imagem.
# Excecao documentada: a arvore do produto (SOFTWARE\Microsoft\Windows Defender) que JA existe e teve a ACL afrouxada
# pelo debloat volta a ACL original (Administradores: somente leitura) - a ACL anterior fica em changes.txt.
$rs = @{ keys = 0; values = 0; kept = 0; diff = 0; acl = 0; managed = 0 }
$defRunning = Test-KitDefenderRunning   # com o Defender rodando, ele administra (e protege) as proprias chaves - ver KitDefender.ps1
if ($KP.Features.Registry) {
    $entries = @($data.Keys | Where-Object { $groups -contains [int]$_.Group } | Sort-Object { (Convert-KitRegPath $_).Split('\').Count })
    foreach ($k in $entries) {
        $sub = Convert-KitRegPath $k
        try {
            $exists = [KitReg]::KeyExists($sub)
            if (-not $exists) {
                if ($DryRun) { $rs.keys++; $rs.values += @($k.Values).Count; continue }
                foreach ($c in [KitReg]::CreateKeyChain($sub)) { Add-Content $createdReg "KEY  HKLM\$c" -Encoding UTF8; $rs.keys++ }
                if ($k.Sddl) { [KitReg]::SetSddl($sub, $k.Sddl) }
                if ($k.Kind -eq 'service' -or $sub -match '^SYSTEM\\CurrentControlSet\\Services\\[^\\]+$') { $needReboot = $true }
            } elseif ($k.Sddl -and -not $defRunning -and $sub -match '^SOFTWARE\\Microsoft\\Windows Defender(\\|$)') {
                $cur = [KitReg]::GetSddl($sub)
                if ((Get-KitDaclKey $cur) -ne (Get-KitDaclKey $k.Sddl)) {
                    if ($DryRun) { $rs.acl++ }
                    else { Add-Content $changes ("ACL  HKLM\{0}|{1}" -f $sub, $cur) -Encoding UTF8; [KitReg]::SetSddl($sub, $k.Sddl); $rs.acl++ }
                }
            }
            foreach ($v in @($k.Values)) {
                $name = [string]$v.Name; $bytes = Get-KitValueBytes $v
                if ($exists -and [KitReg]::ValueExists($sub, $name)) {
                    $t = 0; $curB = [KitReg]::GetValue($sub, $name, [ref]$t)
                    if ($t -ne [int]$v.Type -or [Convert]::ToBase64String($curB) -ne [Convert]::ToBase64String($bytes)) { $rs.diff++; L "KEEP  REG HKLM\$sub [$name] : valor existente difere do da imagem - preservado, NAO alterado" 'DarkYellow' } else { $rs.kept++ }
                    continue
                }
                if ($exists -and $defRunning -and $sub -match $KitDefenderOwnedRx) { $rs.managed++; continue }
                if ($DryRun) { $rs.values++; continue }
                [KitReg]::SetValue($sub, $name, [int]$v.Type, $bytes)
                Add-Content $createdReg ("VAL  HKLM\{0}|{1}" -f $sub, $name) -Encoding UTF8; $rs.values++
            }
        } catch { L "ERRO  REG HKLM\$sub : $($_.Exception.Message)" 'Red'; $errors++ }
    }
    L ("REGISTRO: {0}: {1} chaves, {2} valores | ja presentes e iguais: {3} | existentes diferentes (preservados): {4} | ACL original reaplicada: {5} | administrados pelo Defender em execucao (nao recriados): {6}" -f $(if ($DryRun) { 'a criar' } else { 'criados' }), $rs.keys, $rs.values, $rs.kept, $rs.diff, $rs.acl, $rs.managed) $(if ($rs.keys -or $rs.values) { 'Cyan' } else { 'Green' })

    # ---- grupo svchost
    $shKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
    foreach ($g in @($data.SvchostGroups)) {
        $cur = @((Get-ItemProperty $shKey -Name $g.Group -ErrorAction SilentlyContinue).($g.Group)) | Where-Object { $_ }
        if ($cur | Where-Object { $_ -ieq $g.Service }) { continue }
        if ($DryRun) { L "WHATIF REG Svchost\$($g.Group): $($g.Service) seria adicionado" 'Yellow'; continue }
        try {
            $cur -join "`n" | Out-File (Join-Path $Backup "svchost-$($g.Group)-before.txt") -Encoding UTF8
            Set-ItemProperty -Path $shKey -Name $g.Group -Value ([string[]](@($cur) + $g.Service)) -Type MultiString -ErrorAction Stop
            Add-Content $changes ("SVCHOST {0}|{1}" -f $g.Group, $g.Service) -Encoding UTF8
            L "REG   Svchost\$($g.Group): $($g.Service) adicionado (demais entradas preservadas)" 'Cyan'; $needReboot = $true
        } catch { L "ERRO  Svchost\$($g.Group): $($_.Exception.Message)" 'Red'; $errors++ }
    }
}

# ------------------------------------------------------------------ catalogos de assinatura
$catNew = 0
$catRoot = Join-Path $env:SystemRoot 'System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
foreach ($c in @(Get-ChildItem $KP.CatalogsRoot -Filter *.cat -ErrorAction SilentlyContinue)) {
    if (Test-Path -LiteralPath (Join-Path $catRoot $c.Name)) { continue }
    if ($DryRun) { $catNew++; continue }
    try { [KitCat]::Add($c.FullName); Add-Content $changes "CATALOG $($c.Name)" -Encoding UTF8; $catNew++ }
    catch { L "AVISO catalogo $($c.Name): $($_.Exception.Message)" 'Yellow' }
}
L ("CATALOGOS: {0} {1}" -f $catNew, $(if ($DryRun) { 'a registrar' } else { 'registrados' })) $(if ($catNew) { 'Cyan' } else { 'Green' })

# ------------------------------------------------------------------ WMI (classes MSFT_Mp*, SecurityCenter2...)
$wmiOk = [bool](Get-CimClass -Namespace 'root\Microsoft\Windows\Defender' -ClassName 'MSFT_MpComputerStatus' -ErrorAction SilentlyContinue)
if ($ForceMof -or -not $wmiOk -or $created -gt 0) {
    $mofcomp = Join-Path $env:SystemRoot 'System32\wbem\mofcomp.exe'
    foreach ($mf in @($data.Mof | Where-Object { $groups -contains [int]$_.Group } | Sort-Object { $_.RelPath -like '*.mfl' })) {
        $path = Resolve-KitRel $mf.RelPath
        if ($mf.RelPath -like '*.mfl' -and -not $langOk) { continue }
        if (-not (Test-Path -LiteralPath $path)) { if (-not $DryRun) { L "AVISO MOF $($mf.RelPath): arquivo ausente - nao compilado" 'Yellow' }; continue }
        if ($DryRun) { L "WHATIF MOF $($mf.RelPath) seria compilado (mofcomp)" 'Yellow'; continue }
        $o = & $mofcomp $path 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { L "MOF   $($mf.RelPath): compilado" 'Cyan'; Add-Content $changes "MOF $($mf.RelPath)" -Encoding UTF8 }
        else { L ("ERRO  MOF $($mf.RelPath): mofcomp codigo $LASTEXITCODE - " + (($o -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -Last 2) -join ' ')) 'Red'; $errors++ }
    }
} else { L 'WMI: classes do Defender ja registradas - mofcomp nao necessario' 'Green' }

# ------------------------------------------------------------------ tarefas agendadas
foreach ($t in @($data.Tasks | Where-Object { $groups -contains [int]$_.Group })) {
    if (Get-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction SilentlyContinue) { continue }
    $xml = Join-Path $KP.TasksRoot $t.File
    if (-not (Test-Path -LiteralPath $xml)) { L "ERRO  tarefa $($t.TaskName): $xml ausente" 'Red'; $errors++; continue }
    if ($DryRun) { L "WHATIF tarefa '$($t.TaskPath)$($t.TaskName)' seria registrada" 'Yellow'; continue }
    try {
        Register-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -Xml (Get-Content -LiteralPath $xml -Raw) -ErrorAction Stop | Out-Null
        Add-Content $changes ("TASK {0}{1}" -f $t.TaskPath, $t.TaskName) -Encoding UTF8
        L "TASK  '$($t.TaskPath)$($t.TaskName)' registrada" 'Cyan'
    } catch { L "ERRO  tarefa $($t.TaskName): $($_.Exception.Message)" 'Red'; $errors++ }
}

[void](Set-KitPrivileges $false)

# ------------------------------------------------------------------ resumo
L ''
L ("RESUMO: arquivos={0} pastas={1} chaves={2} valores={3} catalogos={4} erros={5}" -f $created, $dirNew, $rs.keys, $rs.values, $catNew, $errors) 'Cyan'
if ($needReboot -and -not $DryRun) { L 'REINICIALIZACAO NECESSARIA: servicos/drivers do Defender foram recriados no registro; o Windows so os carrega no boot.' 'Yellow' }
else { L 'Reinicializacao: nao necessaria por esta etapa.' }
Hist ("Restore-Defender concluido: arquivos={0} chaves={1} valores={2} erros={3} reboot={4}" -f $created, $rs.keys, $rs.values, $errors, $needReboot)
$madeChanges = (-not $DryRun) -and ($created -gt 0 -or $dirNew -gt 0 -or $rs.keys -gt 0 -or $rs.values -gt 0 -or $rs.acl -gt 0 -or (Test-Path $changes))
if ($madeChanges) { Copy-Item $Log $Backup -ErrorAction SilentlyContinue }
else { Remove-Item -LiteralPath $Backup -Recurse -Force -ErrorAction SilentlyContinue; L 'Backup desta execucao descartado (nenhuma alteracao feita).' }
if ($errors) { exit 1 } else { exit 0 }
