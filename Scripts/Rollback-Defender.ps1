#Requires -Version 5.1
<#
.SYNOPSIS
  Desfaz UMA execucao do kit usando a pasta de backup dela (Backup\<timestamp> da etapa A ou Backup\Enable-<timestamp> da etapa B).

.DESCRIPTION
  Etapa A (Restore-Defender):
    - tarefas agendadas, catalogos e entrada do svchost registrados pelo kit: removidos;
    - registro: remove SOMENTE as chaves/valores de created-registry.txt (criados pelo kit), em ordem inversa;
      ACLs reaplicadas pelo kit voltam ao valor anterior (changes.txt);
    - arquivos: MOVE (nao apaga) os de created-files.txt para <backup>\rolled-back\, somente se o hash ainda confere
      com o manifest; pastas criadas pelo kit sao removidas se ficarem vazias.
    - As classes WMI compiladas (mofcomp) nao sao removidas.
  Etapa B (Enable-Defender):
    - reimporta as politicas/marcas de app exportadas (.reg), recria os valores removidos, devolve Start dos servicos
      e remove a entrada Active Setup.
  Com o Defender em execucao, o proprio Defender protege seus arquivos e chaves: reinicie em Modo de Seguranca ou
  desfaca antes do primeiro reinicio. Sempre pede confirmacao (use -WhatIf para simular).

.EXAMPLE
  .\Rollback-Defender.ps1 -BackupFolder 'C:\Restore-Defender\Backup\20261001-153000' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$BackupFolder,
    [string]$KitRoot = (Split-Path $PSScriptRoot -Parent)
)
$ErrorActionPreference = 'Continue'
if (-not (Test-Path $BackupFolder)) { Write-Host "Backup nao encontrado: $BackupFolder" -ForegroundColor Red; exit 1 }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'ERRO: execute como Administrador.' -ForegroundColor Red; exit 2 }
$hist = Join-Path $KitRoot 'Logs\Repair-History.log'
. (Join-Path $PSScriptRoot 'KitDefender.ps1')
$KP = Get-KitProfile -KitRoot $KitRoot
$manifest = @{}
if ($KP -and (Test-Path $KP.ManifestPath)) { Import-Csv $KP.ManifestPath | ForEach-Object { $manifest[(Resolve-KitRel $_.RelPath).ToLower()] = $_.SHA256 } }
if ((Get-SvcStartInfo 'WinDefend').State -eq 'Running') { Write-Host 'AVISO: o Defender esta em execucao e protege seus proprios arquivos/chaves - parte do rollback pode falhar (ver ajuda).' -ForegroundColor Yellow }
if (-not (Set-KitPrivileges $true)) { Write-Host 'ERRO: nao foi possivel ativar SeRestorePrivilege.' -ForegroundColor Red; exit 2 }
$errors = 0
function Sub([string]$hklmPath) { $hklmPath -replace '^HKLM\\', '' }
$changes = @(); $cf = Join-Path $BackupFolder 'changes.txt'; if (Test-Path $cf) { $changes = @(Get-Content $cf -Encoding UTF8 | Where-Object { $_ }) }

foreach ($line in $changes) {
    $kind, $rest = $line -split ' ', 2
    try {
        switch ($kind) {
            'TASK' {
                $tp = (Split-Path $rest -Parent).TrimEnd('\') + '\'; $tn = Split-Path $rest -Leaf
                if ($PSCmdlet.ShouldProcess($rest, 'Remover tarefa agendada criada pelo kit')) { Unregister-ScheduledTask -TaskPath $tp -TaskName $tn -Confirm:$false -ErrorAction Stop; Write-Host "tarefa removida: $rest" }
            }
            'CATALOG' { if ($PSCmdlet.ShouldProcess($rest, 'Remover catalogo registrado pelo kit')) { [KitCat]::Remove($rest); Write-Host "catalogo removido: $rest" } }
            'SVCHOST' {
                $g, $s = $rest -split '\|', 2; $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
                $cur = @((Get-ItemProperty $key -Name $g -ErrorAction SilentlyContinue).$g)
                if (($cur | Where-Object { $_ -ieq $s }) -and $PSCmdlet.ShouldProcess("Svchost\$g", "Remover $s")) { Set-ItemProperty $key -Name $g -Value ([string[]]@($cur | Where-Object { $_ -and $_ -ine $s })) -Type MultiString; Write-Host "Svchost\${g}: $s removido" }
            }
            'ACL' { $p, $sddl = $rest -split '\|', 2; if ($PSCmdlet.ShouldProcess($p, 'Restaurar ACL anterior')) { [KitReg]::SetSddl((Sub $p), $sddl); Write-Host "ACL anterior restaurada: $p" } }
            'POLICYKEY' { $p, $f = $rest -split '\|', 2; if ($PSCmdlet.ShouldProcess($p, "Reimportar $f")) { & reg.exe import (Join-Path $BackupFolder $f) 2>&1 | Out-Null; if ($LASTEXITCODE) { throw "reg import falhou ($f)" }; Write-Host "politica reimportada: $p" } }
            'APPXKEY' { $p, $f = $rest -split '\|', 2; if ($PSCmdlet.ShouldProcess($p, "Reimportar $f")) { & reg.exe import (Join-Path $BackupFolder $f) 2>&1 | Out-Null; if ($LASTEXITCODE) { throw "reg import falhou ($f)" }; Write-Host "marca do app reimportada: $p" } }
            'POLICYVAL' {
                $p, $n, $t, $v = $rest -split '\|', 4
                if ($PSCmdlet.ShouldProcess("$p\$n", "Recriar valor = $v")) { [void][KitReg]::CreateKeyChain((Sub $p)); [KitReg]::SetValue((Sub $p), $n, 4, [BitConverter]::GetBytes([uint32]$v)); Write-Host "valor recriado: $p\$n = $v" }
            }
            'SETVAL' { $p, $n, $oldV, $newV = $rest -split '\|', 4; if ($PSCmdlet.ShouldProcess("$p\$n", "Voltar a $oldV")) { [KitReg]::SetValue((Sub $p), $n, 4, [BitConverter]::GetBytes([uint32]$oldV)); Write-Host "valor restaurado: $p\$n = $oldV" } }
            'SETBIN' { $p, $n, $hex = $rest -split '\|', 3; if ($PSCmdlet.ShouldProcess("$p\$n", 'Restaurar valor binario anterior')) { $bb = [byte[]]::new($hex.Length / 2); for ($bi = 0; $bi -lt $bb.Length; $bi++) { $bb[$bi] = [Convert]::ToByte($hex.Substring($bi * 2, 2), 16) }; [KitReg]::SetValue((Sub $p), $n, 3, $bb); Write-Host "valor restaurado: $p\$n" } }
            'SVCSTART' { $s, $old, $new = $rest -split '\|', 3; if ($PSCmdlet.ShouldProcess($s, "Start $new -> $old")) { [KitReg]::SetValue("SYSTEM\CurrentControlSet\Services\$s", 'Start', 4, [BitConverter]::GetBytes([uint32]$old)); Write-Host "servico ${s}: Start = $old" } }
            'ACTIVESETUP' { if ([KitReg]::KeyExists((Sub $rest)) -and $PSCmdlet.ShouldProcess($rest, 'Remover entrada Active Setup')) { [KitReg]::DeleteKey((Sub $rest), $true); Write-Host "Active Setup removido" } }
            default { }   # MOF / APPXREG: informativos
        }
    } catch { Write-Host "ERRO ($line): $($_.Exception.Message)" -ForegroundColor Red; $errors++ }
}

# ---- registro criado pelo kit (ordem inversa: valores e chaves mais profundas primeiro)
$rl = Join-Path $BackupFolder 'created-registry.txt'
if (Test-Path $rl) {
    $lines = @(Get-Content $rl -Encoding UTF8 | Where-Object { $_ }); [array]::Reverse($lines)
    $rk = 0; $rv = 0; $skip = 0
    if ($PSCmdlet.ShouldProcess("$($lines.Count) chaves/valores de registro criados pelo kit", 'Remover')) {
        foreach ($l in $lines) {
            try {
                if ($l -match '^VAL\s+HKLM\\(.+)\|(.*)$') { if ([KitReg]::KeyExists($Matches[1])) { [KitReg]::DeleteValue($Matches[1], $Matches[2]); $rv++ } }
                elseif ($l -match '^KEY\s+HKLM\\(.+)$') { if ([KitReg]::KeyExists($Matches[1])) { [KitReg]::DeleteKey($Matches[1], $false); $rk++ } }
            } catch { $skip++ }   # chave com subchaves criadas depois (pelo proprio Defender) ou protegida: mantida
        }
        Write-Host ("registro: {0} chave(s) e {1} valor(es) removidos; {2} mantidos (em uso/protegidos/com conteudo novo)" -f $rk, $rv, $skip)
    }
}

# ---- arquivos criados pelo kit: mover para <backup>\rolled-back
$fl = Join-Path $BackupFolder 'created-files.txt'
if (Test-Path $fl) {
    $dstRoot = Join-Path $BackupFolder 'rolled-back'; $mv = 0
    foreach ($f in (Get-Content $fl -Encoding UTF8 | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if ($manifest[$f.ToLower()] -ne $h) { Write-Host "mantido (hash difere do kit - nao e mais o arquivo que o kit criou): $f" -ForegroundColor Yellow; continue }
        if (-not $PSCmdlet.ShouldProcess($f, 'Mover para rolled-back')) { continue }
        try {
            $dst = Join-Path $dstRoot ($f -replace '^[A-Za-z]:\\', '')
            New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null
            [KitFile]::SetSddl($f, 'O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)')   # o kit deixou o arquivo como "protegido"; libera para mover
            Move-Item -LiteralPath $f -Destination $dst -Force -ErrorAction Stop; $mv++
        } catch { Write-Host "ERRO ao mover ${f}: $($_.Exception.Message)" -ForegroundColor Red; $errors++ }
    }
    Write-Host "arquivos movidos para ${dstRoot}: $mv"
}
$dl = Join-Path $BackupFolder 'created-dirs.txt'
if (Test-Path $dl) {
    $dirs = @(Get-Content $dl -Encoding UTF8 | Where-Object { $_ } | Sort-Object { $_.Length } -Descending)
    foreach ($d in $dirs) {
        if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue) -and $PSCmdlet.ShouldProcess($d, 'Remover pasta vazia criada pelo kit')) {
            try { [KitFile]::SetSddl($d, 'O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)'); Remove-Item -LiteralPath $d -Force -ErrorAction Stop } catch { Write-Host "pasta mantida: $d ($($_.Exception.Message))" -ForegroundColor Yellow }
        }
    }
}
[void](Set-KitPrivileges $false)
"[{0}] Rollback-Defender executado para {1} (erros={2})" -f (Get-Date -Format 's'), $BackupFolder, $errors | Out-File $hist -Append -Encoding UTF8
Write-Host 'Rollback concluido. Reinicie o Windows.' -ForegroundColor Cyan
if ($errors) { exit 1 } else { exit 0 }
