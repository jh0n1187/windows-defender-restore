#Requires -Version 5.1
<#
.SYNOPSIS
  Autoteste (elevado) das rotinas privilegiadas do kit, SEM tocar em nada do Defender nem do Windows:
  usa apenas a chave temporaria HKLM\SOFTWARE\RestoreDefenderSelfTest e uma pasta temporaria em %TEMP%,
  ambas apagadas ao final. Em seguida mostra o diagnostico (-CheckOnly) e a simulacao da etapa A (-WhatIf).
  Uso: TESTAR-SEM-ALTERAR.cmd (grava Logs\SelfTest-<data>.log).
#>
[CmdletBinding()]
param([string]$KitRoot = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
. (Join-Path $PSScriptRoot 'KitDefender.ps1')
$script:bad = 0
function T([string]$name, [scriptblock]$test) {
    try { $r = & $test; if ($r -eq $true) { Write-Host "[PASS] $name" -ForegroundColor Green } else { Write-Host "[FAIL] $name -> $r" -ForegroundColor Red; $script:bad++ } }
    catch { Write-Host "[FAIL] $name -> $($_.Exception.Message)" -ForegroundColor Red; $script:bad++ }
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'ERRO: execute como Administrador (TESTAR-SEM-ALTERAR.cmd).' -ForegroundColor Red; exit 2 }

Write-Host '========== 1) ROTINAS PRIVILEGIADAS (chave e pasta temporarias) ==========' -ForegroundColor Cyan
T 'Privilegios SeRestore/SeBackup ativados' { Set-KitPrivileges $true }
$k = 'SOFTWARE\RestoreDefenderSelfTest'; $ti = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$lock = "O:${ti}G:${ti}D:P(A;CI;GA;;;${ti})(A;CI;GR;;;SY)(A;CI;GR;;;BA)(A;CI;GR;;;BU)"   # igual a WRP_REGKEY_DEFAULT: Administrador so le
if ([KitReg]::KeyExists($k)) { [KitReg]::DeleteKey($k, $true) }
T 'Registro: criar cadeia de chaves' { $c = [KitReg]::CreateKeyChain("$k\A\B"); $c.Count -eq 3 -and [KitReg]::KeyExists("$k\A\B") }
T 'Registro: aplicar dono TrustedInstaller + ACL somente leitura' { [KitReg]::SetSddl("$k\A", $lock); [KitReg]::GetSddl("$k\A") -like "O:${ti}*D:P*" }
T 'Registro: escrita normal de Administrador e negada na chave protegida' { try { New-ItemProperty "HKLM:\$k\A" -Name x -Value 1 -ErrorAction Stop | Out-Null; 'escrita permitida (ACL nao aplicada)' } catch { $true } }
T 'Registro: criar subchave sob chave protegida (modo restauracao)' { ([KitReg]::CreateKeyChain("$k\A\C")).Count -eq 1 }
T 'Registro: gravar/ler REG_SZ, REG_DWORD, REG_MULTI_SZ, REG_BINARY em chave protegida' {
    [KitReg]::SetValue("$k\A", '', 1, [Text.Encoding]::Unicode.GetBytes("padrao`0"))
    [KitReg]::SetValue("$k\A", 'dw', 4, [BitConverter]::GetBytes([uint32]3))
    [KitReg]::SetValue("$k\A", 'ms', 7, [Text.Encoding]::Unicode.GetBytes("a`0b`0`0"))
    [KitReg]::SetValue("$k\A", 'bin', 3, [byte[]](1, 2, 3))
    $t = 0; $b = [KitReg]::GetValue("$k\A", 'dw', [ref]$t)
    [KitReg]::ValueExists("$k\A", '') -and [KitReg]::ValueExists("$k\A", 'ms') -and -not [KitReg]::ValueExists("$k\A", 'nao') -and $t -eq 4 -and [BitConverter]::ToUInt32($b, 0) -eq 3
}
T 'Registro: apagar valor e chaves (rollback)' { [KitReg]::DeleteValue("$k\A", 'dw'); [KitReg]::DeleteKey("$k\A\C", $false); [KitReg]::DeleteKey($k, $true); -not [KitReg]::KeyExists($k) }

$d = Join-Path $env:TEMP ('kit-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$src = Join-Path $env:SystemRoot 'System32\drivers\etc\services'
T 'Arquivos: criar pasta e copiar (modo restauracao)' { [KitFile]::CreateDirectory($d); [KitFile]::CreateDirectory("$d\sub"); [KitFile]::CopyNew($src, "$d\sub\f.bin"); (Get-FileHash "$d\sub\f.bin").Hash -eq (Get-FileHash $src).Hash }
T 'Arquivos: nunca sobrescreve (CREATE_NEW)' { try { [KitFile]::CopyNew($src, "$d\sub\f.bin"); 'sobrescreveu' } catch { $true } }
T 'Arquivos: dono TrustedInstaller + ACL de arquivo protegido' { [KitFile]::SetSddl("$d\sub\f.bin", $KitWrpFileSddl); (Get-Acl "$d\sub\f.bin").Owner -match 'TrustedInstaller' }
T 'Arquivos: criar em pasta protegida (dono TrustedInstaller, Administrador so leitura)' {
    [KitFile]::SetSddl("$d\sub", "O:${ti}D:P(A;OICI;FA;;;${ti})(A;OICI;0x1200a9;;;BA)(A;OICI;0x1200a9;;;SY)")
    [KitFile]::CopyNew($src, "$d\sub\g.bin"); [KitFile]::CreateDirectory("$d\sub\h"); (Test-Path "$d\sub\g.bin") -and (Test-Path "$d\sub\h")
}
T 'Arquivos: liberar e remover (rollback)' {
    foreach ($p in "$d\sub\h", "$d\sub\g.bin", "$d\sub\f.bin", "$d\sub") { [KitFile]::SetSddl($p, 'O:BAD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)') }
    [IO.Directory]::Delete($d, $true); -not (Test-Path $d)
}
$KP = Get-KitProfile -KitRoot $KitRoot
T 'Perfil e dados carregados' { $script:data = Get-KitData $KP; [bool]$KP -and $script:data.Keys.Count -gt 100 }
T 'Leitura de estado com privilegio (chaves protegidas)' { $s = Get-KitDefenderState $KP $script:data; $s.FilesTotal -gt 100 }
[void](Set-KitPrivileges $false)
Write-Host ("Rotinas privilegiadas: {0}" -f $(if ($script:bad) { "$($script:bad) FALHA(S)" } else { 'todas OK' })) -ForegroundColor $(if ($script:bad) { 'Red' } else { 'Green' })

Write-Host "`n========== 2) DIAGNOSTICO (Repair-And-Enable -CheckOnly) ==========" -ForegroundColor Cyan
& .\Repair-And-Enable.ps1 -CheckOnly
Write-Host "`n========== 3) SIMULACAO DA ETAPA A (Restore-Defender -WhatIf) ==========" -ForegroundColor Cyan
& .\Restore-Defender.ps1 -WhatIf   # (a lista completa de arquivos fica no Logs\Restore-*.log)
Write-Host "`n========== 4) SIMULACAO DA ETAPA B (Enable-Defender -WhatIf) ==========" -ForegroundColor Cyan
& .\Enable-Defender.ps1 -WhatIf
Write-Host "`nNADA FOI ALTERADO NESTA MAQUINA." -ForegroundColor Green
if ($script:bad) { exit 1 } else { exit 0 }
