# KitDefender.ps1 - biblioteca comum do kit Restore-Defender (dot-source: . "$PSScriptRoot\KitDefender.ps1")
#
# Perfil por versao do Windows em <KitRoot>\Profiles\<Nome>\:
#   profile.json                      MinBuild/MaxBuild/Arch/Features
#   Files\manifest.csv + binarios     Group,Component,Arch,RelPath,Version,Size,SHA256,Required
#                                     RelPath e relativo a unidade do sistema (Windows\..., Program Files\..., ProgramData\...)
#   Registry\defender-registry.json   Services, SvchostGroups, Mof, Directories, Tasks, Keys (extraidos da imagem original)
#   Tasks\*.xml                       tarefas agendadas (do <taskScheduler> do manifesto do componente)
#   Catalogs\*.cat                    catalogos de assinatura dos pacotes do Defender
#
# Grupos (manifest.csv / Keys[].Group):
#   1 antivirus (servico, drivers, motor, definicoes-base)   2 gerenciamento (WMI, PowerShell, MDM)   3 menu de contexto
#   4 Central de Seguranca (wscsvc)   5 SecurityHealthService + icone da bandeja   6 app Seguranca do Windows
#   7 SmartScreen + AMSI   9 opcional (modelos ADMX)

function Get-KitProfile {
    param([Parameter(Mandatory = $true)][string]$KitRoot, [string]$Name)
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$cv.CurrentBuild; $arch = $env:PROCESSOR_ARCHITECTURE
    foreach ($d in Get-ChildItem (Join-Path $KitRoot 'Profiles') -Directory -ErrorAction SilentlyContinue) {
        $pj = Join-Path $d.FullName 'profile.json'
        if (-not (Test-Path $pj)) { continue }
        $p = Get-Content $pj -Raw -Encoding UTF8 | ConvertFrom-Json
        $match = if ($Name) { $p.Name -ieq $Name } else { ($build -ge [int]$p.MinBuild) -and ($build -le [int]$p.MaxBuild) -and (@($p.Arch) -contains $arch) }
        if ($match) {
            return [pscustomobject]@{
                Name = $p.Name; Description = $p.Description; Path = $d.FullName; MinBuild = [int]$p.MinBuild; MaxBuild = [int]$p.MaxBuild
                Build = $build; UBR = $cv.UBR; Arch = $arch; Language = $p.Language; Features = $p.Features; Note = $p.Note
                ManifestPath = Join-Path $d.FullName 'Files\manifest.csv'; FilesRoot = Join-Path $d.FullName 'Files'
                RegistryData = Join-Path $d.FullName 'Registry\defender-registry.json'
                TasksRoot = Join-Path $d.FullName 'Tasks'; CatalogsRoot = Join-Path $d.FullName 'Catalogs'
            }
        }
    }
    return $null
}

function Write-KitProfileBanner($KitProf) {
    if (-not $KitProf) { return }
    $on = @(); $off = @()
    foreach ($n in 'Files', 'Registry', 'Enable') { if ($KitProf.Features.$n) { $on += $n } else { $off += $n } }
    Write-Host ("Perfil: {0} (builds {1}-{2}) | build atual {3}.{4} {5}" -f $KitProf.Name, $KitProf.MinBuild, $KitProf.MaxBuild, $KitProf.Build, $KitProf.UBR, $KitProf.Arch) -ForegroundColor Cyan
    Write-Host ("  Recursos ativos: {0}" -f ($on -join ', ')) -ForegroundColor Cyan
    if ($off) { Write-Host ("  Somente diagnostico (nao suportado neste perfil): {0}" -f ($off -join ', ')) -ForegroundColor DarkYellow }
    if ($KitProf.Note) { Write-Host "  Obs.: $($KitProf.Note)" -ForegroundColor DarkYellow }
}

function Get-KitData($KitProf) {
    if (-not (Test-Path $KitProf.RegistryData)) { return $null }
    Get-Content $KitProf.RegistryData -Raw -Encoding UTF8 | ConvertFrom-Json
}

# RelPath do perfil -> caminho real nesta maquina
function Resolve-KitRel([string]$Rel) {
    if ($Rel -match '^Windows\\(.*)$') { return (Join-Path $env:SystemRoot $Matches[1]) }
    if ($Rel -match '^Program Files \(x86\)\\(.*)$') { return (Join-Path ${env:ProgramFiles(x86)} $Matches[1]) }
    if ($Rel -match '^Program Files\\(.*)$') { return (Join-Path $env:ProgramFiles $Matches[1]) }
    if ($Rel -match '^ProgramData\\(.*)$') { return (Join-Path $env:ProgramData $Matches[1]) }
    return (Join-Path "$env:SystemDrive\" $Rel)
}

# arquivo de recurso de idioma so e restaurado se o idioma do perfil estiver instalado
function Test-KitLanguage($KitProf) { Test-Path (Join-Path $env:SystemRoot ("System32\{0}" -f $KitProf.Language)) }

# chave do perfil (Hive + Path do hive offline) -> subchave de HKLM
function Convert-KitRegPath($Key) {
    if ($Key.Hive -eq 'SYSTEM') { return ('SYSTEM\' + ($Key.Path -replace '^ControlSet001\\', 'CurrentControlSet\')) }
    return ('SOFTWARE\' + $Key.Path)
}

# Os hives da imagem guardam caminhos absolutos com a letra X: -> unidade real do sistema
function Convert-KitDrive([string]$s) { [regex]::Replace($s, '(?<![A-Za-z])X:\\', { $env:SystemDrive + '\' }) }

# valor do perfil -> bytes crus para RegSetValueEx
function Get-KitValueBytes($v) {
    if ($null -ne $v.Hex) {
        $h = [string]$v.Hex; $b = [byte[]]::new($h.Length / 2)
        for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16) }
        return , $b
    }
    switch ([int]$v.Type) {
        { $_ -in 1, 2 } { return , [Text.Encoding]::Unicode.GetBytes((Convert-KitDrive ([string]$v.Data)) + "`0") }
        7 { $items = @($v.Data | ForEach-Object { Convert-KitDrive ([string]$_) }); return , [Text.Encoding]::Unicode.GetBytes((($items -join "`0") + "`0`0")) }
        4 { return , [BitConverter]::GetBytes([uint32]$v.Data) }
        11 { return , [BitConverter]::GetBytes([uint64]$v.Data) }
        default { return , [byte[]]::new(0) }
    }
}

# Estado de inicializacao de um servico: registro (Start) E configuracao carregada no SCM (o SCM so rele o registro no boot)
function Get-SvcStartInfo {
    param([Parameter(Mandatory = $true)][string]$Name)
    $reg = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -ErrorAction SilentlyContinue).Start
    $w = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $w) { $w = Get-CimInstance Win32_SystemDriver -Filter "Name='$Name'" -ErrorAction SilentlyContinue }
    [pscustomobject]@{ Name = $Name; Reg = $reg; Scm = $(if ($w) { [string]$w.StartMode }); State = $(if ($w) { [string]$w.State }); InScm = [bool]$w
                       Disabled = ($reg -eq 4) -or ($w -and $w.StartMode -eq 'Disabled') }
}

# MpCmdRun.exe da plataforma mais nova (ProgramData\...\Platform\<versao>) ou, na falta, o da imagem (Program Files)
function Get-KitMpCmdRun {
    $plat = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    $p = Get-ChildItem $plat -Directory -ErrorAction SilentlyContinue | Sort-Object { try { [version]($_.Name -replace '-.*$', '') } catch { [version]'0.0' } } -Descending |
        ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($p) { return $p }
    $p = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path $p) { return $p }
    return $null
}

# Limpeza final: descarta backups de execucoes que nao alteraram nada e mantem os N logs mais recentes de cada tipo
function Invoke-KitHousekeeping {
    param([Parameter(Mandatory = $true)][string]$KitRoot, [int]$KeepLogs = 10)
    $removedB = 0; $keptB = 0; $removedL = 0
    foreach ($d in (Get-ChildItem (Join-Path $KitRoot 'Backup') -Directory -ErrorAction SilentlyContinue)) {
        $files = @(Get-ChildItem $d.FullName -Recurse -File -Force -ErrorAction SilentlyContinue)
        if ($files | Where-Object { $_.Name -like 'created-*.txt' -or $_.Name -eq 'changes.txt' -or $_.Extension -eq '.reg' }) { $keptB++; continue }
        Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue; $removedB++
    }
    $logRoot = Join-Path $KitRoot 'Logs'
    foreach ($pat in 'Restore-*.log', 'Enable-*.log', 'Verify-*.log', 'Repair-And-Enable-*.log') {
        foreach ($f in @(Get-ChildItem $logRoot -File -Filter $pat -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -Skip $KeepLogs)) {
            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue; $removedL++
        }
    }
    $msg = "Limpeza final: {0} backup(s) sem alteracoes removidos, {1} backup(s) de alteracoes mantidos, {2} log(s) antigos removidos (mantidos os {3} mais recentes de cada tipo)." -f $removedB, $keptB, $removedL, $KeepLogs
    Write-Host $msg -ForegroundColor Green
    "[{0}] {1}" -f (Get-Date -Format 's'), $msg | Out-File (Join-Path $logRoot 'Repair-History.log') -Append -Encoding UTF8
}

# ======================================================================  ACESSO PRIVILEGIADO (registro, arquivos, catalogos)
# As chaves do Defender (SOFTWARE\Microsoft\Windows Defender, CLSIDs do TrustedInstaller...) e algumas pastas do Windows
# (ex.: SystemResources) nao dao escrita nem ao Administrador. Em vez de tomar posse ou afrouxar ACLs, o kit liga os
# privilegios de backup/restauracao (todo Administrador elevado os possui, desligados) e abre chaves/arquivos com a opcao
# BACKUP_RESTORE. O que e criado recebe o dono/ACL ORIGINAIS da imagem; nada existente tem ACL alterada, exceto a
# arvore do produto (ver Restore-Defender.ps1). Os privilegios sao desligados ao final de cada script.
if (-not ('KitReg' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class KitPriv {
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Lo; public int Hi; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attr; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, uint len, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static bool Set(string name, bool enable) {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return false;   // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        try {
            LUID l; if (!LookupPrivilegeValue(null, name, out l)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(); tp.Count = 1; tp.Luid = l; tp.Attr = enable ? 2u : 0u;
            if (!AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
            return Marshal.GetLastWin32Error() == 0;   // 1300 = privilegio nao existe no token
        } finally { CloseHandle(tok); }
    }
}

// Registro em HKLM (visao 64-bit) com REG_OPTION_BACKUP_RESTORE
public static class KitReg {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegCreateKeyEx(UIntPtr hKey, string subKey, int reserved, string cls, uint options, uint sam, IntPtr sa, out IntPtr result, out uint disposition);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, uint options, uint sam, out IntPtr result);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegSetValueEx(IntPtr hKey, string name, int reserved, uint type, byte[] data, int len);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegQueryValueEx(IntPtr hKey, string name, IntPtr reserved, out uint type, byte[] data, ref int len);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegDeleteValue(IntPtr hKey, string name);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegEnumKeyEx(IntPtr hKey, uint index, StringBuilder name, ref int nameLen, IntPtr reserved, IntPtr cls, IntPtr clsLen, IntPtr lastWrite);
    [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr h);
    [DllImport("advapi32.dll")] static extern int RegSetKeySecurity(IntPtr h, uint info, byte[] sd);
    [DllImport("advapi32.dll")] static extern int RegGetKeySecurity(IntPtr h, uint info, byte[] sd, ref int len);
    [DllImport("ntdll.dll")] static extern int NtDeleteKey(IntPtr h);
    static readonly UIntPtr HKLM = new UIntPtr(0x80000002u);
    const uint BACKUP_RESTORE = 4, KEY_ALL_ACCESS = 0xF003F, KEY_WOW64_64KEY = 0x100;

    static IntPtr Open(string sub, out uint disposition) {
        IntPtr h;
        int rc = RegCreateKeyEx(HKLM, sub, 0, null, BACKUP_RESTORE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, IntPtr.Zero, out h, out disposition);
        if (rc != 0) throw new Win32Exception(rc);
        return h;
    }
    public static bool KeyExists(string sub) {
        IntPtr h; int rc = RegOpenKeyEx(HKLM, sub, 0, 0x20000 /* READ_CONTROL */ | KEY_WOW64_64KEY, out h);
        if (rc == 0) { RegCloseKey(h); return true; }
        return rc == 5;   // acesso negado = existe
    }
    // cria a chave e os niveis intermediarios que faltarem; devolve os caminhos criados, do mais alto ao mais profundo
    public static string[] CreateKeyChain(string sub) {
        var created = new List<string>(); string[] parts = sub.Split('\\'); string cur = "";
        for (int i = 0; i < parts.Length; i++) {
            cur = i == 0 ? parts[0] : cur + "\\" + parts[i];
            if (KeyExists(cur)) continue;
            uint d; IntPtr h = Open(cur, out d); RegCloseKey(h);
            if (d == 1) created.Add(cur);
        }
        return created.ToArray();
    }
    // leitura: acesso normal primeiro (funciona sem privilegio); so recorre ao modo backup se a ACL negar. A chave deve existir.
    static IntPtr OpenRead(string sub) {
        IntPtr h; int rc = RegOpenKeyEx(HKLM, sub, 0, 1 /* KEY_QUERY_VALUE */ | KEY_WOW64_64KEY, out h);
        if (rc == 0) return h;
        if (rc != 5) throw new Win32Exception(rc);
        uint d; return Open(sub, out d);
    }
    public static bool ValueExists(string sub, string name) {
        IntPtr h = OpenRead(sub);
        try { uint t; int len = 0; int rc = RegQueryValueEx(h, name, IntPtr.Zero, out t, null, ref len); return rc == 0 || rc == 234; } finally { RegCloseKey(h); }
    }
    public static byte[] GetValue(string sub, string name, out int type) {
        type = -1; IntPtr h = OpenRead(sub);
        try {
            uint t; int len = 0; int rc = RegQueryValueEx(h, name, IntPtr.Zero, out t, null, ref len);
            if (rc != 0 && rc != 234) return null;
            byte[] b = new byte[len]; rc = RegQueryValueEx(h, name, IntPtr.Zero, out t, b, ref len);
            if (rc != 0) return null;
            type = (int)t; if (len != b.Length) Array.Resize(ref b, len); return b;
        } finally { RegCloseKey(h); }
    }
    public static void SetValue(string sub, string name, int type, byte[] data) {
        uint d; IntPtr h = Open(sub, out d);
        try { int rc = RegSetValueEx(h, name, 0, (uint)type, data, data.Length); if (rc != 0) throw new Win32Exception(rc); } finally { RegCloseKey(h); }
    }
    public static void DeleteValue(string sub, string name) {
        uint d; IntPtr h = Open(sub, out d);
        try { int rc = RegDeleteValue(h, name); if (rc != 0 && rc != 2) throw new Win32Exception(rc); } finally { RegCloseKey(h); }
    }
    public static string[] SubKeyNames(string sub) {
        var names = new List<string>(); uint d; IntPtr h = Open(sub, out d);
        try {
            for (uint i = 0; ; i++) {
                var sb = new StringBuilder(260); int len = sb.Capacity;
                int rc = RegEnumKeyEx(h, i, sb, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (rc == 259) break;   // ERROR_NO_MORE_ITEMS
                if (rc != 0) throw new Win32Exception(rc);
                names.Add(sb.ToString());
            }
        } finally { RegCloseKey(h); }
        return names.ToArray();
    }
    // tree = true: apaga as subchaves antes, cada uma aberta em modo restauracao (RegDeleteTree abriria as subchaves
    // com acesso normal e falharia com "acesso negado" nas chaves protegidas)
    public static void DeleteKey(string sub, bool tree) {
        if (tree) foreach (string n in SubKeyNames(sub)) DeleteKey(sub + "\\" + n, true);
        uint d; IntPtr h = Open(sub, out d);
        try { int st = NtDeleteKey(h); if (st != 0) throw new Exception("NtDeleteKey falhou: 0x" + st.ToString("X8")); } finally { RegCloseKey(h); }
    }
    public static string GetSddl(string sub) {
        uint d; IntPtr h = Open(sub, out d);
        try {
            int len = 0; RegGetKeySecurity(h, 7, null, ref len);
            byte[] sd = new byte[len]; int rc = RegGetKeySecurity(h, 7, sd, ref len); if (rc != 0) throw new Win32Exception(rc);
            return new RawSecurityDescriptor(sd, 0).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
        } finally { RegCloseKey(h); }
    }
    public static void SetSddl(string sub, string sddl) {
        var raw = new RawSecurityDescriptor(sddl); byte[] sd = new byte[raw.BinaryLength]; raw.GetBinaryForm(sd, 0);
        uint info = 0;
        if (raw.Owner != null) info |= 1; if (raw.Group != null) info |= 2;
        if (raw.DiscretionaryAcl != null) info |= 4 | ((raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 ? 0x80000000u : 0x20000000u);
        uint d; IntPtr h = Open(sub, out d);
        try { int rc = RegSetKeySecurity(h, info, sd); if (rc != 0) throw new Win32Exception(rc); } finally { RegCloseKey(h); }
    }
}

// Arquivos e pastas com FILE_FLAG_BACKUP_SEMANTICS (privilegio de restauracao)
public static class KitFile {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetKernelObjectSecurity(SafeFileHandle h, uint info, byte[] sd);
    const uint BACKUP = 0x02000000, POSIX = 0x01000000;
    public static void CreateDirectory(string path) {
        using (SafeFileHandle h = CreateFile(path, 0x80000000, 7, IntPtr.Zero, 1 /* CREATE_NEW */, 0x10 | BACKUP | POSIX, IntPtr.Zero)) {
            if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
    // copia SOMENTE se o destino nao existir (CREATE_NEW)
    public static void CopyNew(string src, string dst) {
        byte[] data = File.ReadAllBytes(src);
        using (SafeFileHandle h = CreateFile(dst, 0x40000000, 0, IntPtr.Zero, 1 /* CREATE_NEW */, 0x80 | BACKUP, IntPtr.Zero)) {
            if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            using (var fs = new FileStream(h, FileAccess.Write)) { fs.Write(data, 0, data.Length); }
        }
    }
    public static void SetSddl(string path, string sddl) {
        var raw = new RawSecurityDescriptor(sddl); byte[] sd = new byte[raw.BinaryLength]; raw.GetBinaryForm(sd, 0);
        uint info = 0;
        if (raw.Owner != null) info |= 1; if (raw.Group != null) info |= 2;
        if (raw.DiscretionaryAcl != null) info |= 4 | ((raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 ? 0x80000000u : 0x20000000u);
        using (SafeFileHandle h = CreateFile(path, 0x000C0000 /* WRITE_DAC | WRITE_OWNER */, 7, IntPtr.Zero, 3 /* OPEN_EXISTING */, BACKUP, IntPtr.Zero)) {
            if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!SetKernelObjectSecurity(h, info, sd)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}

// Catalogos de assinatura (CatRoot): registra pelo servico de criptografia, como o CBS faria
public static class KitCat {
    [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminAcquireContext(out IntPtr hAdmin, ref Guid subsystem, uint flags);
    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr CryptCATAdminAddCatalog(IntPtr hAdmin, string file, string selectBaseName, uint flags);
    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CryptCATAdminRemoveCatalog(IntPtr hAdmin, string name, uint flags);
    [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hAdmin, IntPtr hCatInfo, uint flags);
    [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr hAdmin, uint flags);
    static Guid sys = new Guid("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
    public static void Add(string file) {
        IntPtr a; if (!CryptCATAdminAcquireContext(out a, ref sys, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr ci = CryptCATAdminAddCatalog(a, file, Path.GetFileName(file), 0);
            if (ci == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            CryptCATAdminReleaseCatalogContext(a, ci, 0);
        } finally { CryptCATAdminReleaseContext(a, 0); }
    }
    public static void Remove(string name) {
        IntPtr a; if (!CryptCATAdminAcquireContext(out a, ref sys, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { if (!CryptCATAdminRemoveCatalog(a, name, 0)) throw new Win32Exception(Marshal.GetLastWin32Error()); } finally { CryptCATAdminReleaseContext(a, 0); }
    }
}
'@
}

function Set-KitPrivileges([bool]$Enable) {
    $ok = [KitPriv]::Set('SeRestorePrivilege', $Enable)
    [void][KitPriv]::Set('SeBackupPrivilege', $Enable)
    [void][KitPriv]::Set('SeTakeOwnershipPrivilege', $Enable)
    return $ok
}

# ACL padrao de arquivo protegido do Windows (WRP_FILE_DEFAULT_SDDL dos manifestos): dono TrustedInstaller, demais so leitura
$KitWrpFileSddl = 'O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:P(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)'

# Com o Defender em execucao, ELE administra a propria configuracao: apaga valores de instalacao (ex.: WdBoot\SupportElamHive),
# troca caminhos para a plataforma nova e protege essas chaves (escrita = "acesso negado"). Por isso, com o WinDefend rodando,
# valor ausente em chave EXISTENTE dessas arvores nao e tratado como falta, e o kit nao tenta recria-lo nem mexer na ACL.
$KitDefenderOwnedRx = '^(SYSTEM\\CurrentControlSet\\Services\\(WinDefend|WdBoot|WdFilter|WdNisDrv|WdNisSvc)|SOFTWARE\\Microsoft\\Windows Defender)(\\|$)'
function Test-KitDefenderRunning { $s = Get-Service WinDefend -ErrorAction SilentlyContinue; return ($s -and $s.Status -eq 'Running') }

# Item de inicializacao "SecurityHealth" (icone da bandeja, que tambem dispara o SecurityHealthService) desabilitado no
# Gerenciador de Tarefas / pelo debloat: 1o byte impar em StartupApproved\Run (02/06 = habilitado, 03/07 = desabilitado)
$KitStartupApprovedKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
function Test-KitStartupDisabled {
    $b = (Get-ItemProperty "HKLM:\$KitStartupApprovedKey" -Name SecurityHealth -ErrorAction SilentlyContinue).SecurityHealth
    return [bool]($b -and $b.Length -ge 1 -and ($b[0] -band 1))
}

# normaliza a DACL de um SDDL para comparacao (o Windows reordena as ACEs e troca os flags P/AI sem mudar o efeito)
function Get-KitDaclKey([string]$Sddl) {
    if ($Sddl -notmatch 'D:([A-Z]*)((\([^)]*\))*)') { return '' }
    $prot = if ($Matches[1] -match 'P') { 'P' } else { '' }
    return $prot + ((([regex]::Matches($Matches[2], '\([^)]*\)') | ForEach-Object { $_.Value }) | Sort-Object) -join '')
}

# ======================================================================  ESTADO (somente leitura) - usado pelo diagnostico e pela verificacao
# Compara a maquina com o perfil: arquivos, chaves/valores de registro, servicos, grupo svchost, tarefas, WMI.
function Get-KitDefenderState {
    param($KitProf, $Data, [int[]]$Group = @(1, 2, 3, 4, 5, 6, 7))
    $langOk = Test-KitLanguage $KitProf
    $st = [ordered]@{}
    # arquivos
    $man = @(Import-Csv $KitProf.ManifestPath | Where-Object { $Group -contains [int]$_.Group })
    $missing = @(); $present = 0
    foreach ($m in $man) {
        if ($m.Required -eq 'Language' -and -not $langOk) { continue }
        if (Test-Path -LiteralPath (Resolve-KitRel $m.RelPath)) { $present++ } else { $missing += $m }
    }
    $st.FilesTotal = $man.Count; $st.FilesPresent = $present; $st.FilesMissing = $missing
    # registro
    $kMiss = New-Object System.Collections.Generic.List[string]; $vMiss = 0; $vOk = 0; $vManaged = 0
    $defRunning = Test-KitDefenderRunning
    foreach ($k in $Data.Keys) {
        if ($Group -notcontains [int]$k.Group) { continue }
        $sub = Convert-KitRegPath $k
        if (-not [KitReg]::KeyExists($sub)) { $kMiss.Add($sub); $vMiss += @($k.Values).Count; continue }
        $managed = $defRunning -and $sub -match $KitDefenderOwnedRx
        foreach ($v in @($k.Values)) {
            # sem privilegio de backup uma chave protegida nao pode ser lida: nao conta como ausente
            try { if ([KitReg]::ValueExists($sub, [string]$v.Name)) { $vOk++ } elseif ($managed) { $vManaged++ } else { $vMiss++ } } catch { $vOk++ }
        }
    }
    $st.RegKeysMissing = $kMiss; $st.RegValuesMissing = $vMiss; $st.RegValuesPresent = $vOk; $st.RegValuesManaged = $vManaged
    # servicos
    $st.Services = @(foreach ($s in $Data.Services) {
        $i = Get-SvcStartInfo $s
        $img = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
        $want = ($Data.Keys | Where-Object { $_.Hive -eq 'SYSTEM' -and $_.Path -ieq "ControlSet001\Services\$s" } | Select-Object -First 1).Values | Where-Object Name -eq 'Start' | Select-Object -First 1
        [pscustomobject]@{ Name = $s; RegOk = [bool]$img; Start = $i.Reg; WantStart = $(if ($want) { [int]$want.Data }); InScm = $i.InScm; State = $i.State; Disabled = $i.Disabled }
    })
    $st.Svchost = @(foreach ($g in $Data.SvchostGroups) {
        $cur = @((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost' -Name $g.Group -ErrorAction SilentlyContinue).($g.Group))
        [pscustomobject]@{ Group = $g.Group; Service = $g.Service; Ok = [bool]($cur | Where-Object { $_ -ieq $g.Service }) }
    })
    $st.Tasks = @(foreach ($t in $Data.Tasks) { [pscustomobject]@{ Name = $t.TaskName; Path = $t.TaskPath; Ok = [bool](Get-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction SilentlyContinue) } })
    $st.WmiClass = [bool](Get-CimClass -Namespace 'root\Microsoft\Windows\Defender' -ClassName 'MSFT_MpComputerStatus' -ErrorAction SilentlyContinue)
    $st.Catalogs = @(Get-ChildItem $KitProf.CatalogsRoot -Filter *.cat -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Ok = (Test-Path -LiteralPath (Join-Path $env:SystemRoot "System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\$($_.Name)")) } })
    # bloqueios (politicas / desativacao)
    $pol = @()
    foreach ($pk in @('SOFTWARE\Policies\Microsoft\Windows Defender')) {   # (WOW6432Node\Policies e a mesma chave: Policies e compartilhada)
        if (Test-Path "HKLM:\$pk") {
            $n = 0; foreach ($x in @(Get-Item "HKLM:\$pk") + @(Get-ChildItem "HKLM:\$pk" -Recurse -ErrorAction SilentlyContinue)) { $n += $x.ValueCount }
            if ($n) { $pol += [pscustomobject]@{ Key = "HKLM\$pk"; Values = $n } }
        }
    }
    $st.Policies = $pol
    $dis = @()
    $wd = 'SOFTWARE\Microsoft\Windows Defender'
    foreach ($pair in @(@($wd, 'DisableAntiSpyware'), @($wd, 'DisableAntiVirus'), @("$wd\Real-Time Protection", 'DisableRealtimeMonitoring'), @("$wd\Real-Time Protection", 'DisableBehaviorMonitoring'),
                        @("$wd\Real-Time Protection", 'DisableOnAccessProtection'), @("$wd\Real-Time Protection", 'DisableScanOnRealtimeEnable'), @("$wd\Real-Time Protection", 'DisableIOAVProtection'))) {
        if (-not [KitReg]::KeyExists($pair[0])) { continue }
        $t = 0; $b = $null; try { $b = [KitReg]::GetValue($pair[0], $pair[1], [ref]$t) } catch { }
        if ($b -and $b.Length -ge 4 -and [BitConverter]::ToUInt32($b, 0) -eq 1) { $dis += [pscustomobject]@{ Key = $pair[0]; Name = $pair[1] } }
    }
    $st.DisableValues = $dis
    # 1 = nao verificar anexos/downloads com o antivirus (ajuste de debloat); original da imagem = 3
    $st.StartupDisabled = Test-KitStartupDisabled
    $st.WscRegistered = $false
    try { $st.WscRegistered = [bool](Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Where-Object { $_.displayName -match 'Defender' }) } catch { }
    $st.AttachScan = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name ScanWithAntiVirus -ErrorAction SilentlyContinue).ScanWithAntiVirus
    $st.SmartScreenPolicy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -ErrorAction SilentlyContinue).EnableSmartScreen
    $ax = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
    $st.AppBlocked = @(@(Get-ChildItem "$ax\Deprovisioned" -ErrorAction SilentlyContinue) + @(Get-ChildItem "$ax\EndOfLife" -Recurse -ErrorAction SilentlyContinue) | Where-Object { $_.PSChildName -like 'Microsoft.Windows.SecHealthUI*' } | ForEach-Object { $_.Name -replace '^HKEY_LOCAL_MACHINE\\', '' })
    $st.AppManifest = Join-Path $env:SystemRoot 'SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\AppxManifest.xml'
    $st.AppRegistered = [bool](Get-AppxPackage -Name 'Microsoft.Windows.SecHealthUI' -ErrorAction SilentlyContinue)
    return [pscustomobject]$st
}
