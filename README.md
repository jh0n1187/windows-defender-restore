# Restore-Defender — kit de reparo do Microsoft Defender (Windows 10)

Kit reutilizável para restaurar o **Microsoft Defender Antivírus**, a **Central de Segurança (`wscsvc`)**, o
**`SecurityHealthService`** e o app **Segurança do Windows** em instalações do Windows 10 modificadas/"debloated" em que o
Defender foi **removido** (não apenas desativado). Mesmo método do kit Restore-Location: diagnosticar, restaurar só o que
falta, nunca sobrescrever, registrar tudo para rollback. **O kit é autossuficiente**: não depende de ISO, `install.wim`, DISM, 7-Zip nem de nenhum programa
instalado — tudo que é necessário está em `Profiles\<perfil>\`. A internet só é usada para atualizar as assinaturas
(sem ela o Defender sobe com as definições-base incluídas no kit).

> **Por que não DISM / `sfc`?** Nessas instalações o component store foi esvaziado (aqui: 43 pastas em `WinSxS` contra
> ~13.500 na imagem original) e os pacotes `Windows-Defender-*` foram apagados do CBS. `DISM /RestoreHealth` não tem o que
> reparar. A alternativa oficial é a **instalação de reparo (in-place upgrade)** com a ISO; este kit é a alternativa que
> não reinstala o Windows.

> **Binários incluídos.** `Profiles\Win10-19041\Files\` traz os 229 arquivos originais da Microsoft (Windows 10 Pro pt-BR,
> build 19041.3803) e `Catalogs\` os 32 catálogos de assinatura. Cada arquivo é conferido pelo SHA256 do `manifest.csv`
> antes de ser copiado; arquivo adulterado ou corrompido é recusado.
>
> Copie a pasta para um caminho curto (ex.: `C:\Restore-Defender`): o arquivo mais profundo do kit tem 163 caracteres
> além da raiz, e o Windows limita caminhos a 260.

---

## ▶ Como usar

1. **(Recomendado)** crie um ponto de restauração ou snapshot da VM: o reparo recria drivers de inicialização (`WdBoot`, `WdFilter`).
2. Duplo clique em **`REPARAR-E-HABILITAR.cmd`** → termina com **REINÍCIO NECESSÁRIO** (código 3010).
3. **Reinicie** o Windows.
4. Duplo clique em **`REPARAR-E-HABILITAR.cmd`** de novo → inicia a proteção, atualiza as assinaturas e verifica.

São duas passagens porque o Gerenciador de Serviços (SCM) e o kernel só carregam serviços/drivers recriados no registro
durante o boot.

| Lançador | O que faz |
|---|---|
| `REPARAR-E-HABILITAR.cmd` | diagnóstico + somente as etapas necessárias + verificação |
| `TESTAR-SEM-ALTERAR.cmd` | autoteste das rotinas privilegiadas (em chave/pasta temporárias), diagnóstico e **simulação** das etapas A e B — não altera nada |

| Etapa | Script | Executa somente se… |
|---|---|---|
| A | `Restore-Defender.ps1` | faltar arquivo, pasta de dados, chave/valor de registro, entrada do svchost, catálogo, classe WMI ou tarefa |
| B | `Enable-Defender.ps1` | houver política/bloqueio do debloat, app marcado como removido, serviço parado ou assinaturas com mais de 7 dias |
| C | `Verify-Defender.ps1` | sempre (somente leitura) |
| D | limpeza final | sempre, exceto `-CheckOnly` |

Opções (`Scripts\Repair-And-Enable.ps1`): `-CheckOnly` (só diagnóstico/plano), `-NoEnable` (não mexe em políticas nem liga
a proteção), `-NoUpdate` (sem rede), `-Functional` (teste com o arquivo EICAR), `-Force`.
O fim do log traz o bloco **RESULTADO FINAL** (SUCESSO / SUCESSO COM AVISOS / REINICIO NECESSARIO / FALHA) e o código de
saída (0, 3010, 1, 2/3). Logs em `Logs\`, histórico em `Logs\Repair-History.log`.

## 1. Diagnóstico desta máquina (Windows 10 Pro 22H2 19045.6811, pt-BR)

| Item | Situação encontrada |
|---|---|
| Pacotes CBS `Windows-Defender-*` (11) | removidos do registro do CBS e de `servicing\Packages`; payload ausente do `WinSxS` |
| Arquivos | 224 de 227 ausentes (`Program Files\Windows Defender`, drivers `Wd*.sys`, `SecurityHealth*`, `wsc*`, `smartscreen*`, app SecHealthUI…) |
| Serviços | `WinDefend`, `WdNisSvc`, `WdFilter`, `WdBoot`, `WdNisDrv`, `SecurityHealthService`, `wscsvc`: chaves inexistentes |
| Registro | 630 chaves / 991 valores ausentes (COM, AppID, WINEVT, Security Center, firewall, Run, AMSI provider…) |
| Svchost | `wscsvc` removido do grupo `LocalServiceNetworkRestricted` |
| Políticas | `Policies\Microsoft\Windows Defender` com 12 valores (`DisableAntiSpyware`, `DisableRealtimeMonitoring`…), `EnableSmartScreen = 0`, `Policies\Attachments\ScanWithAntiVirus = 1` |
| App | `Microsoft.Windows.SecHealthUI` marcado como `Deprovisioned` |
| WMI / PowerShell | namespace `root\Microsoft\Windows\Defender` sem provedor; módulo `Defender` ausente |
| Dependência extra | `winbio.dll` (importado estaticamente por `SecurityHealthService.exe`) também removido |

## 2. O que a etapa A restaura

Origem dos dados do perfil: imagem original do Windows 10 Pro pt-BR, build 19041.3803. A lista foi obtida dos **manifestos dos
componentes** da imagem (não por heurística de nomes): cada arquivo, chave, serviço, tarefa e MOF pertence a um
componente `Windows-Defender-*`, `Windows-Shield-Provider`, `Windows-SecurityHealth-SSO`, `Microsoft-Windows-SecHealthUI*`,
`Microsoft-Windows-SecurityCenter-*`, `Microsoft-Windows-SmartScreen`, `Microsoft-Antimalware-Scan-Interface` (+ `winbio.dll`).

| Grupo | Conteúdo | Arquivos |
|---|---|---|
| 1 | Antivírus: `MsMpEng.exe`, `MpSvc.dll`, `MpCmdRun.exe`, `NisSrv.exe`, drivers `WdFilter/WdBoot/WdNisDrv.sys` (+ `ELAMBKUP`), motor e definições-base | 40 |
| 2 | Gerenciamento: provedores WMI (`ProtectionManagement.dll`, MOFs), módulo PowerShell `Defender`, CSP | 32 |
| 3 | Menu de contexto "Verificar com o Microsoft Defender" (`shellext.dll`) | 4 |
| 4 | Central de Segurança: `wscsvc.dll`, `wscapi.dll`, `wscui.cpl`, broker (x64 + WOW64) | 24 |
| 5 | `SecurityHealthService.exe`, `SecurityHealthSystray.exe` (ícone da bandeja), `winbio.dll` | 16 |
| 6 | App Segurança do Windows (`SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy`) | 104 |
| 7 | SmartScreen (`smartscreen.exe`, `smartscreenps.dll`) e AMSI | 7 |
| 9 (opcional) | modelos ADMX do Defender (`-IncludeOptional`) | 2 |

Regras: arquivo existente **nunca** é sobrescrito (ex.: `amsi.dll` 19041.4355 do sistema é mantido); cada cópia é
validada por SHA256; arquivos de programa recebem dono `TrustedInstaller` e a ACL padrão de arquivo protegido; as pastas
de dados em `ProgramData\Microsoft\Windows Defender` são criadas com a ACL definida no manifesto (sem isso herdariam a
ACL permissiva de `ProgramData`).

Além dos arquivos:

| Item | Como |
|---|---|
| 679 chaves de registro (1.030 valores) lidas do hive `SOFTWARE`/`SYSTEM` da imagem | cria **somente** chaves/valores ausentes; valor existente diferente é preservado e listado; chave criada recebe o dono/ACL originais |
| ACL de `SOFTWARE\Microsoft\Windows Defender` | única exceção: como o debloat a deixou gravável por Administradores, volta à ACL original (a anterior fica em `changes.txt`) |
| `Svchost\LocalServiceNetworkRestricted` | acrescenta `wscsvc`, preservando as demais entradas |
| 32 catálogos de assinatura (`Windows-Defender-*` + os dos pacotes que cobrem os demais binários) | registrados via `CryptCATAdminAddCatalog`; **obrigatórios** para os serviços protegidos carregarem as DLLs restauradas |
| WMI | `mofcomp` de `ProtectionManagement.mof`, `wscenter.mof` e demais MOF/MFL dos componentes |
| 4 tarefas `\Microsoft\Windows\Windows Defender\` | registradas a partir do XML do manifesto |

Chaves protegidas (dono `TrustedInstaller`/`SYSTEM`) são gravadas com os privilégios de backup/restauração
(`REG_OPTION_BACKUP_RESTORE`, `FILE_FLAG_BACKUP_SEMANTICS`), sem tomar posse nem afrouxar ACLs.

## 3. O que a etapa B faz

1. Exporta e remove `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`; remove `EnableSmartScreen = 0`
   (`-KeepSmartScreenPolicy` mantém); `Policies\Attachments\ScanWithAntiVirus` volta a 3.
2. Remove `DisableAntiSpyware`/`DisableAntiVirus` e `Real-Time Protection\Disable* = 1` da chave do produto.
3. Serviço do Defender com `Start = 4` volta ao valor da imagem.
4. Reabilita o item de inicialização `SecurityHealth` (ícone da bandeja) se estiver desabilitado;
   apaga a marca `Deprovisioned`/`EndOfLife` do app, registra-o para o usuário atual e cria uma entrada **Active Setup**
   que o registra no próximo logon de cada um dos demais usuários.
5. Após o reinício: inicia `wscsvc`, `SecurityHealthService` e `WinDefend`, e atualiza as assinaturas
   (`MpCmdRun -SignatureUpdate`; se o Windows Update não responder, `-MMPC`).
   Sem internet: baixe `mpam-fe.exe` (assinaturas) e, se quiser, `updateplatform.exe` (KB4052623) do site da Microsoft,
   coloque em `Updates\` e rode de novo — só são executados se a assinatura digital for válida e da Microsoft.

A **Proteção contra Adulteração** não é alterada (fica como estiver; pode ser ligada em Segurança do Windows).

## 4. Rollback

Cada execução que altera algo grava `Backup\<timestamp>\` (etapa A) ou `Backup\Enable-<timestamp>\` (etapa B):
`created-files.txt`, `created-dirs.txt`, `created-registry.txt`, `changes.txt` e os `.reg` exportados.

```powershell
.\Scripts\Rollback-Defender.ps1 -BackupFolder C:\Restore-Defender\Backup\<timestamp> -WhatIf
.\Scripts\Rollback-Defender.ps1 -BackupFolder C:\Restore-Defender\Backup\<timestamp>
```

Arquivos são **movidos** para `<backup>\rolled-back\` (só os que o kit criou e cujo hash confere); do registro saem só as
chaves/valores que o kit criou. Com o Defender já em execução ele protege os próprios arquivos e chaves: desfaça antes do
primeiro reinício ou em Modo de Segurança.

## 5. Limitações

- **Fora do component store**: os arquivos restaurados não estão registrados no CBS/WinSxS, então as atualizações
  cumulativas do Windows não os atualizam. O antivírus em si se atualiza sozinho (assinaturas, motor e plataforma vão para
  `ProgramData\Microsoft\Windows Defender\Platform`); Central de Segurança, SecurityHealth e SmartScreen ficam na versão 19041.3636.
- **Plataforma inicial 4.18.1909.6** (a da imagem). No teste ela se atualizou sozinha minutos depois da primeira
  atualização de assinaturas; sem internet, use `Updates\updateplatform.exe` (KB4052623).
- **Fora do escopo**: Defender for Endpoint (`Sense`), Application Guard, System Guard (`SgrmBroker`, descontinuado),
  o app de aviso do SmartScreen (`Microsoft.Windows.AppRep.ChxApp`) e os ADMX do SmartScreen.
- **Idioma**: recursos somente pt-BR (em outro idioma os binários funcionam, com nomes/descrições em inglês ou ausentes).
- **Outro antivírus instalado**: o Windows mantém o Defender em modo passivo/desligado de propósito.
- Builds aceitos: 19041–19045 x64. Outras versões são recusadas sem alterar nada (é preciso um perfil próprio em `Profiles\`).

## 6. Builds testadas

| Sistema | Resultado |
|---|---|
| Windows 10 Pro 22H2 **19045.6811** x64 pt-BR (VM, debloated) | 1ª passagem sem erros → reinício → `WinDefend`, `WdFilter`, `WdNisSvc`, `wscsvc` e `SecurityHealthService` em execução; proteção em tempo real ligada; assinaturas do dia baixadas; plataforma atualizada sozinha de 4.18.1909.6 para 4.18.26080.4; Defender registrado na Central de Segurança (`0x61100`); todos os binários com assinatura válida; reexecução idempotente; verificação **PASS** sem avisos |

### O que o teste real ensinou (já incorporado ao kit)

- **Catálogos não são cosméticos.** `MsMpEng`, `wscsvc` e `SecurityHealthService` são processos protegidos (PPL) e recusam
  carregar DLL sem assinatura válida. Só com os catálogos `Windows-Defender-*` o antivírus subia, mas o
  `SecurityHealthService` encerrava ao iniciar (`winbio.dll`) e o Defender não aparecia na Central de Segurança
  (`wscisvif.dll`). O perfil agora inclui o catálogo de **cada** binário sem assinatura embutida (32 catálogos);
  cada um foi localizado na imagem original pelo hash do arquivo.
- **Ícone da bandeja desabilitado**: o debloat deixa `StartupApproved\Run\SecurityHealth` com o 1º byte ímpar
  (desabilitado). É o ícone que dispara o `SecurityHealthService` no logon; a etapa B o reabilita.
- **O Defender em execução administra as próprias chaves**: apaga valores de instalação (`WdBoot\SupportElamHive`),
  aponta CLSIDs/eventos para a plataforma nova e bloqueia escrita. O kit não trata isso como falta nem tenta "consertar".

## Estrutura

```nRestore-Defender\
  REPARAR-E-HABILITAR.cmd   lancador de 1 clique (diagnostica + executa so o necessario + verifica)
  TESTAR-SEM-ALTERAR.cmd    autoteste + diagnostico + simulacao (nao altera nada)
  Profiles\Win10-19041\
    profile.json
    Files\      manifest.csv (SHA256) + 229 binarios, na mesma arvore do destino (Windows\, Program Files\, ProgramData\)
    Registry\   defender-registry.json (679 chaves, servicos, svchost, MOF, pastas, tarefas)
    Tasks\      4 tarefas agendadas (XML)
    Catalogs\   32 catalogos de assinatura
  Scripts\  KitDefender.ps1 (biblioteca), Repair-And-Enable.ps1, Restore-Defender.ps1, Enable-Defender.ps1,
            Verify-Defender.ps1, Rollback-Defender.ps1, Test-KitPrimitives.ps1
  Updates\  (opcional, nao versionado) mpam-fe.exe, updateplatform.exe para maquinas sem internet
  Backup\  Logs\   gerados em cada maquina (nao versionados)
```n
Para levar a outra máquina, copie a pasta inteira e execute `REPARAR-E-HABILITAR.cmd`.
