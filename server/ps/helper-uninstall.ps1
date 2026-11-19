# Адамант: удаление помощника администратора. Запускается с правами администратора:
#  - из программы (кнопка «Удалить помощника»): helper-uninstall.ps1 -Out <файл.json>;
#  - при удалении программы: защищённая копия %ProgramFiles%\Adamant\Helper\helper-uninstall.ps1.
# Убирает задания \Adamant\Adamant Helper и \Adamant\Adamant Helper Security, папку %ProgramFiles%\Adamant\Helper
# и %ProgramData%\Adamant\helper. Прежние значения для отката исправлений (%ProgramData%\Adamant\undo) не трогает.
# Что было до установки (папка в Program Files и её права, папка заданий) - восстанавливает по state.json.
param([ValidatePattern('^$|\.json$')][string]$Out = '')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch {}

$Trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$PF = [Environment]::GetEnvironmentVariable('ProgramW6432')
if (-not $PF) { $PF = $env:ProgramFiles }
$ProgParent = Join-Path $PF 'Adamant'
$Prog = Join-Path $ProgParent 'Helper'
$Base = Join-Path $env:ProgramData 'Adamant'
$Data = Join-Path $Base 'helper'
$Tasks = @('Adamant Helper', 'Adamant Helper Security')

function Info([string]$p) {
  $d = New-Object IO.DirectoryInfo $p
  if ($d.Exists) { return $d }
  $f = New-Object IO.FileInfo $p
  if ($f.Exists) { return $f }
  return $null
}
function Owner-Ok([string]$p) {
  try { $it = Info $p; return ($it -and -not ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $Trusted -contains $it.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner).GetOwner([Security.Principal.SecurityIdentifier]).Value) } catch { return $false }
}
# Ссылки удаляются как ссылки, внутрь них не заходим.
function Remove-Tree([string]$p) {
  $it = Info $p
  if (-not $it) { return }
  if ($it -is [IO.FileInfo]) { $it.Attributes = [IO.FileAttributes]::Normal; $it.Delete(); return }
  if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) { [IO.Directory]::Delete($p, $false); return }
  foreach ($c in $it.GetFileSystemInfos()) {
    if ($c -is [IO.DirectoryInfo]) { Remove-Tree $c.FullName } else { $c.Attributes = [IO.FileAttributes]::Normal; $c.Delete() }
  }
  [IO.Directory]::Delete($p, $false)
}
function Is-Empty([string]$p) { $d = New-Object IO.DirectoryInfo $p; return ($d.Exists -and -not @($d.GetFileSystemInfos()).Count) }

$result = [ordered]@{ ok = $false; removed = @(); kept = @(); warnings = @() }
try {
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Нужны права администратора' }

  # Прежнее состояние - только из папки, созданной администратором.
  $before = $null
  $sf = Join-Path $Data 'state.json'
  if ((Owner-Ok $Data) -and (Owner-Ok $sf)) {
    try { $s = [IO.File]::ReadAllText($sf) | ConvertFrom-Json; if ($s.format -eq 'adamant-helper-state') { $before = $s.before } } catch {}
  }

  # 1. Задания.
  try {
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $folder = $null
    try { $folder = $svc.GetFolder('\Adamant') } catch {}
    if ($folder) {
      foreach ($n in $Tasks) {
        try { $t = $folder.GetTask($n) } catch { continue }
        try { [void]$t.Stop(0) } catch {}
        $folder.DeleteTask($n, 0)
        $result.removed += "задание \Adamant\$n"
      }
      # Папку заданий убираем, если её создал помощник (или про неё ничего не известно) и в ней больше ничего нет.
      $mine = -not ($before -and $before.taskFolderExisted)
      if ($mine -and -not @($folder.GetTasks(1)).Count -and -not @($folder.GetFolders(0)).Count) {
        $svc.GetFolder('\').DeleteFolder('Adamant', 0)
        $result.removed += 'папка заданий \Adamant'
      }
    }
  } catch { $result.warnings += ('Планировщик заданий: ' + $_.Exception.Message) }

  # 2. Program Files.
  if (Info $Prog) { Remove-Tree $Prog; $result.removed += $Prog }
  if (Info $ProgParent) {
    if ($before -and $before.programParentSddl) {
      try {
        $sd = New-Object Security.AccessControl.DirectorySecurity
        $sd.SetSecurityDescriptorSddlForm([string]$before.programParentSddl)
        [IO.Directory]::SetAccessControl($ProgParent, $sd)
        $result.kept += "$ProgParent (права восстановлены)"
      } catch { $result.warnings += ('Не удалось вернуть прежние права папки: ' + $_.Exception.Message) }
    } elseif (-not ($before -and $before.programParentExisted) -and (Is-Empty $ProgParent)) {
      [IO.Directory]::Delete($ProgParent, $false)
      $result.removed += $ProgParent
    }
  }

  # 3. ProgramData: только папка помощника. Папку, созданную не администратором, не трогаем.
  if (Info $Data) {
    if (Owner-Ok $Data) { Remove-Tree $Data; $result.removed += $Data }
    else { $result.warnings += "Папку $Data создал не администратор - она оставлена, удалите её вручную." }
  }
  if ((Owner-Ok $Base) -and $before -and -not $before.baseExisted -and (Is-Empty $Base)) {
    [IO.Directory]::Delete($Base, $false)
    $result.removed += $Base
  }
  $result.ok = $true
} catch {
  $result.error = $_.Exception.Message
}
$json = $result | ConvertTo-Json -Depth 4 -Compress
if ($Out) { [IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding $false)) } else { [Console]::Out.Write($json) }
if (-not $result.ok) { exit 1 }
