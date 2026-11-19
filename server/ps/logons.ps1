# Адамант: входы в Windows для раздела «Пока вас не было». Только чтение.
#  - журнал безопасности: 4625 (неверный пароль), 4624 (вход; тип 7 - разблокировка), 4800/4801 (блокировка/разблокировка),
#    типы входа 2 (с клавиатуры), 7 (разблокировка), 10 (удалённый рабочий стол), 11 (по сохранённому паролю);
#  - журнал безопасности открывается только администратору или участнику группы «Читатели журнала событий»;
#    иначе - файл помощника с правами администратора (%ProgramData%\Adamant\helper\out\security.json), если он есть;
#  - иначе ответ {visible:false}.
# Ответ - JSON {visible, source, items:[{at, kind:'failed'|'logon'|'unlock'|'lock', user, logonType}]}.
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7})?(Z|[+-]\d\d:\d\d)$')][string]$Since,
  [ValidateRange(1, 2000)][int]$Max = 500,
  # Файл помощника с правами администратора (другой путь - только для проверки сценария).
  [string]$HelperFile = '',
  # Не читать файл помощника: сервер берёт его сам через helper.js (с проверкой доверия).
  [switch]$NoHelper
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false

function Send($o) { [Console]::Out.Write((ConvertTo-Json -InputObject $o -Depth 5 -Compress)) }
function IsoUtc([datetime]$d) { $d.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture) }

$inv = [Globalization.CultureInfo]::InvariantCulture
$sinceUtc = [DateTime]::Parse($Since, $inv, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
$sinceText = $sinceUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $inv)
$skip = '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|-|UMFD-\d+|DWM-\d+)$'

function FromSecurityLog {
  $time = "TimeCreated[@SystemTime&gt;='$sinceText']"
  $types = "Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11'"
  $xml = "<QueryList><Query Id='0' Path='Security'>" +
    "<Select Path='Security'>*[System[(EventID=4624 or EventID=4625) and $time]] and *[EventData[$types]]</Select>" +
    "<Select Path='Security'>*[System[(EventID=4800 or EventID=4801) and $time]]</Select>" +
    "</Query></QueryList>"
  $events = @()
  try {
    $events = @(Get-WinEvent -FilterXml ([xml]$xml) -MaxEvents $Max -ErrorAction Stop)
  } catch {
    $id = [string]$_.FullyQualifiedErrorId
    if ($id -like 'NoMatchingEventsFound*') { return ,@() }
    throw
  }
  $items = New-Object System.Collections.ArrayList
  foreach ($e in $events) {
    try {
      $x = [xml]$e.ToXml()
      $d = @{}
      foreach ($n in @($x.Event.EventData.Data)) { if ($n -and $n.Name) { $d[[string]$n.Name] = [string]$n.'#text' } }
      $user = [string]$d['TargetUserName']
      $lt = 0; [void][int]::TryParse([string]$d['LogonType'], [ref]$lt)
      $kind = switch ($e.Id) { 4625 { 'failed' } 4624 { if ($lt -eq 7) { 'unlock' } else { 'logon' } } 4801 { 'unlock' } 4800 { 'lock' } }
      if ($kind -ne 'failed' -and ($user -match $skip -or $user.EndsWith('$'))) { continue }
      $item = [ordered]@{ at = (IsoUtc $e.TimeCreated); kind = $kind; user = $user }
      if ($lt -gt 0) { $item.logonType = $lt }
      [void]$items.Add($item)
    } catch { }
  }
  return ,$items.ToArray()
}

function FromHelper {
  $root = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
  $file = if ($HelperFile) { $HelperFile } else { Join-Path $root 'Adamant\helper\out\security.json' }
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $null }
  if ((Get-Item -LiteralPath $file).Length -gt 4MB) { return $null }
  $j = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($null -eq $j) { return $null }
  $items = New-Object System.Collections.ArrayList
  $add = {
    param($list, [string]$forceKind)
    foreach ($x in @($list)) {
      if ($null -eq $x -or -not $x.at) { continue }
      $at = [datetime]::MinValue
      if (-not [datetime]::TryParse([string]$x.at, $inv, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at)) { continue }
      if ($at -lt $sinceUtc) { continue }
      $lt = 0; [void][int]::TryParse([string]$x.logonType, [ref]$lt)
      $kind = $forceKind
      if ($kind -eq 'logon' -and ($lt -eq 7 -or [string]$x.kind -eq 'unlock')) { $kind = 'unlock' }
      $item = [ordered]@{ at = $at.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $inv); kind = $kind; user = [string]$x.user }
      if ($lt -gt 0) { $item.logonType = $lt }
      [void]$items.Add($item)
    }
  }
  if ($j.PSObject.Properties['failed']) { & $add $j.failed 'failed' }
  if ($j.PSObject.Properties['logons']) { & $add $j.logons 'logon' }
  if ($j.PSObject.Properties['unlocks']) { & $add $j.unlocks 'unlock' }
  return ,$items.ToArray()
}

try {
  $items = FromSecurityLog
  Send ([ordered]@{ visible = $true; source = 'security'; items = @($items) })
} catch {
  $denied = $false
  $ex = $_.Exception
  while ($ex) { if ($ex -is [UnauthorizedAccessException] -or $ex.HResult -eq -2147024891) { $denied = $true }; $ex = $ex.InnerException }
  $h = $null
  if (-not $NoHelper) { try { $h = FromHelper } catch { $h = $null } }
  if ($null -ne $h) { Send ([ordered]@{ visible = $true; source = 'helper'; items = @($h) }) }
  else { Send ([ordered]@{ visible = $false; reason = $(if ($denied) { 'denied' } else { 'error' }) }) }
}
