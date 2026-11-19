# Адамант: учения - безопасная проверка, что защита действительно срабатывает.
# Сценарий НЕ меняет настройки Windows и не требует прав администратора.
# Он создаёт только свои файлы и сам их удаляет:
#   eicar - учебный файл EICAR в своей временной папке %TEMP%\Adamant-drill-<guid> (папка удаляется);
#   amsi  - дочерний PowerShell вычисляет учебную строку AMSI (строка ничего не делает);
#   cfa   - один текстовый файл Adamant-check-<guid>.txt в «Документах» (если записался - сразу удаляется).
# Учебные строки EICAR и AMSI собираются из кодов символов во время работы,
# чтобы антивирус не принял за угрозу сам этот сценарий.
#   powershell -File drill.ps1 -Drill eicar              → JSON в stdout
#   powershell -File drill.ps1 -Drill eicar -Out f.json  → JSON в файл
# Ответ: { drill, status: passed|failed|skipped|error, ms, detail, ... }
param(
  [ValidateSet('eicar', 'amsi', 'cfa')][string]$Drill = 'eicar',
  [string]$Out = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false

# Стандартная учебная строка EICAR (68 символов) и учебная строка AMSI - коды символов.
$EicarCodes = @(88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42)
$AmsiCodes = @(65,77,83,73,32,84,101,115,116,32,83,97,109,112,108,101,58,32,55,101,55,50,99,51,99,101,45,56,54,49,98,45,52,51,51,57,45,56,55,52,48,45,48,97,99,49,52,56,52,99,49,51,56,54)

# Коды ошибок Windows: «файл содержит вирус», «вирус удалён», «доступ запрещён».
$VirusHResults = @(-2147024671, -2147024670)
$AccessDenied = -2147024891

function FromCodes([int[]]$codes) { return -join ($codes | ForEach-Object { [char]$_ }) }

function Result([string]$status, $ms, [string]$detail) {
  return [ordered]@{ drill = $Drill; status = $status; ms = [int64]$ms; detail = $detail }
}

function ErrorText($e) {
  $m = [string]$e.Exception.Message
  if ($m.Length -gt 300) { $m = $m.Substring(0, 300) }
  return $m
}

# ---------- Учебный вирус EICAR ----------
function EicarDrill {
  $id = [guid]::NewGuid().ToString('N')
  $tmp = $env:TEMP
  if (-not $tmp) { $tmp = [IO.Path]::GetTempPath() }
  $dir = Join-Path $tmp ('Adamant-drill-' + $id)
  $file = Join-Path $dir 'adamant-eicar-test.com'
  $text = FromCodes $EicarCodes
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $res = $null
  try {
    [void][IO.Directory]::CreateDirectory($dir)
    $sw.Restart()
    $written = $false
    try {
      [IO.File]::WriteAllText($file, $text, [Text.Encoding]::ASCII)
      $written = $true
    } catch {
      $h = $_.Exception.HResult
      if ($_.Exception -is [UnauthorizedAccessException] -or $VirusHResults -contains $h -or $h -eq $AccessDenied) {
        $res = Result 'passed' $sw.ElapsedMilliseconds 'blocked-write'
      } else {
        $res = Result 'error' $sw.ElapsedMilliseconds (ErrorText $_)
      }
    }
    if ($written) {
      $how = $null
      while ($sw.ElapsedMilliseconds -lt 15000) {
        Start-Sleep -Milliseconds 200
        if (-not [IO.File]::Exists($file)) { $how = 'removed'; break }
        try {
          $now = [IO.File]::ReadAllText($file, [Text.Encoding]::ASCII)
          if ($now -ne $text) { $how = 'changed'; break }
        } catch { $how = 'locked'; break }
      }
      if ($how) { $res = Result 'passed' $sw.ElapsedMilliseconds $how }
      else { $res = Result 'failed' $sw.ElapsedMilliseconds 'kept' }
    }
    # Название угрозы из журнала Defender - без прав администратора может быть недоступно.
    if ($res.status -eq 'passed') {
      try {
        Start-Sleep -Milliseconds 800
        $d = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { (@($_.Resources) -join ' ') -match [regex]::Escape($id) }) | Select-Object -First 1
        if ($d) {
          $th = @(Get-MpThreat -ThreatID $d.ThreatID -ErrorAction Stop) | Select-Object -First 1
          if ($th -and $th.ThreatName) { $res.threat = [string]$th.ThreatName }
        }
      } catch {}
    }
  } finally {
    # Своя папка удаляется всегда. Если антивирус ещё держит файл - несколько попыток.
    for ($i = 0; $i -lt 15 -and [IO.Directory]::Exists($dir); $i++) {
      try { [IO.Directory]::Delete($dir, $true) } catch { Start-Sleep -Milliseconds 300 }
    }
  }
  if ($res) { $res.cleaned = -not [IO.Directory]::Exists($dir) }
  return $res
}

# ---------- Учебный вредный сценарий (AMSI) ----------
function AmsiDrill {
  $marker = 'ADAMANT-AMSI-RAN'
  $cmd = "`$s = '" + (FromCodes $AmsiCodes) + "'; [Console]::Out.Write('" + $marker + "')"
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $psi.Arguments = '-NoProfile -NonInteractive -EncodedCommand ' + $enc
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = [Diagnostics.Process]::Start($psi)
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit(20000)) {
    try { $p.Kill() } catch {}
    return Result 'error' $sw.ElapsedMilliseconds 'timeout'
  }
  $ms = $sw.ElapsedMilliseconds
  $stdout = [string]$so.Result
  $stderr = [string]$se.Result
  if ($stdout.Contains($marker)) { return Result 'failed' $ms 'ran' }
  if ($stderr -match 'ScriptContainedMaliciousContent|malicious content|вредоносн') { return Result 'passed' $ms 'blocked' }
  $tail = ($stderr -replace '\s+', ' ').Trim()
  if ($tail.Length -gt 300) { $tail = $tail.Substring(0, 300) }
  return Result 'error' $ms ('no-result: ' + $tail)
}

# ---------- Шантажист в «Документах» (контролируемый доступ к папкам) ----------
function CfaState {
  try {
    $v = (Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess
    if ($null -ne $v) { return [int]$v }
  } catch {}
  foreach ($k in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access',
                   'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access')) {
    try {
      $v = (Get-ItemProperty -LiteralPath $k -Name EnableControlledFolderAccess -ErrorAction Stop).EnableControlledFolderAccess
      if ($null -ne $v) { return [int]$v }
    } catch {}
  }
  return $null
}

function CfaDrill {
  $state = CfaState
  if ($null -eq $state) { return Result 'skipped' 0 'unknown' }
  # 0 - выключен, 1 - блокировка, 2 - только аудит, 3 - только защита диска, 4 - аудит диска.
  if ($state -eq 2 -or $state -eq 4) { return Result 'skipped' 0 'audit' }
  if ($state -ne 1) { return Result 'skipped' 0 'off' }
  $docs = [Environment]::GetFolderPath('MyDocuments')
  if (-not $docs -or -not [IO.Directory]::Exists($docs)) { return Result 'error' 0 'no-documents' }
  $file = Join-Path $docs ('Adamant-check-' + [guid]::NewGuid().ToString('N') + '.txt')
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    [IO.File]::WriteAllText($file, "Проверка программы «Адамант». Этот файл должен был удалиться сам; его можно удалить.", (New-Object Text.UTF8Encoding $true))
  } catch {
    $h = $_.Exception.HResult
    if ($_.Exception -is [UnauthorizedAccessException] -or $h -eq $AccessDenied) { return Result 'passed' $sw.ElapsedMilliseconds 'blocked' }
    return Result 'error' $sw.ElapsedMilliseconds (ErrorText $_)
  }
  $ms = $sw.ElapsedMilliseconds
  for ($i = 0; $i -lt 10 -and [IO.File]::Exists($file); $i++) {
    try { [IO.File]::Delete($file) } catch { Start-Sleep -Milliseconds 200 }
  }
  $res = Result 'failed' $ms 'written'
  $res.cleaned = -not [IO.File]::Exists($file)
  return $res
}

$res = $null
try {
  switch ($Drill) {
    'eicar' { $res = EicarDrill }
    'amsi' { $res = AmsiDrill }
    'cfa' { $res = CfaDrill }
  }
} catch {
  $res = Result 'error' 0 (ErrorText $_)
}
if (-not $res) { $res = Result 'error' 0 'no-result' }
$json = ConvertTo-Json -InputObject $res -Depth 4 -Compress
if ($Out) { [IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding $false)) } else { [Console]::Out.Write($json) }
