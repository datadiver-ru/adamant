# Адамант: учения - безопасная проверка, что защита действительно срабатывает.
# Сценарий НЕ меняет настройки Windows и не требует прав администратора.
# Он создаёт только свои файлы и сам их удаляет:
#   eicar - учебный файл EICAR в своей временной папке %TEMP%\Adamant-drill-<guid> (папка удаляется);
#   amsi  - дочерний PowerShell получает учебную строку AMSI через стандартный ввод (строка ничего не делает);
#   cfa   - один текстовый файл Adamant-check-<guid>.txt в «Документах» (если записался - сразу удаляется).
# Учебные строки EICAR и AMSI сценарий получает от программы через стандартный ввод (server/drills.js),
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

# Учебные строки EICAR и AMSI приходят от программы через стандартный ввод (server/drills.js):
# в самом сценарии их нет ни в каком виде, и запуск не похож на «расшифровку и выполнение».
function ReadSample([int]$len) {
  try { $o = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { return $null }
  $s = [string]$o.sample
  if ($s.Length -ne $len) { return $null }
  return $s
}

# Коды ошибок Windows: «файл содержит вирус», «вирус удалён», «доступ запрещён».
$VirusHResults = @(-2147024671, -2147024670)
$AccessDenied = -2147024891

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
  $text = ReadSample 68
  if (-not $text) { return Result 'error' 0 'no-sample' }
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
  $sample = ReadSample 54
  if (-not $sample) { return Result 'error' 0 'no-sample' }
  # Учебный сценарий - обычной строкой через стандартный ввод (-Command -), без кодирования.
  $cmd = "`$s = '" + $sample + "'; [Console]::Out.Write('" + $marker + "')"
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $psi.Arguments = '-NoProfile -NonInteractive -Command -'
  $psi.RedirectStandardInput = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $sw = [Diagnostics.Stopwatch]::StartNew()
  # Без этого Windows ставит в начало ввода метку кодировки (BOM), и первая команда не узнаётся.
  try { [Console]::InputEncoding = New-Object Text.UTF8Encoding $false } catch {}
  $p = [Diagnostics.Process]::Start($psi)
  $p.StandardInput.WriteLine($cmd)
  $p.StandardInput.Close()
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
