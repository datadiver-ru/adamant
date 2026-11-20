# Адамант: «Уничтожить данные» - то, что доступно только администраторам. Запускается с разрешением UAC
# и только по кнопке «Уничтожить данные» с отмеченной галочкой (или server/wipe.js --admin).
#
#   wipe-admin.ps1 -Out <файл.json>
#
# Удаляет:
#  - %ProgramData%\Adamant\undo - прежние значения для отката исправлений (сами исправления в Windows остаются);
#  - файлы в %ProgramData%\Adamant\helper\out и \tmp - ответы помощника администратора. Сами папки и задания
#    помощника остаются: он продолжит работать и напишет новые ответы.
# Файлы перед удалением перезаписываются случайными байтами (на SSD это не гарантия, поэтому важнее ключ данных).
# Папки, владелец которых не администраторы и не SYSTEM, и ссылки (reparse point) не трогаются:
# через них удаление с правами администратора могло бы стереть чужие файлы.
param([Parameter(Mandatory = $true)][ValidatePattern('\.json$')][string]$Out)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ADMINS = 'S-1-5-32-544'
$SYSTEM = 'S-1-5-18'
$Base = Join-Path $env:ProgramData 'Adamant'
$left = New-Object System.Collections.ArrayList
$removed = 0

function Trusted([string]$p) {
  $i = Get-Item -LiteralPath $p -Force
  if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
  return ((Get-Acl -LiteralPath $p).GetOwner([Security.Principal.SecurityIdentifier]).Value -in @($ADMINS, $SYSTEM))
}
function Overwrite([string]$f) {
  $len = (Get-Item -LiteralPath $f -Force).Length
  if ($len -le 0) { return }
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $fs = [IO.File]::Open($f, 'Open', 'Write', 'None')
  try {
    $buf = New-Object byte[] ([Math]::Min($len, 1MB))
    $done = 0
    while ($done -lt $len) {
      $n = [int][Math]::Min($buf.Length, $len - $done)
      $rng.GetBytes($buf)
      $fs.Write($buf, 0, $n)
      $done += $n
    }
    $fs.Flush($true)
  } finally { $fs.Dispose(); $rng.Dispose() }
}
# Все файлы внутри папки (без перехода по ссылкам); $removeDir - удалить и саму папку.
function Wipe-Dir([string]$dir, [bool]$removeDir) {
  if (-not (Test-Path -LiteralPath $dir)) { return }
  if (-not (Trusted $dir)) { [void]$left.Add($dir); return }
  $stack = New-Object System.Collections.Stack
  $stack.Push($dir)
  $dirs = New-Object System.Collections.ArrayList
  while ($stack.Count) {
    $d = $stack.Pop()
    [void]$dirs.Add($d)
    foreach ($e in @(Get-ChildItem -LiteralPath $d -Force)) {
      if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { [void]$left.Add($e.FullName); continue }
      if ($e.PSIsContainer) { $stack.Push($e.FullName); continue }
      try { Overwrite $e.FullName } catch { }
      try { Remove-Item -LiteralPath $e.FullName -Force; $script:removed++ } catch { [void]$left.Add($e.FullName) }
    }
  }
  # Вложенные папки - от самых глубоких; саму папку - только если просили.
  $sorted = @($dirs | Sort-Object { $_.Length } -Descending)
  foreach ($d in $sorted) {
    if ($d -eq $dir -and -not $removeDir) { continue }
    try { Remove-Item -LiteralPath $d -Force } catch { if ($d -eq $dir) { [void]$left.Add($d) } }
  }
}

try {
  if ((Test-Path -LiteralPath $Base) -and -not (Trusted $Base)) {
    [void]$left.Add($Base)
  } else {
    Wipe-Dir (Join-Path $Base 'undo') $true
    Wipe-Dir (Join-Path $Base 'helper\out') $false
    Wipe-Dir (Join-Path $Base 'helper\tmp') $false
  }
  $result = [ordered]@{ ok = ($left.Count -eq 0); removed = $removed; left = @($left) }
} catch {
  $result = [ordered]@{ ok = $false; removed = $removed; left = @($left); error = [string]$_.Exception.Message }
}
[IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Depth 4 -Compress), (New-Object Text.UTF8Encoding $false))
