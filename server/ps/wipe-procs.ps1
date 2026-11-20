# Адамант: закрыть свои процессы перед удалением папки данных («Уничтожить данные», server/wipe.js).
# Вход - JSON {"data":"<папка данных>","self":<PID вызывающего>} на стандартном вводе.
# Закрывает только процессы этой папки данных, узнавая их по командной строке:
#   - значок в трее: powershell ... tray.ps1 ... -Data "<папка>";
#   - сервер: node ... index.js --data=<папка>;
#   - окно программы: msedge/chrome --user-data-dir=<папка>\window (обычный браузер с таким профилем не запускается).
# Выход - JSON {"ok":true,"stopped":<число>}. Чужие процессы и сам вызывающий не трогаются.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
# Путь к папке данных бывает русским (Desktop\Адамант\data): вход читаем как UTF-8, иначе свои процессы не узнаются.
try { [Console]::InputEncoding = New-Object Text.UTF8Encoding $false } catch {}
try {
  $text = [Console]::In.ReadToEnd().Trim([char[]]@([char]0xFEFF, ' ', [char]13, [char]10))
  $in = $text | ConvertFrom-Json
  $data = ([string]$in.data).TrimEnd('\')
  $self = [int]$in.self
  if ($data.Length -lt 4 -or -not [IO.Path]::IsPathRooted($data)) { throw 'папка данных не указана' }
  # Путь в командной строке заканчивается кавычкой, пробелом или концом строки - не путаем data и data2.
  $end = '(?=["\s\\]|$)'
  $esc = [regex]::Escape($data)
  $tray = '(?i)tray\.ps1.*-Data\s+"?' + $esc + $end
  $server = '(?i)index\.js.*--data=' + $esc + $end
  $window = '(?i)--user-data-dir="?' + [regex]::Escape((Join-Path $data 'window')) + $end
  $stopped = 0
  # Сначала значок (иначе он перезапустит сервер), потом сервер, потом окно.
  foreach ($step in @(@{ names = @('powershell.exe'); re = $tray }, @{ names = @('node.exe'); re = $server }, @{ names = @('msedge.exe', 'chrome.exe'); re = $window })) {
    foreach ($p in @(Get-CimInstance Win32_Process | Where-Object { $step.names -contains $_.Name.ToLowerInvariant() })) {
      if ($p.ProcessId -eq $self -or -not $p.CommandLine) { continue }
      if ($p.CommandLine -notmatch $step.re) { continue }
      try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $stopped++ } catch { }
    }
  }
  [Console]::Out.Write((@{ ok = $true; stopped = $stopped } | ConvertTo-Json -Compress))
} catch {
  [Console]::Out.Write((@{ ok = $false; error = [string]$_.Exception.Message } | ConvertTo-Json -Compress))
}
