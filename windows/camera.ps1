# Адамант: один снимок с камеры по умолчанию для раздела «Пока вас не было».
# Включается отдельной настройкой (по умолчанию выключена). Запускает значок в трее (tray.ps1) в сеансе пользователя,
# когда сервер программы просит снимок после неверного пароля. Ничего никуда не отправляет.
#  - пишет только один файл: -Out, и только если это <данные>\away\photos\<32 шестнадцатеричных знака>.jpg;
#  - камера: Windows.Media.Capture.MediaCapture (WinRT) из Windows PowerShell 5.1, ожидание через AsTask;
#  - ответ - JSON {ok, path, error, detail}. Коды ошибок: bad-path, no-winrt, no-camera, blocked, busy, timeout, error.
# Запускать с -MTA: ожидание операций WinRT в потоке STA может зависнуть.
param([Parameter(Mandatory = $true)][string]$Out, [ValidateRange(3, 60)][int]$TimeoutSec = 15)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false

function Done([bool]$ok, [string]$err = '', [string]$detail = '') {
  $o = [ordered]@{ ok = $ok; path = $(if ($ok) { $Out } else { $null }); error = $(if ($ok) { $null } else { $err }) }
  if ($detail) { $o.detail = $detail.Substring(0, [Math]::Min(200, $detail.Length)) }
  [Console]::Out.Write((ConvertTo-Json -InputObject $o -Compress))
  exit 0
}

# --- куда писать: только папка away\photos данных программы, имя - номер запроса сервера
try {
  $full = [IO.Path]::GetFullPath($Out)
  $dir = [IO.Path]::GetDirectoryName($full)
  $okPath = ([IO.Path]::GetFileName($full) -cmatch '^[a-f0-9]{32}\.jpg$') -and
    ([IO.Path]::GetFileName($dir) -eq 'photos') -and
    ([IO.Path]::GetFileName([IO.Path]::GetDirectoryName($dir)) -eq 'away') -and
    [IO.Directory]::Exists($dir) -and -not [IO.File]::Exists($full)
} catch { $okPath = $false }
if (-not $okPath) { Done $false 'bad-path' }
$Out = $full

# --- запрет в параметрах конфиденциальности (только чтение реестра): камеру даже не включаем
function Denied([string]$key) {
  try { return [string](Get-ItemProperty -LiteralPath $key -Name Value -ErrorAction Stop).Value -eq 'Deny' } catch { return $false }
}
$cs = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
if ((Denied "HKLM:\$cs") -or (Denied "HKCU:\$cs") -or (Denied "HKCU:\$cs\NonPackaged")) { Done $false 'blocked' 'privacy' }

# --- WinRT из PowerShell 5.1
try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime
  $null = [Windows.Media.Capture.MediaCapture, Windows.Media.Capture, ContentType = WindowsRuntime]
  $null = [Windows.Media.Capture.MediaCaptureInitializationSettings, Windows.Media.Capture, ContentType = WindowsRuntime]
  $null = [Windows.Media.MediaProperties.ImageEncodingProperties, Windows.Media.MediaProperties, ContentType = WindowsRuntime]
  $null = [Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType = WindowsRuntime]
  $null = [Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
  $null = [Windows.Storage.Streams.DataReader, Windows.Storage.Streams, ContentType = WindowsRuntime]
  $methods = [System.WindowsRuntimeSystemExtensions].GetMethods()
  $asTaskOp = $methods | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
  $asTaskAction = $methods | Where-Object { $_.Name -eq 'AsTask' -and -not $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' } | Select-Object -First 1
  if (-not $asTaskOp -or -not $asTaskAction) { throw 'AsTask не найден' }
} catch { Done $false 'no-winrt' $_.Exception.Message }

$ms = $TimeoutSec * 1000
function Await($op, [Type]$type) {
  $task = $asTaskOp.MakeGenericMethod($type).Invoke($null, @($op))
  if (-not $task.Wait($ms)) { throw (New-Object TimeoutException) }
  return $task.Result
}
function AwaitAction($op) {
  $task = $asTaskAction.Invoke($null, @($op))
  if (-not $task.Wait($ms)) { throw (New-Object TimeoutException) }
}
# Код ошибки по HRESULT самого глубокого исключения.
function Code($err) {
  $ex = $err.Exception
  $codes = @()
  while ($ex) {
    if ($ex -is [TimeoutException]) { return 'timeout' }
    if ($ex -is [UnauthorizedAccessException]) { return 'blocked' }
    # HRESULT как строка из 8 шестнадцатеричных знаков (в PowerShell 5.1 0x8… - отрицательное Int32, так надёжнее).
    $codes += ('{0:X8}' -f [int]$ex.HResult)
    $ex = $ex.InnerException
  }
  foreach ($h in $codes) {
    switch ($h) {
      '80070005' { return 'blocked' }      # E_ACCESSDENIED: запрет в параметрах или экран блокировки
      'C00D3704' { return 'busy' }         # MF_E_HW_MFT_FAILED_START_STREAMING: камеру держит другая программа
      'C00DABE0' { return 'busy' }         # MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED
      'C00DABE1' { return 'busy' }         # MF_E_VIDEO_RECORDING_DEVICE_PREEMPTED
      '800705AA' { return 'busy' }         # ERROR_NO_SYSTEM_RESOURCES
      '80070015' { return 'busy' }         # ERROR_NOT_READY
      '80070490' { return 'no-camera' }    # ERROR_NOT_FOUND
      '8007048F' { return 'no-camera' }    # ERROR_DEVICE_NOT_CONNECTED
      'C00D36D5' { return 'no-camera' }    # MF_E_NO_CAPTURE_DEVICES_AVAILABLE
    }
  }
  return 'error'
}

$mc = $null
$tmp = $Out + '.part'
try {
  # Камера: сначала встроенная спереди (смотрит на сидящего за компьютером), иначе первая включённая.
  $devs = @(Await ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync([Windows.Devices.Enumeration.DeviceClass]::VideoCapture)) ([Windows.Devices.Enumeration.DeviceInformationCollection]))
  $enabled = @($devs | Where-Object { $_.IsEnabled })
  if ($enabled.Count -eq 0) { Done $false 'no-camera' }
  $dev = $enabled | Where-Object { $_.EnclosureLocation -and $_.EnclosureLocation.Panel -eq [Windows.Devices.Enumeration.Panel]::Front } | Select-Object -First 1
  if (-not $dev) { $dev = $enabled[0] }

  $mc = [Windows.Media.Capture.MediaCapture]::new()
  $set = [Windows.Media.Capture.MediaCaptureInitializationSettings]::new()
  $set.VideoDeviceId = $dev.Id
  $set.StreamingCaptureMode = [Windows.Media.Capture.StreamingCaptureMode]::Video
  try {
    AwaitAction ($mc.InitializeAsync($set))
  } catch {
    if ((Code $_) -ne 'busy') { throw }
    # Камеру держит другая программа - попробовать совместный доступ.
    try { $mc.Dispose() } catch { }
    $mc = [Windows.Media.Capture.MediaCapture]::new()
    $set.SharingMode = [Windows.Media.Capture.MediaCaptureSharingMode]::SharedReadOnly
    AwaitAction ($mc.InitializeAsync($set))
  }
  # Дать камере подстроить яркость: первый кадр часто тёмный.
  Start-Sleep -Milliseconds 900

  $stream = [Windows.Storage.Streams.InMemoryRandomAccessStream]::new()
  AwaitAction ($mc.CapturePhotoToStreamAsync([Windows.Media.MediaProperties.ImageEncodingProperties]::CreateJpeg(), $stream))
  $size = [uint32]$stream.Size
  if ($size -lt 100 -or $size -gt 8MB) { Done $false 'error' "size $size" }
  $reader = [Windows.Storage.Streams.DataReader]::new($stream.GetInputStreamAt(0))
  $null = Await ($reader.LoadAsync($size)) ([uint32])
  $bytes = New-Object byte[] $size
  $reader.ReadBytes($bytes)
  try { $reader.Dispose() } catch { }
  try { $stream.Dispose() } catch { }
  if ($bytes[0] -ne 0xFF -or $bytes[1] -ne 0xD8) { Done $false 'error' 'not jpeg' }

  [IO.File]::WriteAllBytes($tmp, $bytes)
  [IO.File]::Move($tmp, $Out)
  Done $true
} catch {
  $code = Code $_
  try { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } } catch { }
  Done $false $code $_.Exception.Message
} finally {
  if ($mc) { try { $mc.Dispose() } catch { } }
}
