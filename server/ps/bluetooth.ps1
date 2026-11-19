# Адамант: Bluetooth этого компьютера. ТОЛЬКО ЧТЕНИЕ, ничего не подключает и не сопрягает.
#  - radio   - есть ли Bluetooth и включён ли он (Windows.Devices.Radios);
#  - adapter - адаптер Bluetooth (имя из диспетчера устройств);
#  - paired  - сопряжённые устройства из диспетчера устройств: имя, MAC и чем оно представилось
#              (клавиатура и мышь, наушники, телефон) - по службам, которые Windows для него завела;
#  - nearby  - устройства Bluetooth LE рядом: сценарий -Seconds секунд слушает эфир (как телефон при поиске
#              устройств) и запоминает адрес, силу сигнала, имя, код производителя и службы. Сам он никуда
#              не подключается. Адреса чужих устройств программа держит только в памяти.
param([ValidateRange(0, 20)][int]$Seconds = 10)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false

$R = [ordered]@{ format = 'adamant-bluetooth'; version = 1; at = (Get-Date).ToUniversalTime().ToString('o'); seconds = $Seconds; errors = [ordered]@{} }
function Part([string]$name, [scriptblock]$sb) {
  try { $R[$name] = & $sb } catch { $R[$name] = $null; $R.errors[$name] = [string]$_.Exception.Message }
}

Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($op, [type]$type) {
  $task = $asTask.MakeGenericMethod($type).Invoke($null, @($op))
  if (-not $task.Wait(15000)) { throw 'timeout' }
  $task.Result
}

# ---- радио Bluetooth
Part 'radio' {
  $null = [Windows.Devices.Radios.Radio, Windows.System.Devices, ContentType = WindowsRuntime]
  $all = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
  $bt = @($all | Where-Object { [string]$_.Kind -eq 'Bluetooth' })
  [ordered]@{ present = ($bt.Count -gt 0); on = [bool]($bt | Where-Object { [string]$_.State -eq 'On' }); name = $(if ($bt.Count) { [string]$bt[0].Name } else { $null }) }
}

# ---- адаптер и сопряжённые устройства (диспетчер устройств)
$pnp = @()
Part 'adapter' {
  $script:pnp = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match '^(BTHENUM|BTHLE|BTHLEDEVICE|BTH)\\' -or $_.Class -eq 'Bluetooth' })
  $a = $script:pnp | Where-Object { $_.Class -eq 'Bluetooth' -and $_.InstanceId -match '^(USB|PCI|ACPI|SD)\\' } | Select-Object -First 1
  if ($a) { [ordered]@{ name = [string]$a.FriendlyName; status = [string]$a.Status } } else { $null }
}
Part 'paired' {
  $all = $script:pnp
  $top = @($all | Where-Object { $_.InstanceId -match '^(BTHENUM|BTHLE)\\DEV_([0-9A-F]{12})\\' })
  @($top | ForEach-Object {
    $null = $_.InstanceId -match '^(BTHENUM|BTHLE)\\DEV_([0-9A-F]{12})\\'
    $mac = $Matches[2]
    $le = $Matches[1] -eq 'BTHLE'
    $kids = @($all | Where-Object { $_.InstanceId.ToUpper().Contains($mac) })
    $ids = ($kids | ForEach-Object { $_.InstanceId }) -join ' '
    $classes = @($kids | ForEach-Object { [string]$_.Class } | Where-Object { $_ } | Sort-Object -Unique)
    [ordered]@{
      name = [string]$_.FriendlyName; mac = $mac; le = $le; status = [string]$_.Status
      hid = [bool]($ids -match '\{0000(1812|1124)-' -or ($classes -match '^(HIDClass|Keyboard|Mouse)$'))
      audio = [bool]($ids -match '\{0000(110B|111E|1108|110D)-' -or ($classes -match '^(MEDIA|AudioEndpoint)$'))
      phone = [bool]($ids -match '\{0000(112F|1132|1105|111F)-')
      classes = $classes
    }
  })
}

# ---- кто рядом: слушаем объявления Bluetooth LE
Part 'nearby' {
  if ($Seconds -le 0) { return @() }
  if ($R.radio -and -not $R.radio.on) { return @() }
  $null = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher, Windows.Devices.Bluetooth, ContentType = WindowsRuntime]
  # PowerShell 5.1 не умеет подписываться на события Windows Runtime: событие складывает в очередь маленький класс на C#,
  # он же достаёт байты из буфера данных (интерфейс IBufferByteAccess).
  if (-not ('AdamantBtSink' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
[ComImport, Guid("905a0fef-bc53-11df-8c49-001e4fc686da"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAdamantBufferByteAccess { IntPtr Buffer(); }
public class AdamantBtSink {
  public System.Collections.Concurrent.ConcurrentQueue<object> Q = new System.Collections.Concurrent.ConcurrentQueue<object>();
  public void On(object sender, object args) { if (Q.Count < 20000) Q.Enqueue(args); }
  public static byte[] Bytes(object buffer, int length) {
    if (buffer == null || length <= 0) return new byte[0];
    if (length > 64) length = 64;
    IntPtr p = ((IAdamantBufferByteAccess)buffer).Buffer();
    byte[] b = new byte[length];
    Marshal.Copy(p, b, 0, length);
    return b;
  }
}
'@
  }
  $sink = New-Object AdamantBtSink
  $w = New-Object Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher
  $w.ScanningMode = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode]::Active
  $ev = $w.GetType().GetEvent('Received')
  $del = [Delegate]::CreateDelegate($ev.EventHandlerType, $sink, $sink.GetType().GetMethod('On'))
  $null = $ev.GetAddMethod().Invoke($w, @($del))
  $w.Start()
  try { Start-Sleep -Seconds $Seconds } finally { $w.Stop() }
  $seen = @{}
  $a = $null
  while ($sink.Q.TryDequeue([ref]$a)) {
    try {
      $addr = '{0:X12}' -f $a.BluetoothAddress
      $d = $seen[$addr]
      if (-not $d) { $d = [ordered]@{ addr = $addr; rssi = -127; n = 0; name = ''; mf = @(); svc = @(); random = $null; connectable = $null }; $seen[$addr] = $d }
      $d.n++
      if ($a.RawSignalStrengthInDBm -gt $d.rssi) { $d.rssi = [int]$a.RawSignalStrengthInDBm }
      $ln = [string]$a.Advertisement.LocalName
      if ($ln -and -not $d.name) { $d.name = $ln.Substring(0, [Math]::Min(60, $ln.Length)) }
      try { $d.random = ([string]$a.BluetoothAddressType -eq 'Random') } catch { }
      try { if ($a.IsConnectable) { $d.connectable = $true } elseif ($null -eq $d.connectable) { $d.connectable = $false } } catch { }
      foreach ($m in @($a.Advertisement.ManufacturerData)) {
        $b = [AdamantBtSink]::Bytes($m.Data, [int]$m.Data.Length)
        $k = '{0:X4}:{1}' -f [int]$m.CompanyId, (($b | Select-Object -First 4 | ForEach-Object { '{0:X2}' -f $_ }) -join '')
        if ($d.mf -notcontains $k -and $d.mf.Count -lt 4) { $d.mf += $k }
      }
      foreach ($u in @($a.Advertisement.ServiceUuids)) {
        $s = $u.ToString().ToUpper()
        if ($s -match '^0000([0-9A-F]{4})-0000-1000-8000-00805F9B34FB$') { $s = $Matches[1] }
        if ($d.svc -notcontains $s -and $d.svc.Count -lt 6) { $d.svc += $s }
      }
    } catch { }
  }
  @($seen.Values | Sort-Object { $_.rssi } -Descending | Select-Object -First 200)
}

[Console]::Out.Write((ConvertTo-Json -InputObject $R -Depth 6 -Compress))
