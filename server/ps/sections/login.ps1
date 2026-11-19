# Адамант: вход в Windows. ТОЛЬКО ЧТЕНИЕ - ничего не меняет в системе.
# Блокировка после неверных паролей (NetUserModalsGet, уровень 3 - читается и без прав администратора),
# Ctrl+Alt+Del перед входом, ПИН-код Windows Hello у текущего пользователя, выпуск Windows,
# что есть для шифрования диска и политика ПИН-кода BitLocker (HKLM\SOFTWARE\Policies\Microsoft\FVE).
# Подсказку к паролю не читаем: она хранится в SAM, который доступен только системе.
# Производитель и модель компьютера уже есть в разделе firmware (collect.ps1), состав ключей BitLocker - в physical.

Section 'login' {
  $r = [ordered]@{ admin = $isAdmin; errors = [ordered]@{} }
  $sys32 = Join-Path $env:SystemRoot 'System32'
  function Int($v) { if ($null -eq $v -or "$v" -eq '') { return $null }; try { return [int64]$v } catch { return $null } }

  try { $r.partOfDomain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { $r.partOfDomain = $null; $r.errors.domain = $_.Exception.Message }

  # ---------- Блокировка после неверных паролей ----------
  # USER_MODALS_INFO_3: длительность блокировки (с), окно счёта ошибок (с), порог. 4294967295 - «до разблокировки администратором».
  try {
    if (-not ('Adamant.Login' -as [type])) {
      Add-Type -Namespace Adamant -Name Login -MemberDefinition @'
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetUserModalsGet(string server, int level, out IntPtr buf);
[DllImport("netapi32.dll")] static extern int NetApiBufferFree(IntPtr buf);
// [код ошибки, порог, окно (с), длительность (с)]
public static long[] Lockout() {
  IntPtr p;
  int rc = NetUserModalsGet(null, 3, out p);
  if (rc != 0) return new long[] { rc, 0, 0, 0 };
  try { return new long[] { 0, (uint)Marshal.ReadInt32(p, 8), (uint)Marshal.ReadInt32(p, 4), (uint)Marshal.ReadInt32(p, 0) }; }
  finally { NetApiBufferFree(p); }
}
'@
    }
    $l = [Adamant.Login]::Lockout()
    if ($l[0] -ne 0) { throw "NetUserModalsGet: $($l[0])" }
    $r.lockout = [ordered]@{ threshold = $l[1]; windowSec = $l[2]; durationSec = $l[3] }
  } catch { $r.lockout = $null; $r.errors.lockout = $_.Exception.Message }

  # ---------- Ctrl+Alt+Del перед входом ----------
  # Политика (Policies\System) важнее старого значения в Winlogon. Без обоих: в домене - требуется, иначе - нет.
  try {
    $pol = Int (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCAD')
    $wl = Int (Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DisableCAD')
    $src = $null; $eff = $null
    if ($null -ne $pol) { $eff = $pol; $src = 'policy' }
    elseif ($null -ne $wl) { $eff = $wl; $src = 'winlogon' }
    elseif ($null -ne $r.partOfDomain) { $eff = $(if ($r.partOfDomain) { 0 } else { 1 }); $src = 'default' }
    $r.cad = [ordered]@{ policy = $pol; winlogon = $wl; source = $src; required = $(if ($null -eq $eff) { $null } else { $eff -eq 0 }) }
  } catch { $r.errors.cad = $_.Exception.Message }

  # ---------- Windows Hello ----------
  # ПИН-код: поставщик входа NGC ({D6886603-…}) отмечает у пользователя LogonCredsAvailable = 1, LogonUI хранит NgcPin\Credentials\<SID>.
  # Если ни того, ни другого нет - ПИН-кода, скорее всего, нет; если сведений не прочитать - null.
  try {
    $sid = $me.User.Value
    $auth = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication'
    $cp = "$auth\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}"
    $creds = Int (Reg "$cp\$sid" 'LogonCredsAvailable')
    $ngc = Test-Path -LiteralPath "$auth\LogonUI\NgcPin\Credentials\$sid"
    $pin = $null; $pinSource = $null
    if ($creds -eq 1 -or $ngc) { $pin = $true; $pinSource = $(if ($creds -eq 1) { 'logon-creds' } else { 'ngc' }) }
    elseif ($null -ne $creds) { $pin = $false; $pinSource = 'logon-creds' }
    elseif ((Test-Path -LiteralPath $cp) -and -not (Test-Path -LiteralPath "$cp\$sid")) { $pin = $false; $pinSource = 'absent' }
    # Отпечаток и лицо: видно только, есть ли сканер; настроен ли он у пользователя - без прав системы не узнать.
    $bio = $null
    try { $bio = @(Get-CimInstance Win32_PnPEntity -Filter "PNPClass='Biometric'" -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch {}
    $r.hello = [ordered]@{ pin = $pin; pinSource = $pinSource; biometricDevices = $bio; biometrics = $null }
  } catch { $r.errors.hello = $_.Exception.Message }

  # ---------- Выпуск Windows и шифрование диска ----------
  try {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $r.edition = [ordered]@{ id = [string](Reg $cv 'EditionID'); composition = [string](Reg $cv 'CompositionEditionID') }
  } catch { $r.errors.edition = $_.Exception.Message }
  try {
    $ctl = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
    $fve = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    $r.bitlocker = [ordered]@{
      controlKey = Test-Path -LiteralPath $ctl
      autoDE = Test-Path -LiteralPath "$ctl\AutoDE"
      preventDeviceEncryption = Int (Reg $ctl 'PreventDeviceEncryption')
      tools = [ordered]@{ wizard = Test-Path -LiteralPath (Join-Path $sys32 'BitLockerWizardElev.exe'); manageBde = Test-Path -LiteralPath (Join-Path $sys32 'manage-bde.exe') }
      # 0 - не разрешать, 1 - требовать, 2 - разрешать (как в редакторе групповой политики).
      policy = [ordered]@{
        useAdvancedStartup = Int (Reg $fve 'UseAdvancedStartup'); enableBdeWithNoTpm = Int (Reg $fve 'EnableBDEWithNoTPM')
        useTpm = Int (Reg $fve 'UseTPM'); useTpmPin = Int (Reg $fve 'UseTPMPIN'); useTpmKey = Int (Reg $fve 'UseTPMKey'); useTpmKeyPin = Int (Reg $fve 'UseTPMKeyPIN')
        minimumPin = Int (Reg $fve 'MinimumPIN'); useEnhancedPin = Int (Reg $fve 'UseEnhancedPin')
      }
    }
  } catch { $r.errors.bitlocker = $_.Exception.Message }

  $r
}
