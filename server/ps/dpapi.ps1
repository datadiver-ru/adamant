# Адамант: ключ данных через DPAPI текущего пользователя Windows (server/vault.js).
# Открыть обёрнутый ключ может только эта учётная запись на этом компьютере.
# Вход - JSON {"data":"<base64>"} на стандартном вводе (не в командной строке). Выход - JSON {"ok":true,"data":"<base64>"}.
# Ничего не пишет на диск и ничего не меняет в системе.
param([Parameter(Mandatory = $true)][ValidateSet('protect', 'unprotect')][string]$Op)
$ErrorActionPreference = 'Stop'
try {
  Add-Type -AssemblyName System.Security
  $text = [Console]::In.ReadToEnd().Trim([char[]]@([char]0xFEFF, ' ', [char]13, [char]10))
  $in = $text | ConvertFrom-Json
  $bytes = [Convert]::FromBase64String([string]$in.data)
  $entropy = [Text.Encoding]::UTF8.GetBytes('Adamant data.key v1')
  $scope = [Security.Cryptography.DataProtectionScope]::CurrentUser
  if ($Op -eq 'protect') { $r = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, $scope) }
  else { $r = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, $scope) }
  [Console]::Out.Write((@{ ok = $true; data = [Convert]::ToBase64String($r) } | ConvertTo-Json -Compress))
} catch {
  [Console]::Out.Write((@{ ok = $false; error = [string]$_.Exception.Message } | ConvertTo-Json -Compress))
}
