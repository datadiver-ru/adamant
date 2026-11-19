# Адамант: действие с одним скачанным файлом по кнопке пользователя.
#   -Action trash - переместить файл в корзину (его можно вернуть из корзины).
# Путь проверяет сервер: только файлы из находок «Скачанные файлы» последней проверки.
param([Parameter(Mandatory = $true)][ValidateSet('trash')][string]$Action, [Parameter(Mandatory = $true)][string]$Path)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
$r = [ordered]@{ ok = $false }
try {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'not found' }
  Add-Type -AssemblyName Microsoft.VisualBasic
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($Path, [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
  $r.ok = -not (Test-Path -LiteralPath $Path)
} catch { $r.error = $_.Exception.Message }
[Console]::Out.Write(($r | ConvertTo-Json -Compress))
