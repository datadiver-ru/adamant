// Адамант: запуск без окна консоли. Заменяет windows/adamant.vbs и windows/tray.vbs:
// скрипт VBS, который скрыто запускает PowerShell, антивирусы часто принимают за загрузчик вирусов.
// Собирается при сборке дистрибутива (scripts/build-dist.js) компилятором C# из .NET Framework 4.
//
//   Adamant.exe                        - сервер (если ещё не запущен) и окно программы: server/launch.js
//   Adamant.exe --tray | --background | --stop   - то же с ключом для server/launch.js
//   Adamant.exe --tray-icon <папка данных>       - значок в трее (windows/tray.ps1) отдельным скрытым процессом
//
// Программа ничего не скачивает и не меняет: только запускает свои файлы из своей папки.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

[assembly: AssemblyTitle("Адамант")]
[assembly: AssemblyDescription("Адамант - проверка защиты компьютера с Windows")]
[assembly: AssemblyProduct("Адамант")]
[assembly: AssemblyCopyright("Data Diver")]

static class Launcher {
  [STAThread]
  static int Main(string[] args) {
    string root = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location).TrimEnd('\\');
    try {
      if (args.Length == 2 && args[0] == "--tray-icon") return TrayIcon(root, args[1]);
      // Для server/launch.js - только известные ключи, остальное игнорируем.
      var extra = new StringBuilder();
      foreach (string a in args) {
        if ((a == "--tray" || a == "--background" || a == "--stop") && extra.ToString().IndexOf(a) < 0) extra.Append(' ').Append(a);
      }
      string node = Path.Combine(root, "runtime", "node.exe");
      if (!File.Exists(node)) node = "node";
      Start(node, Q(Path.Combine(root, "server", "launch.js")) + extra, root);
      return 0;
    } catch {
      return 1;
    }
  }

  /// Значок в трее. Процесс PowerShell получает свою скрытую консоль и не зависит от того, кто его запустил.
  static int TrayIcon(string root, string data) {
    data = data.TrimEnd('\\');
    if (data.Length == 0 || data.IndexOf('"') >= 0 || !Directory.Exists(data)) return 2;
    string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
    Start(ps, "-NoProfile -ExecutionPolicy Bypass -STA -File " + Q(Path.Combine(root, "windows", "tray.ps1")) + " -Root " + Q(root) + " -Data " + Q(data), root);
    return 0;
  }

  static void Start(string file, string arguments, string dir) {
    var psi = new ProcessStartInfo(file, arguments) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = dir };
    using (Process.Start(psi)) { }
  }

  static string Q(string s) { return "\"" + s + "\""; }
}
