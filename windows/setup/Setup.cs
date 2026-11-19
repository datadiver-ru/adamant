// Адамант: установщик для скачивания с сайта (один файл .exe).
// Собирается встроенным в Windows компилятором C# (.NET Framework 4): npm run setup
//
// Внутри - архив программы (ресурс Adamant.zip), его SHA-256 (Adamant.sha256), текст лицензии (LICENSE.txt)
// и картинки окна (diamond.png, banner.jpg). Окно рисуется само, без сторонних библиотек:
// шапка с Кирой в доспехах и алмазом, шаги «Лицензия → Установка → Готово», свои кнопки, галочки и полоса загрузки.
// Кнопка «Установить» доступна после галочки «Я принимаю условия лицензии». По ней: проверяет архив,
// распаковывает во временную папку и запускает windows\install-app.ps1 - установка для текущего пользователя,
// без прав администратора. Ничего не скачивает. Временная папка удаляется.
//
//   Adamant-Setup.exe /check [файл]                        - только проверить архив внутри (ничего не устанавливает);
//                                                             код выхода 0/1 и, если указан файл, текст в нём.
//   Adamant-Setup.exe /preview <экран> <файл.png> [en] [масштаб] - нарисовать экран (license, install, done, error)
//                                                             в картинку и выйти (ничего не устанавливает).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Адамант - установка")]
[assembly: AssemblyProduct("Адамант")]
[assembly: AssemblyCompany("Data Diver")]
[assembly: AssemblyDescription("Установка Адаманта для текущего пользователя Windows")]

static class Setup {
  public static bool Ru = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ru";
  public static string L(string ru, string en) { return Ru ? ru : en; }

  static Stream Res(string name) { return Assembly.GetExecutingAssembly().GetManifestResourceStream(name); }

  public static string Text(string name) {
    using (Stream s = Res(name))
    using (StreamReader r = new StreamReader(s, Encoding.UTF8)) return r.ReadToEnd().Trim();
  }

  public static Image Picture(string name) {
    try {
      MemoryStream m = new MemoryStream();
      using (Stream s = Res(name)) s.CopyTo(m);
      m.Position = 0;
      return Image.FromStream(m); // поток живёт вместе с картинкой
    } catch { return null; }
  }

  public static string Version() { return Text("version.txt"); }

  /// Архив из ресурсов -> файл; сверяет SHA-256 со встроенным значением.
  public static void ExtractPayload(string zipPath) {
    string want = Text("Adamant.sha256").ToLowerInvariant();
    using (Stream s = Res("Adamant.zip"))
    using (FileStream f = File.Create(zipPath)) s.CopyTo(f);
    string got;
    using (FileStream f = File.OpenRead(zipPath))
    using (SHA256 h = SHA256.Create()) got = BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
    if (got != want) throw new Exception(L("Установщик повреждён: контрольная сумма архива не сходится. Скачайте его заново.", "The installer is damaged: the archive checksum does not match. Download it again."));
  }

  public static string LicenseText() {
    string t = Text("LICENSE.txt").Replace("\r\n", "\n").Replace("\n", "\r\n");
    // Сначала - текст на языке Windows: английская часть идёт после разделителя.
    int cut = t.IndexOf("--------------------");
    if (!Ru && cut > 0) t = t.Substring(t.IndexOf("ADAMANT LICENSE", cut)) + "\r\n\r\n" + t.Substring(0, cut);
    return Reflow(t);
  }

  // В файле строки обрезаны по ширине ~88 знаков; окно уже, поэтому склеиваем перенесённые строки
  // абзаца обратно - текст переносится по ширине окна, без обрывков в одно слово.
  static string Reflow(string t) {
    string[] lines = t.Split(new string[] { "\r\n" }, StringSplitOptions.None);
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < lines.Length; i++) {
      string cur = lines[i];
      while (i + 1 < lines.Length && Continues(cur, lines[i + 1])) cur = cur.TrimEnd() + " " + lines[++i].Trim();
      sb.Append(cur);
      if (i + 1 < lines.Length) sb.Append("\r\n");
    }
    return sb.ToString();
  }

  static int Indent(string s) { int n = 0; while (n < s.Length && s[n] == ' ') n++; return n; }

  static bool Continues(string cur, string next) {
    if (cur.Trim().Length == 0 || next.Trim().Length == 0) return false;
    string n = next.Trim();
    if (n.StartsWith("Copyright") || n.StartsWith("-") || n.StartsWith("«") || n.StartsWith("\"")) return false;
    if (n.Length > 1 && char.IsDigit(n[0])) return false; // новый пункт: «2.», «2.1.»
    int ci = Indent(cur), ni = Indent(next);
    if (ni == ci) return !char.IsDigit(cur.Trim()[0]) || ci > 0;
    // Продолжение подпункта «2.1. ...» идёт с отступом глубже.
    string c = cur.Trim();
    return ni > ci && c.Length > 3 && char.IsDigit(c[0]) && c.IndexOf('.') > 0 && c.IndexOf('.') < c.Length - 1 && char.IsDigit(c[c.IndexOf('.') + 1]);
  }

  public static string InstallScript(string dir) {
    foreach (string d in Directory.GetDirectories(dir, "Adamant-*")) {
      string p = Path.Combine(d, "windows", "install-app.ps1");
      if (File.Exists(p)) return p;
    }
    throw new Exception(L("В архиве нет сценария установки.", "The archive has no install script."));
  }

  static int Check(string outFile) {
    string tmp = Path.Combine(Path.GetTempPath(), "Adamant-setup-check-" + Guid.NewGuid().ToString("N"));
    string msg;
    int code = 0;
    try {
      Directory.CreateDirectory(tmp);
      string zip = Path.Combine(tmp, "Adamant.zip");
      ExtractPayload(zip);
      int n = 0;
      bool script = false, node = false;
      using (ZipArchive z = ZipFile.OpenRead(zip)) {
        foreach (ZipArchiveEntry e in z.Entries) {
          n++;
          if (e.FullName.EndsWith("/windows/install-app.ps1")) script = true;
          if (e.FullName.EndsWith("/runtime/node.exe")) node = true;
        }
      }
      bool pics = Picture("diamond.png") != null && Picture("banner.jpg") != null;
      if (!script || !node || !pics) { code = 1; msg = "missing install-app.ps1, node.exe or pictures"; }
      else msg = "ok " + Version() + " files=" + n;
    } catch (Exception e) {
      code = 1;
      msg = "error " + e.Message;
    } finally {
      try { Directory.Delete(tmp, true); } catch { }
    }
    if (!string.IsNullOrEmpty(outFile)) File.WriteAllText(outFile, msg, new UTF8Encoding(false));
    return code;
  }

  [DllImport("user32.dll")] static extern bool SetProcessDPIAware();

  [STAThread]
  static int Main(string[] args) {
    if (args.Length > 0 && args[0].Equals("/check", StringComparison.OrdinalIgnoreCase)) return Check(args.Length > 1 ? args[1] : null);
    try { SetProcessDPIAware(); } catch { }
    Application.EnableVisualStyles();
    Application.SetCompatibleTextRenderingDefault(false);
    if (args.Length >= 3 && args[0].Equals("/preview", StringComparison.OrdinalIgnoreCase)) {
      if (args.Length > 3 && args[3] == "en") Ru = false;
      float scale = args.Length > 4 ? float.Parse(args[4], CultureInfo.InvariantCulture) : 1f;
      using (SetupForm f = new SetupForm(scale)) return f.Preview(args[1], args[2]);
    }
    Application.Run(new SetupForm(0));
    return 0;
  }
}

/// Цвета и размеры окна (тема сайта и программы).
static class Theme {
  public static readonly Color Bg = Color.FromArgb(17, 21, 26);       // #11151a
  public static readonly Color Card = Color.FromArgb(25, 31, 39);
  public static readonly Color Card2 = Color.FromArgb(31, 39, 49);
  public static readonly Color Line = Color.FromArgb(47, 58, 71);
  public static readonly Color Ink = Color.FromArgb(238, 242, 246);
  public static readonly Color Ink2 = Color.FromArgb(178, 189, 201);
  public static readonly Color Ink3 = Color.FromArgb(118, 131, 146);
  public static readonly Color Accent = Color.FromArgb(207, 227, 245); // #cfe3f5
  public static readonly Color Btn1 = Color.FromArgb(126, 157, 184);   // #7e9db8
  public static readonly Color Btn2 = Color.FromArgb(54, 77, 98);      // #364d62
  public static readonly Color Ok = Color.FromArgb(111, 211, 160);
  public static readonly Color Bad = Color.FromArgb(240, 132, 132);
  public static float Scale = 1f;
  public static int S(float v) { return (int)Math.Round(v * Scale); }
  public static float F(float v) { return v * Scale; }
  /// Шрифт в пикселях: одинаково выглядит при любом масштабе экрана.
  public static Font Font(float px, FontStyle st, string family) { return new Font(family, px * Scale, st, GraphicsUnit.Pixel); }
  public static Font Font(float px) { return Font(px, FontStyle.Regular, "Segoe UI"); }

  public static GraphicsPath Round(RectangleF r, float rad) {
    GraphicsPath p = new GraphicsPath();
    float d = Math.Min(rad * 2, Math.Min(r.Width, r.Height));
    if (d <= 0) { p.AddRectangle(r); return p; }
    p.AddArc(r.X, r.Y, d, d, 180, 90);
    p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
    p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
    p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
    p.CloseFigure();
    return p;
  }

  public static void Smooth(Graphics g) {
    g.SmoothingMode = SmoothingMode.AntiAlias;
    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
    g.PixelOffsetMode = PixelOffsetMode.HighQuality;
    g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
  }

  public static Color Mix(Color a, Color b, float t) {
    return Color.FromArgb((int)(a.A + (b.A - a.A) * t), (int)(a.R + (b.R - a.R) * t), (int)(a.G + (b.G - a.G) * t), (int)(a.B + (b.B - a.B) * t));
  }

  /// Галочка в квадрате/круге со стороной size.
  public static void Tick(Graphics g, RectangleF r, Color c, float width) {
    using (Pen p = new Pen(c, width)) {
      p.StartCap = LineCap.Round;
      p.EndCap = LineCap.Round;
      p.LineJoin = LineJoin.Round;
      g.DrawLines(p, new PointF[] {
        new PointF(r.X + r.Width * .27f, r.Y + r.Height * .52f),
        new PointF(r.X + r.Width * .44f, r.Y + r.Height * .68f),
        new PointF(r.X + r.Width * .74f, r.Y + r.Height * .34f) });
    }
  }
}

/// Кнопка: основная - огранённый градиент, вторая - контурная.
class GemButton : Control {
  public bool Primary;
  bool hover, down;

  public GemButton(string text, bool primary) {
    Text = text;
    Primary = primary;
    SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor | ControlStyles.Selectable, true);
    BackColor = Color.Transparent;
    Cursor = Cursors.Hand;
    TabStop = true;
    Font = Theme.Font(14, FontStyle.Bold, "Segoe UI Semibold");
  }

  protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
  protected override void OnMouseLeave(EventArgs e) { hover = false; down = false; Invalidate(); base.OnMouseLeave(e); }
  protected override void OnMouseDown(MouseEventArgs e) { down = true; Focus(); Invalidate(); base.OnMouseDown(e); }
  protected override void OnMouseUp(MouseEventArgs e) { down = false; Invalidate(); base.OnMouseUp(e); }
  protected override void OnEnabledChanged(EventArgs e) { Cursor = Enabled ? Cursors.Hand : Cursors.Default; Invalidate(); base.OnEnabledChanged(e); }
  protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
  protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }
  protected override void OnKeyDown(KeyEventArgs e) {
    if (e.KeyCode == Keys.Enter || e.KeyCode == Keys.Space) { OnClick(EventArgs.Empty); e.Handled = true; }
    base.OnKeyDown(e);
  }

  protected override void OnPaint(PaintEventArgs e) {
    Graphics g = e.Graphics;
    Theme.Smooth(g);
    RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
    float rad = Theme.F(9);
    using (GraphicsPath p = Theme.Round(r, rad)) {
      if (Primary) {
        Color a = Theme.Btn1, b = Theme.Btn2;
        if (!Enabled) { a = Theme.Mix(a, Theme.Bg, .55f); b = Theme.Mix(b, Theme.Bg, .55f); }
        else if (down) { a = Theme.Mix(a, Theme.Btn2, .25f); }
        else if (hover) { a = Theme.Mix(a, Theme.Accent, .25f); b = Theme.Mix(b, Theme.Btn1, .2f); }
        using (LinearGradientBrush br = new LinearGradientBrush(r, a, b, LinearGradientMode.Vertical)) g.FillPath(br, p);
        // Блик огранки: светлая полоса сверху.
        RectangleF top = new RectangleF(r.X + 1, r.Y + 1, r.Width - 2, r.Height * .45f);
        using (GraphicsPath tp = Theme.Round(top, rad - 1))
        using (LinearGradientBrush br = new LinearGradientBrush(top, Color.FromArgb(Enabled ? 60 : 20, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), LinearGradientMode.Vertical)) g.FillPath(br, tp);
        using (Pen pen = new Pen(Color.FromArgb(Enabled ? 120 : 40, Theme.Accent), 1)) g.DrawPath(pen, p);
      } else {
        using (SolidBrush br = new SolidBrush(hover && Enabled ? Theme.Card2 : Theme.Card)) g.FillPath(br, p);
        using (Pen pen = new Pen(hover && Enabled ? Theme.Ink3 : Theme.Line, 1)) g.DrawPath(pen, p);
      }
      if (Focused && Enabled) {
        RectangleF f = RectangleF.Inflate(r, -Theme.F(3), -Theme.F(3));
        using (GraphicsPath fp = Theme.Round(f, rad - 3))
        using (Pen pen = new Pen(Color.FromArgb(110, Theme.Accent), 1) { DashStyle = DashStyle.Dot }) g.DrawPath(pen, fp);
      }
    }
    Color ink = !Enabled ? Theme.Mix(Theme.Ink, Theme.Bg, .55f) : Primary ? Color.White : (hover ? Theme.Ink : Theme.Ink2);
    TextRenderer.DrawText(g, Text, Font, Rectangle.Round(r), ink, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
  }
}

/// Галочка в цветах Адаманта.
class GemCheck : Control {
  bool on, hover;
  public event EventHandler CheckedChanged;
  public bool Checked {
    get { return on; }
    set { if (on != value) { on = value; Invalidate(); if (CheckedChanged != null) CheckedChanged(this, EventArgs.Empty); } }
  }

  public GemCheck(string text, bool value) {
    Text = text;
    on = value;
    SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor | ControlStyles.Selectable, true);
    BackColor = Color.Transparent;
    Cursor = Cursors.Hand;
    TabStop = true;
    Font = Theme.Font(14);
  }

  protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
  protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
  protected override void OnClick(EventArgs e) { Focus(); Checked = !Checked; base.OnClick(e); }
  protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
  protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }
  protected override void OnKeyDown(KeyEventArgs e) {
    if (e.KeyCode == Keys.Space) { Checked = !Checked; e.Handled = true; }
    base.OnKeyDown(e);
  }

  protected override void OnPaint(PaintEventArgs e) {
    Graphics g = e.Graphics;
    Theme.Smooth(g);
    float box = Theme.F(20);
    RectangleF r = new RectangleF(Theme.F(1), (Height - box) / 2, box, box);
    using (GraphicsPath p = Theme.Round(r, Theme.F(5))) {
      if (on) {
        using (LinearGradientBrush br = new LinearGradientBrush(r, Theme.Btn1, Theme.Btn2, LinearGradientMode.Vertical)) g.FillPath(br, p);
        using (Pen pen = new Pen(Color.FromArgb(150, Theme.Accent), 1)) g.DrawPath(pen, p);
        Theme.Tick(g, r, Color.White, Theme.F(2.2f));
      } else {
        using (SolidBrush br = new SolidBrush(Theme.Card)) g.FillPath(br, p);
        using (Pen pen = new Pen(hover || Focused ? Theme.Accent : Theme.Ink3, Theme.F(1.4f))) g.DrawPath(pen, p);
      }
    }
    Rectangle tr = new Rectangle((int)(r.Right + Theme.F(10)), 0, Width - (int)(r.Right + Theme.F(10)), Height);
    TextRenderer.DrawText(g, Text, Font, tr, hover || Focused ? Theme.Ink : Theme.Ink2, TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);
  }
}

/// Полоса загрузки: огранённая «алмазная» лента с настоящим процентом, бегущим бликом и искрой-алмазом на конце.
/// Ровная анимация - свой таймер (~60 кадров в секунду), пока полоса видна.
class GemBar : Control {
  float value, shown, phase;
  readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 16 };
  public float Value { get { return value; } set { this.value = Math.Max(0, Math.Min(1, value)); Invalidate(); } }
  /// Для предпросмотра: сразу показать значение и положение блика.
  public void Freeze(float v, float ph) { value = shown = v; phase = ph; Invalidate(); }

  public GemBar() {
    SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
    BackColor = Color.Transparent;
    timer.Tick += delegate {
      shown += (value - shown) * .12f; // плавно догоняет настоящее значение
      if (Math.Abs(value - shown) < .0005f) shown = value;
      phase = (phase + .011f) % 1.6f;
      Invalidate();
    };
  }

  protected override void OnVisibleChanged(EventArgs e) { base.OnVisibleChanged(e); timer.Enabled = Visible; }
  protected override void Dispose(bool disposing) { if (disposing) timer.Dispose(); base.Dispose(disposing); }

  protected override void OnPaint(PaintEventArgs e) {
    Graphics g = e.Graphics;
    Theme.Smooth(g);
    float pad = Height * .3f; // место для свечения искры
    RectangleF r = new RectangleF(pad, pad, Width - 2 * pad, Height - 2 * pad);
    float rad = r.Height / 2;
    using (GraphicsPath p = Theme.Round(r, rad)) {
      using (SolidBrush br = new SolidBrush(Theme.Card2)) g.FillPath(br, p);
      using (Pen pen = new Pen(Theme.Line, 1)) g.DrawPath(pen, p);
    }
    if (shown <= 0) return;
    RectangleF f = new RectangleF(r.X, r.Y, Math.Max(r.Height, r.Width * shown), r.Height);
    using (GraphicsPath p = Theme.Round(f, rad)) {
      using (LinearGradientBrush br = new LinearGradientBrush(r, Theme.Btn2, Theme.Accent, LinearGradientMode.Horizontal)) {
        br.InterpolationColors = new ColorBlend { Colors = new Color[] { Theme.Btn2, Theme.Btn1, Theme.Accent }, Positions = new float[] { 0, .55f, 1 } };
        g.FillPath(br, p);
      }
      GraphicsState st = g.Save();
      g.SetClip(p);
      // Грани: светлая верхняя половина и косые линии огранки.
      using (SolidBrush br = new SolidBrush(Color.FromArgb(45, 255, 255, 255))) g.FillRectangle(br, f.X, f.Y, f.Width, f.Height * .45f);
      using (Pen pen = new Pen(Color.FromArgb(38, 255, 255, 255), 1)) {
        float step = r.Height * 1.6f;
        for (float x = f.X - r.Height; x < f.Right; x += step) {
          g.DrawLine(pen, x, f.Bottom, x + r.Height, f.Y);
          g.DrawLine(pen, x + r.Height, f.Bottom, x, f.Y);
        }
      }
      // Бегущий блик.
      float bw = Math.Max(r.Height * 6, r.Width * .18f);
      float bx = r.X - bw + (r.Width + bw) * (phase / 1.2f);
      if (phase < 1.2f) {
        RectangleF band = new RectangleF(bx, f.Y, bw, f.Height);
        using (LinearGradientBrush br = new LinearGradientBrush(band, Color.Transparent, Color.Transparent, LinearGradientMode.Horizontal)) {
          br.InterpolationColors = new ColorBlend { Colors = new Color[] { Color.FromArgb(0, 255, 255, 255), Color.FromArgb(150, 255, 255, 255), Color.FromArgb(0, 255, 255, 255) }, Positions = new float[] { 0, .5f, 1 } };
          g.FillRectangle(br, band);
        }
      }
      g.Restore(st);
    }
    // Искра-алмаз на конце: мягкое свечение и маленький ромб, который мерцает.
    float cx = f.Right - rad * .6f, cy = r.Y + r.Height / 2;
    float glowR = r.Height * 2.4f;
    using (GraphicsPath gp = new GraphicsPath()) {
      gp.AddEllipse(cx - glowR, cy - glowR, glowR * 2, glowR * 2);
      using (PathGradientBrush pb = new PathGradientBrush(gp) { CenterColor = Color.FromArgb(170, Theme.Accent), SurroundColors = new Color[] { Color.FromArgb(0, Theme.Accent) } }) g.FillPath(pb, gp);
    }
    float tw = (float)(0.75 + 0.25 * Math.Sin(phase * Math.PI * 2.5));
    float s = r.Height * .95f * tw;
    PointF[] gem = { new PointF(cx, cy - s), new PointF(cx + s * .7f, cy), new PointF(cx, cy + s), new PointF(cx - s * .7f, cy) };
    using (SolidBrush br = new SolidBrush(Color.White)) g.FillPolygon(br, gem);
    using (Pen pen = new Pen(Color.FromArgb(200, Theme.Accent), 1)) {
      g.DrawLine(pen, cx - s * 1.6f, cy, cx + s * 1.6f, cy);
      g.DrawLine(pen, cx, cy - s * 1.6f, cx, cy + s * 1.6f);
    }
  }
}

class SetupForm : Form {
  enum Step { License, Install, Done, Error }

  const int W = 680, H = 480, BANNER = 158;
  readonly string version = Setup.Version();
  readonly string installDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Adamant");
  readonly Image banner = Setup.Picture("banner.jpg");
  readonly Image diamond = Setup.Picture("diamond.png");

  readonly TextBox license = new TextBox();
  readonly TextBox log = new TextBox();
  readonly GemCheck accept = new GemCheck(Setup.L("Я принимаю условия лицензии", "I accept the license terms"), false);
  readonly GemCheck desktop = new GemCheck(Setup.L("Ярлык на рабочем столе", "Desktop shortcut"), true);
  readonly GemBar bar = new GemBar();
  readonly GemButton main = new GemButton("", true);
  readonly GemButton second = new GemButton("", false);
  readonly List<string> output = new List<string>();

  Step step = Step.License;
  bool working;
  string status = "";
  string error = "";
  bool closeHover;

  public SetupForm(float scale) {
    if (scale > 0) Theme.Scale = scale;
    else using (Graphics g = CreateGraphics()) Theme.Scale = Math.Max(1f, g.DpiX / 96f);
    // Кнопки и галочки созданы до того, как стал известен масштаб экрана: шрифт им - заново, под масштаб.
    main.Font = Theme.Font(14, FontStyle.Bold, "Segoe UI Semibold");
    second.Font = Theme.Font(14, FontStyle.Bold, "Segoe UI Semibold");
    accept.Font = Theme.Font(14);
    desktop.Font = Theme.Font(14);

    Text = Setup.L("Установка Адаманта ", "Adamant setup ") + version;
    try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
    FormBorderStyle = FormBorderStyle.None;
    StartPosition = FormStartPosition.CenterScreen;
    ClientSize = new Size(Theme.S(W), Theme.S(H));
    BackColor = Theme.Bg;
    ForeColor = Theme.Ink;
    DoubleBuffered = true;
    KeyPreview = true;
    Font = Theme.Font(14);

    Frame(license, Theme.Font(13.5f), Theme.Ink2);
    license.Text = Setup.LicenseText();
    license.SetBounds(Theme.S(44), Theme.S(224), Theme.S(W - 88), Theme.S(126));
    Frame(log, Theme.Font(12.5f, FontStyle.Regular, "Consolas"), Theme.Ink2);
    log.SetBounds(Theme.S(44), Theme.S(278), Theme.S(W - 88), Theme.S(92));
    log.Visible = false;

    accept.SetBounds(Theme.S(28), Theme.S(374), Theme.S(380), Theme.S(28));
    accept.CheckedChanged += delegate { main.Enabled = accept.Checked; };
    desktop.SetBounds(Theme.S(28), Theme.S(322), Theme.S(380), Theme.S(28));
    desktop.Visible = false;
    bar.SetBounds(Theme.S(21), Theme.S(313), Theme.S(W - 42), Theme.S(24));
    bar.Visible = false;

    main.SetBounds(Theme.S(W - 28 - 190), Theme.S(H - 66), Theme.S(190), Theme.S(42));
    second.SetBounds(Theme.S(W - 28 - 190 - 12 - 120), Theme.S(H - 66), Theme.S(120), Theme.S(42));
    main.Click += OnMain;
    second.Click += delegate { if (!working) Close(); };

    Controls.AddRange(new Control[] { license, log, accept, desktop, bar, main, second });
    Go(Step.License);
    FormClosing += delegate (object s, FormClosingEventArgs e) { if (working) e.Cancel = true; else ApplyShortcutChoice(); };
  }

  static void Frame(TextBox t, Font font, Color ink) {
    t.Multiline = true;
    t.ReadOnly = true;
    t.ScrollBars = ScrollBars.Vertical;
    t.BorderStyle = BorderStyle.None;
    t.BackColor = Theme.Card;
    t.ForeColor = ink;
    t.Font = font;
    t.TabStop = false;
  }

  // ---- Окно без рамки: тень, скруглённые углы Windows 11, перетаскивание за шапку.
  protected override CreateParams CreateParams {
    get { CreateParams cp = base.CreateParams; cp.ClassStyle |= 0x20000; return cp; } // CS_DROPSHADOW
  }

  [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
  [DllImport("user32.dll")] static extern bool ReleaseCapture();
  [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

  protected override void OnHandleCreated(EventArgs e) {
    base.OnHandleCreated(e);
    try { int round = 2; DwmSetWindowAttribute(Handle, 33, ref round, 4); } catch { } // DWMWA_WINDOW_CORNER_PREFERENCE
  }

  Rectangle CloseRect { get { return new Rectangle(Theme.S(W - 46), Theme.S(10), Theme.S(34), Theme.S(30)); } }

  protected override void OnMouseDown(MouseEventArgs e) {
    base.OnMouseDown(e);
    if (e.Button == MouseButtons.Left && e.Y < Theme.S(BANNER) && !CloseRect.Contains(e.Location)) {
      ReleaseCapture();
      SendMessage(Handle, 0xA1, (IntPtr)2, IntPtr.Zero); // WM_NCLBUTTONDOWN, HTCAPTION
    }
  }
  protected override void OnMouseMove(MouseEventArgs e) {
    base.OnMouseMove(e);
    bool h = CloseRect.Contains(e.Location);
    if (h != closeHover) { closeHover = h; Cursor = h && !working ? Cursors.Hand : Cursors.Default; Invalidate(CloseRect); }
  }
  protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); if (closeHover) { closeHover = false; Invalidate(CloseRect); } }
  protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); if (CloseRect.Contains(e.Location) && !working) Close(); }
  protected override void OnKeyDown(KeyEventArgs e) { base.OnKeyDown(e); if (e.KeyCode == Keys.Escape && !working) Close(); }

  // ---- Экраны
  void Go(Step s) {
    step = s;
    license.Visible = s == Step.License;
    accept.Visible = s == Step.License;
    bar.Visible = s == Step.Install;
    desktop.Visible = s == Step.Done;
    log.Visible = s == Step.Error;
    second.Visible = s != Step.Install;
    main.Visible = s != Step.Install;
    if (s == Step.License) { main.Text = Setup.L("Установить", "Install"); main.Enabled = accept.Checked; second.Text = Setup.L("Отмена", "Cancel"); }
    if (s == Step.Done) { main.Text = Setup.L("Запустить Адамант", "Launch Adamant"); main.Enabled = true; second.Text = Setup.L("Закрыть", "Close"); }
    if (s == Step.Error) { main.Text = Setup.L("Повторить", "Retry"); main.Enabled = true; second.Text = Setup.L("Закрыть", "Close"); log.Text = string.Join("\r\n", output.ToArray()); }
    Invalidate();
    if (s == Step.Done || s == Step.Error) main.Focus(); else if (s == Step.License) accept.Focus();
  }

  void OnMain(object sender, EventArgs e) {
    if (step == Step.Done) {
      ApplyShortcutChoice();
      string vbs = Path.Combine(installDir, "windows", "adamant.vbs");
      try { Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "wscript.exe"), "\"" + vbs + "\"") { UseShellExecute = false, WorkingDirectory = installDir }); } catch { }
      Close();
      return;
    }
    if (step == Step.License && !accept.Checked) return;
    working = true;
    output.Clear();
    status = Setup.L("Готовлюсь …", "Getting ready …");
    bar.Value = 0;
    Go(Step.Install);
    new Thread(Install) { IsBackground = true }.Start();
  }

  /// Ярлык на рабочем столе: установщик ставит его всегда, а если галочку сняли - убираем.
  bool shortcutApplied;
  void ApplyShortcutChoice() {
    if (step != Step.Done || shortcutApplied || desktop.Checked) return;
    shortcutApplied = true;
    try {
      string lnk = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Адамант.lnk");
      if (File.Exists(lnk)) File.Delete(lnk);
    } catch { }
  }

  void Progress(float value, string text) {
    if (InvokeRequired) { BeginInvoke(new Action<float, string>(Progress), value, text); return; }
    if (value >= 0) bar.Value = value;
    if (text != null) status = text;
    Invalidate(new Rectangle(0, Theme.S(BANNER + 40), ClientSize.Width, Theme.S(140)));
  }

  /// Строки install-app.ps1 -> понятный шаг и доля готовности.
  void OnScriptLine(string line) {
    output.Add(line);
    string t = line.TrimStart();
    if (t.StartsWith("Остановка")) Progress(.72f, Setup.L("Останавливаю запущенную копию …", "Stopping the running copy …"));
    else if (t.StartsWith("1.")) Progress(.76f, Setup.L("Копирую программу в папку …", "Copying the program …"));
    else if (t.StartsWith("2.")) Progress(.88f, Setup.L("Готовлю папку для данных …", "Preparing the data folder …"));
    else if (t.StartsWith("3.")) Progress(.93f, Setup.L("Создаю ярлыки и запись в «Установленных приложениях» …", "Creating shortcuts and the Installed apps entry …"));
    else if (t.StartsWith("Готово")) Progress(1f, Setup.L("Готово", "Done"));
  }

  void Install() {
    string tmp = Path.Combine(Path.GetTempPath(), "Adamant-setup-" + Guid.NewGuid().ToString("N"));
    string err = null;
    try {
      Directory.CreateDirectory(tmp);
      Progress(.02f, Setup.L("Проверяю архив …", "Checking the archive …"));
      string zip = Path.Combine(tmp, "Adamant.zip");
      Setup.ExtractPayload(zip);
      string dir = Path.Combine(tmp, "x");
      Unpack(zip, dir);
      string script = Setup.InstallScript(dir);
      Progress(.72f, Setup.L("Устанавливаю …", "Installing …"));
      string cmd = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; & '" + script.Replace("'", "''") + "' -NoLaunch; exit $LASTEXITCODE";
      ProcessStartInfo psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + cmd.Replace("\"", "\\\"") + "\"");
      psi.UseShellExecute = false;
      psi.CreateNoWindow = true;
      psi.RedirectStandardOutput = true;
      psi.RedirectStandardError = true;
      psi.StandardOutputEncoding = Encoding.UTF8;
      psi.StandardErrorEncoding = Encoding.UTF8;
      psi.WorkingDirectory = tmp;
      using (Process p = new Process()) {
        p.StartInfo = psi;
        p.OutputDataReceived += delegate (object s, DataReceivedEventArgs a) { if (!string.IsNullOrEmpty(a.Data)) lock (output) OnScriptLine(a.Data); };
        p.ErrorDataReceived += delegate (object s, DataReceivedEventArgs a) { if (!string.IsNullOrEmpty(a.Data)) lock (output) output.Add(a.Data); };
        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        p.WaitForExit();
        if (p.ExitCode != 0) err = Setup.L("Установка не завершена (код ", "Setup did not finish (code ") + p.ExitCode + ").";
      }
    } catch (Exception ex) {
      err = ex.Message;
    } finally {
      try { Directory.Delete(tmp, true); } catch { }
    }
    BeginInvoke(new Action(delegate {
      working = false;
      if (err != null) { error = err; Go(Step.Error); }
      else { bar.Value = 1; Go(Step.Done); }
    }));
  }

  /// Распаковка с настоящим процентом (по объёму файлов) и защитой от путей за пределы папки.
  void Unpack(string zip, string dir) {
    string root = Path.GetFullPath(dir).TrimEnd('\\') + "\\";
    using (ZipArchive z = ZipFile.OpenRead(zip)) {
      long total = 0, done = 0;
      foreach (ZipArchiveEntry e in z.Entries) total += e.Length;
      int i = 0;
      foreach (ZipArchiveEntry e in z.Entries) {
        string target = Path.GetFullPath(Path.Combine(dir, e.FullName.Replace('/', '\\')));
        if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new Exception("bad path in archive: " + e.FullName);
        if (e.FullName.EndsWith("/")) { Directory.CreateDirectory(target); continue; }
        Directory.CreateDirectory(Path.GetDirectoryName(target));
        e.ExtractToFile(target, true);
        done += e.Length;
        if (++i % 3 == 0 || done == total) Progress(.06f + .64f * (total > 0 ? (float)done / total : 1), Setup.L("Распаковываю: ", "Unpacking: ") + e.Name);
      }
    }
  }

  // ---- Рисование
  protected override void OnPaint(PaintEventArgs e) {
    Graphics g = e.Graphics;
    Theme.Smooth(g);
    float w = ClientSize.Width;
    PaintBanner(g, w);
    PaintSteps(g);
    float x = Theme.F(28), y = Theme.F(BANNER + 54);
    switch (step) {
      case Step.License: {
          RectangleF card = new RectangleF(x, Theme.F(212), w - 2 * x, Theme.F(150));
          Card(g, card);
          break;
        }
      case Step.Install: {
          Headline(g, Setup.L("Устанавливаю Адамант", "Installing Adamant"), x, Theme.F(218));
          Line(g, status, Theme.Font(14), Theme.Ink2, x, Theme.F(262), w - 2 * x - Theme.F(70));
          string pct = (int)Math.Round(bar.Value * 100) + "%";
          using (Font f = Theme.Font(22, FontStyle.Regular, "Segoe UI Light"))
            TextRenderer.DrawText(g, pct, f, new Rectangle((int)(w - x - Theme.F(90)), Theme.S(270), Theme.S(90), Theme.S(40)), Theme.Accent, TextFormatFlags.Right | TextFormatFlags.Bottom | TextFormatFlags.SingleLine);
          Line(g, Setup.L("Права администратора не нужны · ничего не скачивается из интернета", "No administrator rights needed · nothing is downloaded from the internet"), Theme.Font(12.5f), Theme.Ink3, x, Theme.F(346), w - 2 * x);
          break;
        }
      case Step.Done: {
          RectangleF c = new RectangleF(x, Theme.F(218), Theme.F(44), Theme.F(44));
          using (SolidBrush br = new SolidBrush(Color.FromArgb(36, Theme.Ok))) g.FillEllipse(br, c);
          using (Pen p = new Pen(Theme.Ok, Theme.F(1.5f))) g.DrawEllipse(p, c);
          Theme.Tick(g, c, Theme.Ok, Theme.F(2.6f));
          Headline(g, Setup.L("Адамант установлен", "Adamant is installed"), x + Theme.F(60), Theme.F(216));
          Line(g, Setup.L("Ярлык - в меню «Пуск». Удалить программу можно в «Параметры» → «Приложения». При первом запуске Адамант сразу проверит компьютер.",
            "The shortcut is in the Start menu. You can remove the program in Settings → Apps. On first launch Adamant checks the computer right away."), Theme.Font(14), Theme.Ink2, x + Theme.F(60), Theme.F(254), w - 2 * x - Theme.F(60));
          break;
        }
      case Step.Error: {
          Headline(g, Setup.L("Установка не завершена", "Setup did not finish"), x, Theme.F(214), Theme.Bad);
          Line(g, error, Theme.Font(14), Theme.Ink2, x, Theme.F(250), w - 2 * x);
          Card(g, new RectangleF(x, Theme.F(270), w - 2 * x, Theme.F(108)));
          break;
        }
    }
    PaintFooter(g, w);
    using (Pen p = new Pen(Theme.Line, 1)) g.DrawRectangle(p, 0, 0, ClientSize.Width - 1, ClientSize.Height - 1);
  }

  void PaintBanner(Graphics g, float w) {
    float bh = Theme.F(BANNER);
    RectangleF r = new RectangleF(0, 0, w, bh);
    if (banner != null) {
      // Картинка целиком по высоте шапки и прижата вправо: Кира с мечом справа, слева тёмный свод под название.
      // Полоса левее картинки - цвет её левого края; шов прячет затемнение ниже.
      using (SolidBrush br = new SolidBrush(Theme.Mix(Theme.Bg, Color.FromArgb(14, 22, 36), .6f))) g.FillRectangle(br, r);
      float dw = Math.Max(w * .78f, banner.Width * bh / banner.Height);
      RectangleF dst = new RectangleF(w - dw, 0, dw, bh);
      float srcH = Math.Min(banner.Height, banner.Width * bh / dw);
      g.DrawImage(banner, dst, new RectangleF(0, (banner.Height - srcH) / 2, banner.Width, srcH), GraphicsUnit.Pixel);
      RectangleF seam = new RectangleF(dst.X - 1, 0, Theme.F(90), bh);
      using (LinearGradientBrush br = new LinearGradientBrush(new RectangleF(seam.X - 1, 0, seam.Width + 2, bh), Theme.Mix(Theme.Bg, Color.FromArgb(14, 22, 36), .6f), Color.FromArgb(0, 14, 22, 36), LinearGradientMode.Horizontal)) g.FillRectangle(br, seam);
    } else using (SolidBrush br = new SolidBrush(Theme.Card)) g.FillRectangle(br, r);
    // Затемнение слева - под текст (Киру справа не трогает), снизу - переход в фон окна.
    RectangleF left = new RectangleF(0, 0, w * .62f, bh);
    using (LinearGradientBrush br = new LinearGradientBrush(new RectangleF(-1, 0, left.Width + 2, bh), Color.FromArgb(200, Theme.Bg), Color.FromArgb(0, Theme.Bg), LinearGradientMode.Horizontal)) g.FillRectangle(br, left);
    RectangleF fade = new RectangleF(0, bh * .55f, w, bh * .45f + 1);
    using (LinearGradientBrush br = new LinearGradientBrush(fade, Color.FromArgb(0, Theme.Bg), Theme.Bg, LinearGradientMode.Vertical)) g.FillRectangle(br, fade);

    // Алмаз со свечением.
    float d = Theme.F(92);
    RectangleF gem = new RectangleF(Theme.F(26), Theme.F(30), d, d);
    using (GraphicsPath gp = new GraphicsPath()) {
      RectangleF glow = RectangleF.Inflate(gem, d * .35f, d * .35f);
      gp.AddEllipse(glow);
      using (PathGradientBrush pb = new PathGradientBrush(gp) { CenterColor = Color.FromArgb(90, Theme.Accent), SurroundColors = new Color[] { Color.FromArgb(0, Theme.Accent) } }) g.FillPath(pb, gp);
    }
    if (diamond != null) g.DrawImage(diamond, gem);

    float tx = gem.Right + Theme.F(18);
    using (Font f = Theme.Font(40, FontStyle.Regular, "Segoe UI Light"))
      TextRenderer.DrawText(g, Setup.L("Адамант", "Adamant"), f, new Point((int)tx, Theme.S(34)), Theme.Ink, TextFormatFlags.NoPadding);
    using (Font f = Theme.Font(14.5f))
      TextRenderer.DrawText(g, Setup.L("Защита компьютера с Windows и своей сети", "Protection for your PC and home network"), f, new Point((int)tx + Theme.S(2), Theme.S(90)), Theme.Ink2, TextFormatFlags.NoPadding);
    using (Font f = Theme.Font(12.5f, FontStyle.Bold, "Segoe UI Semibold")) {
      string tag = Setup.L("Установка · версия ", "Setup · version ") + version;
      Size sz = TextRenderer.MeasureText(tag, f);
      RectangleF pill = new RectangleF(tx + Theme.F(2), Theme.F(116), sz.Width + Theme.F(14), Theme.F(22));
      using (GraphicsPath p = Theme.Round(pill, pill.Height / 2)) {
        using (SolidBrush br = new SolidBrush(Color.FromArgb(150, Theme.Card))) g.FillPath(br, p);
        using (Pen pen = new Pen(Color.FromArgb(90, Theme.Accent), 1)) g.DrawPath(pen, p);
      }
      TextRenderer.DrawText(g, tag, f, Rectangle.Round(pill), Theme.Accent, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
    }

    // Закрыть.
    Rectangle cr = CloseRect;
    if (closeHover && !working) using (GraphicsPath p = Theme.Round(cr, Theme.F(6))) using (SolidBrush br = new SolidBrush(Color.FromArgb(70, 255, 255, 255))) g.FillPath(br, p);
    using (Pen p = new Pen(working ? Theme.Ink3 : Theme.Ink, Theme.F(1.4f))) {
      float c = Theme.F(5.5f);
      PointF o = new PointF(cr.X + cr.Width / 2f, cr.Y + cr.Height / 2f);
      g.DrawLine(p, o.X - c, o.Y - c, o.X + c, o.Y + c);
      g.DrawLine(p, o.X - c, o.Y + c, o.X + c, o.Y - c);
    }
  }

  void PaintSteps(Graphics g) {
    string[] names = { Setup.L("Лицензия", "License"), Setup.L("Установка", "Install"), Setup.L("Готово", "Done") };
    int cur = step == Step.License ? 0 : step == Step.Done ? 2 : 1;
    float x = Theme.F(28), y = Theme.F(BANNER + 10), d = Theme.F(24);
    using (Font num = Theme.Font(12.5f, FontStyle.Bold, "Segoe UI Semibold"))
    using (Font lab = Theme.Font(14, FontStyle.Bold, "Segoe UI Semibold")) {
      for (int i = 0; i < 3; i++) {
        bool done = i < cur || (step == Step.Done && i == 2);
        bool active = i == cur && step != Step.Done;
        bool bad = step == Step.Error && i == 1;
        RectangleF c = new RectangleF(x, y, d, d);
        if (bad) {
          using (Pen p = new Pen(Theme.Bad, Theme.F(1.5f))) g.DrawEllipse(p, c);
          TextRenderer.DrawText(g, "!", num, Rectangle.Round(c), Theme.Bad, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        } else if (done) {
          using (SolidBrush br = new SolidBrush(Color.FromArgb(40, Theme.Ok))) g.FillEllipse(br, c);
          using (Pen p = new Pen(Theme.Ok, Theme.F(1.5f))) g.DrawEllipse(p, c);
          Theme.Tick(g, c, Theme.Ok, Theme.F(2));
        } else if (active) {
          using (LinearGradientBrush br = new LinearGradientBrush(c, Theme.Btn1, Theme.Btn2, LinearGradientMode.Vertical)) g.FillEllipse(br, c);
          using (Pen p = new Pen(Theme.Accent, Theme.F(1.2f))) g.DrawEllipse(p, c);
          TextRenderer.DrawText(g, (i + 1).ToString(), num, Rectangle.Round(c), Color.White, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        } else {
          using (Pen p = new Pen(Theme.Line, Theme.F(1.5f))) g.DrawEllipse(p, c);
          TextRenderer.DrawText(g, (i + 1).ToString(), num, Rectangle.Round(c), Theme.Ink3, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
        Color ink = bad ? Theme.Bad : active ? Theme.Ink : done ? Theme.Ink2 : Theme.Ink3;
        Size sz = TextRenderer.MeasureText(names[i], lab);
        TextRenderer.DrawText(g, names[i], lab, new Point((int)(c.Right + Theme.F(9)), (int)(y + (d - sz.Height) / 2)), ink, TextFormatFlags.NoPadding);
        x = c.Right + Theme.F(9) + sz.Width + Theme.F(14);
        if (i < 2) {
          float len = Theme.F(46);
          using (Pen p = new Pen(i < cur ? Theme.Ok : Theme.Line, Theme.F(1.4f))) g.DrawLine(p, x, y + d / 2, x + len, y + d / 2);
          x += len + Theme.F(14);
        }
      }
    }
  }

  void PaintFooter(Graphics g, float w) {
    float y = Theme.F(H - 66);
    using (Pen p = new Pen(Color.FromArgb(120, Theme.Line), 1)) g.DrawLine(p, Theme.F(28), y - Theme.F(14), w - Theme.F(28), y - Theme.F(14));
    // Замок и «ничего не отправляется».
    float lx = Theme.F(30), ly = y + Theme.F(12);
    using (Pen p = new Pen(Theme.Ink3, Theme.F(1.4f))) {
      g.DrawRectangle(p, lx, ly + Theme.F(7), Theme.F(13), Theme.F(10));
      g.DrawArc(p, lx + Theme.F(2.5f), ly, Theme.F(8), Theme.F(12), 180, 180);
    }
    using (Font f = Theme.Font(12.5f))
      TextRenderer.DrawText(g, Setup.L("Ничего не отправляется в интернет", "Nothing is sent to the internet"), f, new Point((int)(lx + Theme.F(22)), (int)(ly + Theme.F(2))), Theme.Ink3, TextFormatFlags.NoPadding);
  }

  static void Headline(Graphics g, string text, float x, float y) { Headline(g, text, x, y, Theme.Ink); }
  static void Headline(Graphics g, string text, float x, float y, Color c) {
    using (Font f = Theme.Font(24, FontStyle.Regular, "Segoe UI Semilight"))
      TextRenderer.DrawText(g, text, f, new Point((int)x, (int)y), c, TextFormatFlags.NoPadding);
  }

  static void Line(Graphics g, string text, Font f, Color c, float x, float y, float width) {
    using (f) TextRenderer.DrawText(g, text ?? "", f, new Rectangle((int)x, (int)y, (int)width, Theme.S(60)), c, TextFormatFlags.WordBreak | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
  }

  static void Card(Graphics g, RectangleF r) {
    using (GraphicsPath p = Theme.Round(r, Theme.F(10))) {
      using (SolidBrush br = new SolidBrush(Theme.Card)) g.FillPath(br, p);
      using (Pen pen = new Pen(Theme.Line, 1)) g.DrawPath(pen, p);
    }
  }

  // ---- Предпросмотр экранов в картинку (для проверки оформления; ничего не устанавливает).
  public int Preview(string screen, string file) {
    // Окно показывается за пределами экрана, чтобы создались все элементы, и сразу закрывается.
    StartPosition = FormStartPosition.Manual;
    Location = new Point(-20000, -20000);
    ShowInTaskbar = false;
    Show();
    Application.DoEvents();
    if (screen == "install") { working = true; status = Setup.L("Распаковываю: ", "Unpacking: ") + "node.exe"; Go(Step.Install); bar.Freeze(.46f, .5f); working = false; }
    else if (screen == "done") Go(Step.Done);
    else if (screen == "error") { error = Setup.L("Установка не завершена (код 1).", "Setup did not finish (code 1)."); output.Add("1. Копирование программы в C:\\Users\\...\\Programs\\Adamant ..."); output.Add("Установка не завершена: доступ запрещён"); Go(Step.Error); }
    else { accept.Checked = screen == "license-ok"; Go(Step.License); }
    using (Bitmap b = new Bitmap(ClientSize.Width, ClientSize.Height)) {
      DrawToBitmap(b, new Rectangle(0, 0, b.Width, b.Height));
      b.Save(file, ImageFormat.Png);
    }
    return 0;
  }
}
