using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using MelonLoader;
using MelonLoader.Utils;
using BravelyMod.AutoBattle;
using BravelyMod.Patches;

namespace BravelyMod.WebConfig;

/// <summary>
/// Lightweight HTTP server for live mod configuration editing.
/// Listens on http://localhost:8888/ and serves a web UI for editing
/// autobattle profiles and music config without restarting the game.
/// </summary>
public static class ConfigServer
{
    private static HttpListener _listener;
    private static Thread _listenerThread;
    private static volatile bool _running;

    private const int Port = 8888;
    private const string Prefix = "http://localhost:8888/";

    private static string AutoBattleConfigPath =>
        Path.Combine(MelonEnvironment.UserDataDirectory, "BravelyMod_AutoBattle.yaml");

    private static string MusicConfigPath =>
        Path.Combine(MelonEnvironment.UserDataDirectory, "BravelyMod_Music.yaml");

    public static void Start()
    {
        try
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add(Prefix);
            _listener.Start();
            _running = true;

            _listenerThread = new Thread(ListenLoop)
            {
                IsBackground = true,
                Name = "BravelyMod-ConfigServer"
            };
            _listenerThread.Start();

            Melon<Core>.Logger.Msg($"[WebConfig] Server started at {Prefix}");
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[WebConfig] Failed to start server: {ex.Message}");
        }
    }

    public static void Stop()
    {
        _running = false;
        try
        {
            _listener?.Stop();
            _listener?.Close();
        }
        catch { }
        Melon<Core>.Logger.Msg("[WebConfig] Server stopped.");
    }

    private static void ListenLoop()
    {
        while (_running)
        {
            try
            {
                var context = _listener.GetContext();
                ThreadPool.QueueUserWorkItem(_ => HandleRequest(context));
            }
            catch (HttpListenerException) when (!_running)
            {
                // Expected when stopping
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (_running)
                    Melon<Core>.Logger.Warning($"[WebConfig] Listener error: {ex.Message}");
            }
        }
    }

    private static void HandleRequest(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;

        try
        {
            string path = request.Url?.AbsolutePath ?? "/";
            string method = request.HttpMethod;

            string responseBody;
            int statusCode = 200;

            switch (path)
            {
                case "/":
                    responseBody = HandleIndex();
                    break;

                case "/autobattle" when method == "GET":
                    responseBody = HandleAutoBattleGet();
                    break;

                case "/autobattle" when method == "POST":
                    responseBody = HandleAutoBattlePost(request);
                    break;

                case "/music" when method == "GET":
                    responseBody = HandleMusicGet();
                    break;

                case "/music" when method == "POST":
                    responseBody = HandleMusicPost(request);
                    break;

                case "/status":
                    responseBody = HandleStatus();
                    break;

                default:
                    statusCode = 404;
                    responseBody = WrapHtml("Not Found", "<p>Unknown route.</p><p><a href=\"/\">Back to home</a></p>");
                    break;
            }

            response.StatusCode = statusCode;
            response.ContentType = "text/html; charset=utf-8";
            byte[] buffer = Encoding.UTF8.GetBytes(responseBody);
            response.ContentLength64 = buffer.Length;
            response.OutputStream.Write(buffer, 0, buffer.Length);
        }
        catch (Exception ex)
        {
            try
            {
                response.StatusCode = 500;
                byte[] errBytes = Encoding.UTF8.GetBytes($"Internal error: {ex.Message}");
                response.OutputStream.Write(errBytes, 0, errBytes.Length);
            }
            catch { }
        }
        finally
        {
            try { response.OutputStream.Close(); } catch { }
        }
    }

    // ── Route handlers ──────────────────────────────────────────

    private static string HandleIndex()
    {
        return WrapHtml("BravelyMod Live Config", @"
            <h2>Configuration</h2>
            <ul>
                <li><a href=""/autobattle"">AutoBattle Profiles</a> &mdash; edit autobattle YAML rules</li>
                <li><a href=""/music"">Music Overrides</a> &mdash; edit music replacement config</li>
                <li><a href=""/status"">Mod Status</a> &mdash; current hook and mod state</li>
            </ul>
            <p style=""color:#888;"">Changes take effect immediately &mdash; no restart needed.</p>
        ");
    }

    private static string HandleAutoBattleGet(string message = null)
    {
        string yaml = "";
        try
        {
            if (File.Exists(AutoBattleConfigPath))
                yaml = File.ReadAllText(AutoBattleConfigPath);
            else
                yaml = "# No config file found. Save to create one.";
        }
        catch (Exception ex)
        {
            yaml = $"# Error reading file: {ex.Message}";
        }

        string msgHtml = message != null
            ? $"<div class=\"msg\">{WebUtility.HtmlEncode(message)}</div>"
            : "";

        return WrapHtml("AutoBattle Config", $@"
            <h2>AutoBattle Profiles</h2>
            {msgHtml}
            <form method=""POST"" action=""/autobattle"">
                <textarea name=""yaml"" rows=""30"" cols=""90"">{WebUtility.HtmlEncode(yaml)}</textarea>
                <br/>
                <button type=""submit"">Save &amp; Reload</button>
            </form>
            <p><a href=""/"">Back to home</a></p>
        ");
    }

    private static string HandleAutoBattlePost(HttpListenerRequest request)
    {
        string message;
        try
        {
            string body;
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                body = reader.ReadToEnd();
            }

            // Parse form-encoded body: yaml=...
            string yaml = ExtractFormValue(body, "yaml");
            if (yaml == null)
            {
                message = "Error: No YAML content received.";
                return HandleAutoBattleGet(message);
            }

            File.WriteAllText(AutoBattleConfigPath, yaml);

            // Hot-reload into the running rule engine
            ProfileConfig.LoadInto(AutoBattleConfigPath, NativeAutoBattlePatch.RuleEngine);
            message = "Saved and reloaded! New rules active on next autobattle cycle.";
        }
        catch (Exception ex)
        {
            message = $"Error: {ex.Message}";
        }

        return HandleAutoBattleGet(message);
    }

    private static string HandleMusicGet(string message = null)
    {
        string yaml = "";
        try
        {
            if (File.Exists(MusicConfigPath))
                yaml = File.ReadAllText(MusicConfigPath);
            else
                yaml = "# No music config found. Save to create one.";
        }
        catch (Exception ex)
        {
            yaml = $"# Error reading file: {ex.Message}";
        }

        string msgHtml = message != null
            ? $"<div class=\"msg\">{WebUtility.HtmlEncode(message)}</div>"
            : "";

        return WrapHtml("Music Config", $@"
            <h2>Music Overrides</h2>
            {msgHtml}
            <form method=""POST"" action=""/music"">
                <textarea name=""yaml"" rows=""30"" cols=""90"">{WebUtility.HtmlEncode(yaml)}</textarea>
                <br/>
                <button type=""submit"">Save &amp; Reload</button>
            </form>
            <p><a href=""/"">Back to home</a></p>
        ");
    }

    private static string HandleMusicPost(HttpListenerRequest request)
    {
        string message;
        try
        {
            string body;
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                body = reader.ReadToEnd();
            }

            string yaml = ExtractFormValue(body, "yaml");
            if (yaml == null)
            {
                message = "Error: No YAML content received.";
                return HandleMusicGet(message);
            }

            File.WriteAllText(MusicConfigPath, yaml);

            // Hot-reload music config
            NativeMusicPatch.ReloadConfig();
            message = "Saved and reloaded! Music overrides updated.";
        }
        catch (Exception ex)
        {
            message = $"Error: {ex.Message}";
        }

        return HandleMusicGet(message);
    }

    private static string HandleStatus()
    {
        var sb = new StringBuilder();
        sb.Append("<h2>Mod Status</h2>");
        sb.Append("<table>");

        void Row(string label, string value) =>
            sb.Append($"<tr><td><strong>{WebUtility.HtmlEncode(label)}</strong></td><td>{WebUtility.HtmlEncode(value)}</td></tr>");

        Row("Version", "0.2.0");
        Row("EXP Boost", Core.ExpBoostEnabled.Value ? $"x{Core.ExpMultiplier.Value}" : "OFF");
        Row("JP Boost", Core.ExpBoostEnabled.Value ? $"x{Core.JexpMultiplier.Value}" : "OFF");
        Row("Gold Boost", Core.ExpBoostEnabled.Value ? $"x{Core.GoldMultiplier.Value}" : "OFF");
        Row("Damage Cap", Core.DamageCapEnabled.Value ? $"{Core.DamageCapOverride.Value}" : "OFF");
        Row("BP Limit", Core.BpModEnabled.Value ? $"{Core.BpLimitOverride.Value}" : "OFF");
        Row("BP/Turn", $"{Core.BpPerTurn.Value}");
        Row("Battle Speed", Core.SpeedModEnabled.Value ? $"x{Core.BattleSpeedMultiplier.Value}" : "OFF");
        Row("Colony Speed", Core.ColonyModEnabled.Value ? $"x{Core.ColonySpeedMultiplier.Value}" : "OFF");
        Row("Scene Skip", Core.ForceSceneSkip.Value ? "ON" : "OFF");
        Row("Support Cost", Core.SupportCostModEnabled.Value ? $"{Core.SupportCostOverride.Value}" : "OFF");
        Row("Walk Speed", Core.WalkSpeedModEnabled.Value ? $"x{Core.WalkSpeedMultiplier.Value}" : "OFF");
        Row("Custom BGM", Core.CustomBattleMusicEnabled.Value ? "ON" : "OFF");

        // AutoBattle profile info
        var engine = NativeAutoBattlePatch.RuleEngine;
        Row("AutoBattle Profile", engine.ActiveProfileName);
        Row("AutoBattle Profiles", string.Join(", ", engine.ProfileNames));
        for (int i = 0; i < engine.CharacterProfiles.Length; i++)
        {
            var profile = engine.GetProfileForCharacter(i);
            Row($"Slot {i} Profile", profile?.Name ?? "(default)");
        }

        sb.Append("</table>");
        sb.Append("<p><a href=\"/\">Back to home</a></p>");

        return WrapHtml("Mod Status", sb.ToString());
    }

    // ── Utilities ──────────────────────────────────────────────

    /// <summary>
    /// Extract a named value from a URL-encoded form body (key=value&amp;key2=value2).
    /// </summary>
    private static string ExtractFormValue(string formBody, string key)
    {
        if (string.IsNullOrEmpty(formBody)) return null;

        string prefix = key + "=";
        foreach (var pair in formBody.Split('&'))
        {
            if (pair.StartsWith(prefix, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair.Substring(prefix.Length).Replace('+', ' '));
            }
        }
        return null;
    }

    /// <summary>
    /// Wrap body content in a minimal HTML page with inline styles.
    /// </summary>
    private static string WrapHtml(string title, string bodyContent)
    {
        return $@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""utf-8""/>
    <title>{WebUtility.HtmlEncode(title)} - BravelyMod</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; background: #1a1a2e; color: #e0e0e0; }}
        h1, h2 {{ color: #e4a040; }}
        a {{ color: #5dade2; }}
        textarea {{ width: 100%; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; background: #16213e; color: #e0e0e0; border: 1px solid #444; padding: 8px; border-radius: 4px; }}
        button {{ background: #e4a040; color: #1a1a2e; border: none; padding: 10px 24px; font-size: 15px; font-weight: bold; cursor: pointer; border-radius: 4px; margin-top: 8px; }}
        button:hover {{ background: #f0b860; }}
        table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
        td {{ padding: 6px 12px; border-bottom: 1px solid #333; }}
        tr:hover {{ background: #16213e; }}
        .msg {{ background: #0f3460; padding: 10px 16px; border-left: 4px solid #e4a040; margin: 1em 0; border-radius: 4px; }}
        ul {{ line-height: 2; }}
    </style>
</head>
<body>
    <h1>BravelyMod</h1>
    {bodyContent}
</body>
</html>";
    }
}
