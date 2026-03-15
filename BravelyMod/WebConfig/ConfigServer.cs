using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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

    private static string CustomBgmDir
    {
        get
        {
            try { return Path.Combine(UnityEngine.Application.streamingAssetsPath, "CustomBGM"); }
            catch { return ""; }
        }
    }

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
                ThreadPool.QueueUserWorkItem(HandleRequestCallback, context);
            }
            catch (HttpListenerException) when (!_running)
            {
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

    private static void HandleRequestCallback(object state)
    {
        HandleRequest((HttpListenerContext)state);
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
            string contentType = "text/html; charset=utf-8";

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

                case "/autobattle/reload" when method == "POST":
                    responseBody = HandleAutoBattleReload();
                    break;

                case "/autobattle/editor" when method == "GET":
                    responseBody = HandleAutobattleEditor();
                    break;

                case "/autobattle/editor" when method == "POST":
                    responseBody = HandleAutobattleEditorPost(request);
                    break;

                case "/autobattle/editor/api" when method == "GET":
                    responseBody = HandleAutobattleEditorApi();
                    contentType = "application/json; charset=utf-8";
                    break;

                case "/music" when method == "GET":
                    responseBody = HandleMusicGet();
                    break;

                case "/music" when method == "POST":
                    responseBody = HandleMusicPost(request);
                    break;

                case "/music/save" when method == "POST":
                    responseBody = HandleMusicSave(request);
                    contentType = "application/json; charset=utf-8";
                    break;

                case "/music/reload" when method == "POST":
                    responseBody = HandleMusicReload();
                    break;

                case "/music/files" when method == "GET":
                    responseBody = HandleMusicFiles();
                    contentType = "application/json; charset=utf-8";
                    break;

                case "/music/upload" when method == "POST":
                    responseBody = HandleMusicUpload(request);
                    contentType = "application/json; charset=utf-8";
                    break;

                case "/music/convert-status" when method == "GET":
                    responseBody = HandleConvertStatus(request);
                    contentType = "application/json; charset=utf-8";
                    break;

                case "/music/convert-path" when method == "POST":
                    responseBody = HandleConvertFromPath(request);
                    contentType = "application/json; charset=utf-8";
                    break;

                case "/settings" when method == "GET":
                    responseBody = HandleSettingsGet();
                    break;

                case "/settings" when method == "POST":
                    responseBody = HandleSettingsPost(request);
                    break;

                case "/settings/reset" when method == "POST":
                    responseBody = HandleSettingsReset();
                    break;

                case "/status":
                    responseBody = HandleStatus();
                    break;

                case "/api/status":
                    responseBody = HandleApiStatus();
                    contentType = "application/json; charset=utf-8";
                    break;

                default:
                    statusCode = 404;
                    responseBody = WrapHtml("Not Found", "status",
                        "<p>Unknown route.</p><p><a href=\"/\">Back to home</a></p>");
                    break;
            }

            response.StatusCode = statusCode;
            response.ContentType = contentType;
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
        // Build current assignment summary
        var engine = NativeAutoBattlePatch.RuleEngine;
        var charNames = new[] { "Tiz", "Agnes", "Ringabel", "Edea" };
        var assignmentHtml = new StringBuilder();
        for (int i = 0; i < engine.CharacterProfiles.Length && i < charNames.Length; i++)
        {
            var profile = engine.GetProfileForCharacter(i);
            var pName = WebUtility.HtmlEncode(profile?.Name ?? "(default)");
            assignmentHtml.Append($"<span class=\"badge\">{charNames[i]}: {pName}</span> ");
        }

        return WrapHtml("BravelyMod Live Config", "",
            $@"
            <div class=""hero"">
                <h2>Configuration Dashboard</h2>
                <p class=""subtitle"">Edit mod settings live. Changes take effect immediately — no restart needed.</p>
            </div>

            <div class=""card-grid"">
                <a href=""/autobattle"" class=""card"">
                    <div class=""card-icon"">&#9876;</div>
                    <div class=""card-title"">AutoBattle Profiles</div>
                    <div class=""card-desc"">Edit conditional autobattle rules with the DSL editor.<br/>
                    Active: <strong>{WebUtility.HtmlEncode(engine.ActiveProfileName)}</strong></div>
                    <div class=""card-footer"">{assignmentHtml}</div>
                </a>
                <a href=""/music"" class=""card"">
                    <div class=""card-icon"">&#9835;</div>
                    <div class=""card-title"">Music Overrides</div>
                    <div class=""card-desc"">Replace BGM cues with custom HCA audio files.</div>
                    <div class=""card-footer"">Config: BravelyMod_Music.yaml</div>
                </a>
                <a href=""/settings"" class=""card"">
                    <div class=""card-icon"">&#9881;</div>
                    <div class=""card-title"">Settings</div>
                    <div class=""card-desc"">Edit all mod parameters live — multipliers, toggles, speeds, and more.</div>
                    <div class=""card-footer"">Changes apply immediately</div>
                </a>
                <a href=""/status"" class=""card"">
                    <div class=""card-icon"">&#128202;</div>
                    <div class=""card-title"">Mod Status</div>
                    <div class=""card-desc"">View all hooks, multipliers, and current game state.</div>
                    <div class=""card-footer"">v0.2.0</div>
                </a>
            </div>
        ");
    }

    // ── AutoBattle ──────────────────────────────────────────────

    private static string HandleAutoBattleGet(string messageHtml = null)
    {
        string yaml = "";
        try
        {
            if (File.Exists(AutoBattleConfigPath))
                yaml = File.ReadAllText(AutoBattleConfigPath);
            else
            {
                // Pre-fill with a good example
                yaml = GetDefaultAutoBattleYaml();
            }
        }
        catch (Exception ex)
        {
            yaml = $"# Error reading file: {ex.Message}";
        }

        string msgBlock = messageHtml ?? "";

        // Build current assignments table
        var engine = NativeAutoBattlePatch.RuleEngine;
        var charNames = new[] { "Tiz", "Agnes", "Ringabel", "Edea" };
        var assignSb = new StringBuilder();
        assignSb.Append("<table class=\"assign-table\"><tr><th>Character</th><th>Profile</th><th>Rules</th></tr>");
        for (int i = 0; i < engine.CharacterProfiles.Length && i < charNames.Length; i++)
        {
            var profile = engine.GetProfileForCharacter(i);
            var pName = profile?.Name ?? "(default)";
            var ruleCount = profile?.Rules?.Count ?? 0;
            var rulePreview = "";
            if (profile?.Rules != null && profile.Rules.Count > 0)
            {
                rulePreview = string.Join(", ",
                    profile.Rules.Select(r => r.ToShortString()).Take(3));
                if (profile.Rules.Count > 3) rulePreview += ", ...";
            }
            assignSb.Append($@"<tr>
                <td><strong>{charNames[i]}</strong></td>
                <td>{WebUtility.HtmlEncode(pName)}</td>
                <td class=""mono"">{WebUtility.HtmlEncode(rulePreview)}</td>
            </tr>");
        }
        assignSb.Append("</table>");

        return WrapHtml("AutoBattle Config", "autobattle", $@"
            <h2>AutoBattle Profiles</h2>
            <p class=""subtitle"">Edit conditional autobattle rules using the DSL below. First matching rule wins (top to bottom).</p>

            {msgBlock}

            <div class=""section-label"">Current Assignments</div>
            {assignSb}

            <div class=""editor-layout"">
                <div class=""editor-main"">
                    <div class=""section-label"">YAML Config Editor</div>
                    <form method=""POST"" action=""/autobattle"" id=""abForm"">
                        <textarea name=""yaml"" id=""yamlEditor"" rows=""28"" spellcheck=""false"">{WebUtility.HtmlEncode(yaml)}</textarea>
                        <div class=""btn-row"">
                            <button type=""submit"" class=""btn-primary"">Save &amp; Reload</button>
                            <button type=""button"" class=""btn-secondary"" onclick=""doReload()"">Reload from Disk</button>
                        </div>
                    </form>
                </div>
                <div class=""editor-sidebar"">
                    <div class=""section-label"">DSL Cheat Sheet</div>
                    <div class=""cheatsheet"">
                        <div class=""cs-section"">
                            <div class=""cs-title"">Rule Format</div>
                            <code>conditions &#8594; actions</code>
                        </div>
                        <div class=""cs-section"">
                            <div class=""cs-title"">Conditions</div>
                            <table class=""cs-table"">
                                <tr><td class=""mono"">HP &lt; N%</td><td>HP below N%</td></tr>
                                <tr><td class=""mono"">MP &lt; N%</td><td>MP below N%</td></tr>
                                <tr><td class=""mono"">BP &gt; N</td><td>BP above N</td></tr>
                                <tr><td class=""mono"">Foes = N</td><td>Exactly N enemies alive</td></tr>
                                <tr><td class=""mono"">Allies &lt; N</td><td>Fewer than N allies</td></tr>
                                <tr><td class=""mono"">Turn &gt; N</td><td>After turn N</td></tr>
                                <tr><td class=""mono"">(empty)</td><td>Always (fallback)</td></tr>
                            </table>
                            <p class=""cs-note"">Join with <code>&amp;</code> for AND: <code>HP &lt; 30% &amp; Foes = 1</code></p>
                            <p class=""cs-note"">Operators: <code>&lt; &lt;= = &gt;= &gt; !=</code></p>
                        </div>
                        <div class=""cs-section"">
                            <div class=""cs-title"">Actions</div>
                            <table class=""cs-table"">
                                <tr><td class=""mono"">Atk Weak</td><td>Attack weakest enemy</td></tr>
                                <tr><td class=""mono"">Atk Strong</td><td>Attack strongest enemy</td></tr>
                                <tr><td class=""mono"">Atk Random</td><td>Attack random enemy</td></tr>
                                <tr><td class=""mono"">Cure Self</td><td>Heal self (ability #1)</td></tr>
                                <tr><td class=""mono"">Cure Ally</td><td>Heal weakest ally</td></tr>
                                <tr><td class=""mono"">Guard</td><td>Defend</td></tr>
                                <tr><td class=""mono"">Default</td><td>Original game behavior</td></tr>
                                <tr><td class=""mono"">Abl N Target</td><td>Use ability #N</td></tr>
                                <tr><td class=""mono"">Item N Target</td><td>Use item #N</td></tr>
                            </table>
                            <p class=""cs-note"">Add <code>xN</code> to repeat: <code>Atk Weak x4</code></p>
                            <p class=""cs-note"">Comma-separate multiple: <code>Cure Self, Atk Weak x3</code></p>
                        </div>
                        <div class=""cs-section"">
                            <div class=""cs-title"">Arrow Variants</div>
                            <p class=""cs-note""><code>&#8594;</code> or <code>-&gt;</code> or <code>=&gt;</code></p>
                        </div>
                        <div class=""cs-section"">
                            <div class=""cs-title"">Examples</div>
                            <pre class=""cs-example"">&#8594; Atk Weak x4
HP &lt; 30% &#8594; Cure Self
BP &gt; 2 &amp; HP &gt; 50% &#8594; Atk Strong x4
Foes = 1 &#8594; Atk Strong x4
HP &lt; 50% &#8594; Cure Ally, Atk Strong x2</pre>
                        </div>
                    </div>
                </div>
            </div>

            <script>
            function doReload() {{
                fetch('/autobattle/reload', {{method:'POST'}}).then(()=>location.reload());
            }}
            </script>
        ");
    }

    private static string HandleAutoBattlePost(HttpListenerRequest request)
    {
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
                return HandleAutoBattleGet(MsgBox("Error: No YAML content received.", "error"));
            }

            // Validate before saving
            var (errors, summaries) = ProfileConfig.ValidateConfigDetailed(yaml);

            if (errors.Count > 0)
            {
                var sb = new StringBuilder();
                sb.Append(MsgBoxOpen("error"));
                sb.Append("<strong>Validation failed — not saved.</strong><ul>");
                foreach (var err in errors)
                    sb.Append($"<li>{WebUtility.HtmlEncode(err)}</li>");
                sb.Append("</ul>");
                if (summaries.Count > 0)
                {
                    sb.Append("<strong>Partial results:</strong><ul>");
                    foreach (var s in summaries)
                        sb.Append($"<li>{WebUtility.HtmlEncode(s)}</li>");
                    sb.Append("</ul>");
                }
                sb.Append(MsgBoxClose());
                // Return the form with the invalid YAML still showing, plus errors
                return HandleAutoBattleGetWithContent(yaml, sb.ToString());
            }

            // Valid — save and reload
            File.WriteAllText(AutoBattleConfigPath, yaml);
            ProfileConfig.LoadInto(AutoBattleConfigPath, NativeAutoBattlePatch.RuleEngine);

            var successSb = new StringBuilder();
            successSb.Append(MsgBoxOpen("success"));
            successSb.Append("<strong>Saved and reloaded!</strong> New rules active on next autobattle cycle.");
            if (summaries.Count > 0)
            {
                successSb.Append("<ul>");
                foreach (var s in summaries)
                    successSb.Append($"<li>{WebUtility.HtmlEncode(s)}</li>");
                successSb.Append("</ul>");
            }
            successSb.Append(MsgBoxClose());

            return HandleAutoBattleGet(successSb.ToString());
        }
        catch (Exception ex)
        {
            return HandleAutoBattleGet(MsgBox($"Error: {ex.Message}", "error"));
        }
    }

    /// <summary>
    /// Render the autobattle page with specific YAML content (for showing invalid content after failed validation).
    /// </summary>
    private static string HandleAutoBattleGetWithContent(string yaml, string messageHtml)
    {
        // Build current assignments table
        var engine = NativeAutoBattlePatch.RuleEngine;
        var charNames = new[] { "Tiz", "Agnes", "Ringabel", "Edea" };
        var assignSb = new StringBuilder();
        assignSb.Append("<table class=\"assign-table\"><tr><th>Character</th><th>Profile</th><th>Rules</th></tr>");
        for (int i = 0; i < engine.CharacterProfiles.Length && i < charNames.Length; i++)
        {
            var profile = engine.GetProfileForCharacter(i);
            var pName = profile?.Name ?? "(default)";
            var ruleCount = profile?.Rules?.Count ?? 0;
            var rulePreview = "";
            if (profile?.Rules != null && profile.Rules.Count > 0)
            {
                rulePreview = string.Join(", ",
                    profile.Rules.Select(r => r.ToShortString()).Take(3));
                if (profile.Rules.Count > 3) rulePreview += ", ...";
            }
            assignSb.Append($@"<tr>
                <td><strong>{charNames[i]}</strong></td>
                <td>{WebUtility.HtmlEncode(pName)}</td>
                <td class=""mono"">{WebUtility.HtmlEncode(rulePreview)}</td>
            </tr>");
        }
        assignSb.Append("</table>");

        return WrapHtml("AutoBattle Config", "autobattle", $@"
            <h2>AutoBattle Profiles</h2>
            <p class=""subtitle"">Edit conditional autobattle rules using the DSL below. First matching rule wins (top to bottom).</p>

            {messageHtml}

            <div class=""section-label"">Current Assignments (on disk)</div>
            {assignSb}

            <div class=""editor-layout"">
                <div class=""editor-main"">
                    <div class=""section-label"">YAML Config Editor</div>
                    <form method=""POST"" action=""/autobattle"" id=""abForm"">
                        <textarea name=""yaml"" id=""yamlEditor"" rows=""28"" spellcheck=""false"">{WebUtility.HtmlEncode(yaml)}</textarea>
                        <div class=""btn-row"">
                            <button type=""submit"" class=""btn-primary"">Save &amp; Reload</button>
                            <button type=""button"" class=""btn-secondary"" onclick=""doReload()"">Reload from Disk</button>
                        </div>
                    </form>
                </div>
                <div class=""editor-sidebar"">
                    <div class=""section-label"">DSL Cheat Sheet</div>
                    <div class=""cheatsheet"">
                        <div class=""cs-section"">
                            <div class=""cs-title"">Rule Format</div>
                            <code>conditions &#8594; actions</code>
                        </div>
                        <div class=""cs-section"">
                            <div class=""cs-title"">Conditions</div>
                            <table class=""cs-table"">
                                <tr><td class=""mono"">HP &lt; N%</td><td>HP below N%</td></tr>
                                <tr><td class=""mono"">MP &lt; N%</td><td>MP below N%</td></tr>
                                <tr><td class=""mono"">BP &gt; N</td><td>BP above N</td></tr>
                                <tr><td class=""mono"">Foes = N</td><td>Exactly N enemies alive</td></tr>
                                <tr><td class=""mono"">Allies &lt; N</td><td>Fewer than N allies</td></tr>
                                <tr><td class=""mono"">Turn &gt; N</td><td>After turn N</td></tr>
                                <tr><td class=""mono"">(empty)</td><td>Always (fallback)</td></tr>
                            </table>
                            <p class=""cs-note"">Join with <code>&amp;</code> for AND: <code>HP &lt; 30% &amp; Foes = 1</code></p>
                            <p class=""cs-note"">Operators: <code>&lt; &lt;= = &gt;= &gt; !=</code></p>
                        </div>
                        <div class=""cs-section"">
                            <div class=""cs-title"">Actions</div>
                            <table class=""cs-table"">
                                <tr><td class=""mono"">Atk Weak</td><td>Attack weakest enemy</td></tr>
                                <tr><td class=""mono"">Atk Strong</td><td>Attack strongest enemy</td></tr>
                                <tr><td class=""mono"">Atk Random</td><td>Attack random enemy</td></tr>
                                <tr><td class=""mono"">Cure Self</td><td>Heal self (ability #1)</td></tr>
                                <tr><td class=""mono"">Cure Ally</td><td>Heal weakest ally</td></tr>
                                <tr><td class=""mono"">Guard</td><td>Defend</td></tr>
                                <tr><td class=""mono"">Default</td><td>Original game behavior</td></tr>
                                <tr><td class=""mono"">Abl N Target</td><td>Use ability #N</td></tr>
                                <tr><td class=""mono"">Item N Target</td><td>Use item #N</td></tr>
                            </table>
                            <p class=""cs-note"">Add <code>xN</code> to repeat: <code>Atk Weak x4</code></p>
                            <p class=""cs-note"">Comma-separate multiple: <code>Cure Self, Atk Weak x3</code></p>
                        </div>
                        <div class=""cs-section"">
                            <div class=""cs-title"">Arrow Variants</div>
                            <p class=""cs-note""><code>&#8594;</code> or <code>-&gt;</code> or <code>=&gt;</code></p>
                        </div>
                        <div class=""cs-section"">
                            <div class=""cs-title"">Examples</div>
                            <pre class=""cs-example"">&#8594; Atk Weak x4
HP &lt; 30% &#8594; Cure Self
BP &gt; 2 &amp; HP &gt; 50% &#8594; Atk Strong x4
Foes = 1 &#8594; Atk Strong x4
HP &lt; 50% &#8594; Cure Ally, Atk Strong x2</pre>
                        </div>
                    </div>
                </div>
            </div>

            <script>
            function doReload() {{
                fetch('/autobattle/reload', {{method:'POST'}}).then(()=>location.reload());
            }}
            </script>
        ");
    }

    private static string HandleAutoBattleReload()
    {
        try
        {
            if (File.Exists(AutoBattleConfigPath))
            {
                ProfileConfig.LoadInto(AutoBattleConfigPath, NativeAutoBattlePatch.RuleEngine);
            }
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[WebConfig] Reload error: {ex.Message}");
        }
        return HandleAutoBattleGet(MsgBox("Reloaded config from disk.", "success"));
    }

    // ── AutoBattle Visual Editor ─────────────────────────────────

    /// <summary>
    /// Return the current config as JSON for the editor's initial state.
    /// </summary>
    private static string HandleAutobattleEditorApi()
    {
        try
        {
            AutoBattleConfigDto dto;
            if (File.Exists(AutoBattleConfigPath))
            {
                string yaml = File.ReadAllText(AutoBattleConfigPath);
                var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
                    .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.CamelCaseNamingConvention.Instance)
                    .IgnoreUnmatchedProperties()
                    .Build();
                dto = deserializer.Deserialize<AutoBattleConfigDto>(yaml) ?? ProfileConfig.GetDefaultConfig();
            }
            else
            {
                dto = ProfileConfig.GetDefaultConfig();
            }

            var sb = new StringBuilder();
            sb.Append("{");
            sb.Append($"\"activeProfile\":\"{EscapeJson(dto.ActiveProfile ?? "")}\"");
            sb.Append(",\"profiles\":{");
            bool firstProfile = true;
            foreach (var kv in dto.Profiles)
            {
                if (!firstProfile) sb.Append(",");
                firstProfile = false;
                sb.Append($"\"{EscapeJson(kv.Key)}\":[");
                bool firstRule = true;
                if (kv.Value != null)
                {
                    foreach (var rule in kv.Value)
                    {
                        if (!firstRule) sb.Append(",");
                        firstRule = false;
                        sb.Append($"\"{EscapeJson(rule)}\"");
                    }
                }
                sb.Append("]");
            }
            sb.Append("}");
            sb.Append(",\"assignments\":[");
            if (dto.Assignments != null)
            {
                for (int i = 0; i < dto.Assignments.Count; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.Append($"\"{EscapeJson(dto.Assignments[i])}\"");
                }
            }
            sb.Append("]");
            sb.Append("}");
            return sb.ToString();
        }
        catch (Exception ex)
        {
            return $"{{\"error\":\"{EscapeJson(ex.Message)}\"}}";
        }
    }

    /// <summary>
    /// Handle POST from the visual editor.
    /// </summary>
    private static string HandleAutobattleEditorPost(HttpListenerRequest request)
    {
        try
        {
            string body;
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                body = reader.ReadToEnd();
            }

            string yamlContent = body.StartsWith("yaml=") ? ExtractFormValue(body, "yaml") : body;

            if (string.IsNullOrWhiteSpace(yamlContent))
            {
                return HandleAutobattleEditor(MsgBox("Error: No content received.", "error"));
            }

            var (errors, summaries) = ProfileConfig.ValidateConfigDetailed(yamlContent);
            if (errors.Count > 0)
            {
                var sb = new StringBuilder();
                sb.Append(MsgBoxOpen("error"));
                sb.Append("<strong>Validation failed — not saved.</strong><ul>");
                foreach (var err in errors)
                    sb.Append($"<li>{WebUtility.HtmlEncode(err)}</li>");
                sb.Append("</ul>");
                sb.Append(MsgBoxClose());
                return HandleAutobattleEditor(sb.ToString());
            }

            File.WriteAllText(AutoBattleConfigPath, yamlContent);
            ProfileConfig.LoadInto(AutoBattleConfigPath, NativeAutoBattlePatch.RuleEngine);

            var successSb = new StringBuilder();
            successSb.Append(MsgBoxOpen("success"));
            successSb.Append("<strong>Saved and reloaded!</strong> New rules active on next autobattle cycle.");
            if (summaries.Count > 0)
            {
                successSb.Append("<ul>");
                foreach (var s in summaries)
                    successSb.Append($"<li>{WebUtility.HtmlEncode(s)}</li>");
                successSb.Append("</ul>");
            }
            successSb.Append(MsgBoxClose());
            return HandleAutobattleEditor(successSb.ToString());
        }
        catch (Exception ex)
        {
            return HandleAutobattleEditor(MsgBox($"Error: {ex.Message}", "error"));
        }
    }

    /// <summary>
    /// Render the visual autobattle rule editor page.
    /// </summary>
    private static string HandleAutobattleEditor(string messageHtml = null)
    {
        string msgBlock = messageHtml ?? "";
        string editorScript = GetAutobattleEditorScript();

        return WrapHtml("AutoBattle Editor", "autobattle-editor",
            msgBlock + GetAutobattleEditorHtml() + editorScript);
    }

    /// <summary>
    /// Static HTML body for the autobattle editor (no interpolation needed).
    /// </summary>
    private static string GetAutobattleEditorHtml()
    {
        return @"
            <h2>AutoBattle Rule Editor</h2>
            <p class=""subtitle"">Visual rule editor — build conditional autobattle profiles per character.
            <br/><a href=""/autobattle"">Switch to Advanced YAML Editor</a></p>

            <div id=""editorApp"">
                <div class=""ab-toolbar"">
                    <div class=""ab-toolbar-left"">
                        <label class=""ab-label"">Party Profile:</label>
                        <select id=""partyProfileSelect"" class=""ab-select"" onchange=""loadPartyProfile()"">
                            <option value=""__current__"">Current Config</option>
                        </select>
                        <button type=""button"" class=""btn-sm btn-set"" onclick=""savePartyProfile()"">Save as Party Profile</button>
                        <button type=""button"" class=""btn-sm btn-set"" onclick=""newPartyProfile()"">New Party Profile</button>
                    </div>
                    <div class=""ab-toolbar-right"">
                        <button type=""button"" class=""btn-primary"" onclick=""saveAll()"">Save &amp; Reload</button>
                        <button type=""button"" class=""btn-secondary"" onclick=""reloadFromDisk()"">Reload from Disk</button>
                    </div>
                </div>

                <div id=""charCards"" class=""ab-char-grid""></div>

                <div class=""ab-profiles-section"">
                    <div class=""section-label"">Rule Profiles</div>
                    <div class=""ab-profile-toolbar"">
                        <button type=""button"" class=""btn-sm btn-set"" onclick=""addProfile()"">+ New Profile</button>
                    </div>
                    <div id=""profileCards"" class=""ab-profile-grid""></div>
                </div>

                <details class=""ab-yaml-preview"">
                    <summary>YAML Preview</summary>
                    <pre id=""yamlPreview"" class=""cs-example"" style=""max-height:400px;overflow:auto;""></pre>
                </details>
            </div>
        " + GetAutobattleEditorCss();
    }

    /// <summary>
    /// CSS styles for the autobattle editor (non-interpolated verbatim string).
    /// </summary>
    private static string GetAutobattleEditorCss()
    {
        return @"
            <style>
                .ab-toolbar {
                    display: flex; justify-content: space-between; align-items: center;
                    flex-wrap: wrap; gap: 0.8em; margin-bottom: 1.2em; padding: 0.8em 1em;
                    background: #16162a; border: 1px solid #2a2a44; border-radius: 8px;
                }
                .ab-toolbar-left, .ab-toolbar-right { display: flex; align-items: center; gap: 0.6em; flex-wrap: wrap; }
                .ab-label { color: #7777a0; font-size: 0.9em; font-weight: 600; }
                .ab-select {
                    background: #12122a; color: #d0d0d8; border: 1px solid #333355;
                    padding: 6px 10px; border-radius: 4px; font-size: 0.9em; min-width: 160px;
                }
                .ab-select:focus { outline: none; border-color: #e4a040; }
                .ab-char-grid {
                    display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                    gap: 1em; margin-bottom: 1.5em;
                }
                .ab-char-card {
                    background: #16162a; border: 1px solid #2a2a44; border-radius: 8px; padding: 1em;
                }
                .ab-char-header {
                    display: flex; justify-content: space-between; align-items: center;
                    margin-bottom: 0.8em; padding-bottom: 0.5em; border-bottom: 1px solid #2a2a44;
                }
                .ab-char-name { font-size: 1.1em; font-weight: 700; color: #e4a040; }
                .ab-char-profile-select {
                    background: #12122a; color: #d0d0d8; border: 1px solid #333355;
                    padding: 4px 8px; border-radius: 4px; font-size: 0.85em;
                }
                .ab-char-profile-select:focus { outline: none; border-color: #e4a040; }
                .ab-rule-list { list-style: none; padding: 0; margin: 0; }
                .ab-rule-item {
                    display: flex; align-items: flex-start; gap: 0.4em; padding: 0.5em 0;
                    border-bottom: 1px solid #1a1a30; font-size: 0.85em;
                }
                .ab-rule-item:last-child { border-bottom: none; }
                .ab-rule-num { color: #666688; font-weight: 600; min-width: 1.5em; text-align: right; flex-shrink: 0; padding-top: 0.25em; }
                .ab-rule-dsl { font-family: 'Consolas', 'Courier New', monospace; color: #a0c8e0; flex: 1; word-break: break-word; }
                .ab-rule-actions { display: flex; gap: 0.2em; flex-shrink: 0; }
                .ab-btn-icon {
                    background: transparent; border: 1px solid #333355; color: #7777a0;
                    width: 24px; height: 24px; border-radius: 3px; cursor: pointer;
                    display: flex; align-items: center; justify-content: center;
                    font-size: 0.8em; padding: 0; transition: color 0.15s, border-color 0.15s;
                }
                .ab-btn-icon:hover { color: #d0d0d8; border-color: #5dade2; }
                .ab-btn-icon.ab-btn-delete:hover { color: #e74c3c; border-color: #e74c3c; }
                .ab-add-rule {
                    width: 100%; margin-top: 0.5em; padding: 6px; background: transparent;
                    border: 1px dashed #333355; color: #5dade2; border-radius: 4px;
                    cursor: pointer; font-size: 0.85em; transition: border-color 0.15s, color 0.15s;
                }
                .ab-add-rule:hover { border-color: #5dade2; color: #70c0e8; }
                .ab-profiles-section { margin-top: 1.5em; padding-top: 1em; border-top: 1px solid #2a2a44; }
                .ab-profile-toolbar { margin-bottom: 0.8em; }
                .ab-profile-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1em; }
                .ab-profile-card { background: #12122a; border: 1px solid #2a2a44; border-radius: 6px; padding: 0.8em 1em; }
                .ab-profile-card.ab-profile-active { border-color: #e4a040; }
                .ab-profile-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5em; }
                .ab-profile-name { font-weight: 700; color: #e4a040; font-size: 0.95em; }
                .ab-profile-badge { font-size: 0.7em; padding: 2px 6px; border-radius: 3px; background: #0a2a1a; color: #2ecc71; font-weight: 600; }
                .ab-modal-overlay {
                    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
                    background: rgba(0,0,0,0.7); z-index: 200;
                    display: flex; align-items: center; justify-content: center;
                }
                .ab-modal {
                    background: #16162a; border: 1px solid #e4a040; border-radius: 10px;
                    padding: 1.5em; min-width: 500px; max-width: 90vw; max-height: 85vh;
                    overflow-y: auto; box-shadow: 0 10px 40px rgba(0,0,0,0.5);
                }
                .ab-modal h3 { color: #e4a040; margin-top: 0; margin-bottom: 1em; }
                .ab-modal-section { margin-bottom: 1.2em; }
                .ab-modal-section-title { font-size: 0.8em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: #7777a0; margin-bottom: 0.5em; }
                .ab-cond-row, .ab-action-row { display: flex; align-items: center; gap: 0.5em; margin-bottom: 0.4em; flex-wrap: wrap; }
                .ab-cond-row select, .ab-action-row select, .ab-cond-row input, .ab-action-row input {
                    background: #12122a; color: #d0d0d8; border: 1px solid #333355;
                    padding: 5px 8px; border-radius: 4px; font-size: 0.9em;
                }
                .ab-cond-row select:focus, .ab-action-row select:focus, .ab-cond-row input:focus, .ab-action-row input:focus { outline: none; border-color: #e4a040; }
                .ab-cond-row input[type=""number""] { width: 70px; }
                .ab-modal-btn-row { display: flex; justify-content: flex-end; gap: 0.6em; margin-top: 1.5em; padding-top: 1em; border-top: 1px solid #2a2a44; }
                .ab-dsl-preview {
                    font-family: 'Consolas', 'Courier New', monospace; background: #0f0f1a;
                    padding: 0.6em 1em; border-radius: 4px; color: #a0c8e0; font-size: 0.9em;
                    margin-top: 0.8em; border: 1px solid #2a2a44;
                }
                .ab-yaml-preview { margin-top: 1.5em; padding: 0.5em 0; }
                .ab-yaml-preview summary { cursor: pointer; color: #7777a0; font-size: 0.9em; font-weight: 600; }
                .ab-yaml-preview summary:hover { color: #d0d0d8; }
                .ab-warning { display: inline-block; color: #e4a040; font-size: 0.8em; cursor: help; }
            </style>
        ";
    }

    /// <summary>
    /// JavaScript for the autobattle visual editor (non-interpolated verbatim string
    /// to avoid conflicts with C# string interpolation).
    /// </summary>
    private static string GetAutobattleEditorScript()
    {
        return @"
            <script>
            // ── State ──
            var CHAR_NAMES = ['Tiz', 'Agnes', 'Ringabel', 'Edea'];
            var CONDITION_TYPES = ['Always','HP','MP','BP','Foes','Allies','Turn'];
            var OPERATORS = ['<','<=','=','>=','>','!='];
            var ACTION_TYPES = ['Atk Weak','Atk Strong','Atk Random','Cure Self','Cure Ally','Guard','Default'];
            var PERCENT_CONDITIONS = { 'HP':true, 'MP':true };

            var state = {
                activeProfile: 'Attack 4x',
                profiles: {},
                assignments: ['Attack 4x','Attack 4x','Attack 4x','Attack 4x'],
                partyProfiles: {}
            };

            // ── Load from server ──
            function loadState() {
                var xhr = new XMLHttpRequest();
                xhr.open('GET', '/autobattle/editor/api', true);
                xhr.onload = function() {
                    if (xhr.status === 200) {
                        try {
                            var data = JSON.parse(xhr.responseText);
                            if (data.error) { console.error(data.error); return; }
                            state.activeProfile = data.activeProfile || '';
                            state.profiles = data.profiles || {};
                            state.assignments = data.assignments || [];
                            while (state.assignments.length < 4) state.assignments.push(state.activeProfile || 'Default');
                            state.partyProfiles = data.partyProfiles || {};
                        } catch(e) { console.error('Parse error:', e); }
                    }
                    renderAll();
                };
                xhr.send();
            }

            // ── Rendering ──
            function renderAll() {
                renderCharCards();
                renderProfileCards();
                renderYamlPreview();
            }

            function escHtml(s) {
                if (!s) return '';
                var d = document.createElement('div');
                d.appendChild(document.createTextNode(s));
                return d.innerHTML;
            }

            function escAttr(s) {
                return escHtml(s).replace(/'/g, '&#39;').replace(/""/g, '&quot;');
            }

            function renderCharCards() {
                var container = document.getElementById('charCards');
                container.innerHTML = '';
                var profileNames = Object.keys(state.profiles);

                for (var i = 0; i < 4; i++) {
                    var assigned = state.assignments[i] || state.activeProfile || '';
                    var rules = state.profiles[assigned] || [];

                    var optionsHtml = '';
                    for (var pi = 0; pi < profileNames.length; pi++) {
                        var n = profileNames[pi];
                        optionsHtml += '<option value=""' + escAttr(n) + '""' + (n === assigned ? ' selected' : '') + '>' + escHtml(n) + '</option>';
                    }

                    var rulesHtml = '';
                    for (var ri = 0; ri < rules.length; ri++) {
                        rulesHtml += '<li class=""ab-rule-item"">' +
                            '<span class=""ab-rule-num"">' + (ri+1) + '</span>' +
                            '<span class=""ab-rule-dsl"">' + escHtml(rules[ri] || '(empty)') + '</span>' +
                            '<span class=""ab-rule-actions"">' +
                            '<button class=""ab-btn-icon"" onclick=""editRule(' + i + ',' + ri + ')"" title=""Edit"">&#9998;</button>' +
                            '<button class=""ab-btn-icon"" onclick=""moveRule(' + i + ',' + ri + ',-1)"" title=""Move up"">&uarr;</button>' +
                            '<button class=""ab-btn-icon"" onclick=""moveRule(' + i + ',' + ri + ',1)"" title=""Move down"">&darr;</button>' +
                            '<button class=""ab-btn-icon ab-btn-delete"" onclick=""deleteRule(' + i + ',' + ri + ')"" title=""Delete"">&times;</button>' +
                            '</span></li>';
                    }

                    if (!rulesHtml) {
                        rulesHtml = '<li class=""ab-rule-item""><span class=""ab-rule-dsl"" style=""color:#666688"">(no rules — uses default behavior)</span></li>';
                    }

                    var card = document.createElement('div');
                    card.className = 'ab-char-card';
                    card.innerHTML =
                        '<div class=""ab-char-header"">' +
                        '<span class=""ab-char-name"">' + CHAR_NAMES[i] + '</span>' +
                        '<select class=""ab-char-profile-select"" onchange=""assignProfile(' + i + ', this.value)"">' + optionsHtml + '</select>' +
                        '</div>' +
                        '<ul class=""ab-rule-list"">' + rulesHtml + '</ul>' +
                        '<button class=""ab-add-rule"" onclick=""addRule(' + i + ')"">+ Add Rule</button>';
                    container.appendChild(card);
                }
            }

            function renderProfileCards() {
                var container = document.getElementById('profileCards');
                container.innerHTML = '';
                var profileNames = Object.keys(state.profiles);

                for (var pi = 0; pi < profileNames.length; pi++) {
                    var name = profileNames[pi];
                    var rules = state.profiles[name] || [];
                    var isActive = (name === state.activeProfile);
                    var assignedChars = [];
                    for (var ai = 0; ai < state.assignments.length; ai++) {
                        if (state.assignments[ai] === name) assignedChars.push(CHAR_NAMES[ai]);
                    }

                    var rulesHtml = '';
                    for (var ri = 0; ri < rules.length; ri++) {
                        rulesHtml += '<li class=""ab-rule-item"">' +
                            '<span class=""ab-rule-num"">' + (ri+1) + '</span>' +
                            '<span class=""ab-rule-dsl"">' + escHtml(rules[ri] || '(empty)') + '</span>' +
                            '<span class=""ab-rule-actions"">' +
                            '<button class=""ab-btn-icon"" onclick=""editProfileRule(\'' + escAttr(name) + '\', ' + ri + ')"" title=""Edit"">&#9998;</button>' +
                            '<button class=""ab-btn-icon"" onclick=""moveProfileRule(\'' + escAttr(name) + '\', ' + ri + ', -1)"" title=""Move up"">&uarr;</button>' +
                            '<button class=""ab-btn-icon"" onclick=""moveProfileRule(\'' + escAttr(name) + '\', ' + ri + ', 1)"" title=""Move down"">&darr;</button>' +
                            '<button class=""ab-btn-icon ab-btn-delete"" onclick=""deleteProfileRule(\'' + escAttr(name) + '\', ' + ri + ')"" title=""Delete"">&times;</button>' +
                            '</span></li>';
                    }
                    if (!rulesHtml) {
                        rulesHtml = '<li class=""ab-rule-item""><span class=""ab-rule-dsl"" style=""color:#666688"">(empty profile — default behavior)</span></li>';
                    }

                    var badgeHtml = '';
                    if (isActive) badgeHtml += '<span class=""ab-profile-badge"">Active</span> ';
                    if (assignedChars.length > 0) badgeHtml += '<span class=""ab-profile-badge"">' + assignedChars.join(', ') + '</span>';

                    var deleteBtn = profileNames.length > 1
                        ? '<button class=""ab-btn-icon ab-btn-delete"" onclick=""deleteProfile(\'' + escAttr(name) + '\')"" title=""Delete"">&times;</button>'
                        : '';

                    var card = document.createElement('div');
                    card.className = 'ab-profile-card' + (isActive ? ' ab-profile-active' : '');
                    card.innerHTML =
                        '<div class=""ab-profile-header"">' +
                        '<span class=""ab-profile-name"">' + escHtml(name) + '</span>' +
                        '<span>' + badgeHtml +
                        '<button class=""ab-btn-icon"" onclick=""renameProfile(\'' + escAttr(name) + '\')"" title=""Rename"">&#9998;</button>' +
                        '<button class=""ab-btn-icon"" onclick=""duplicateProfile(\'' + escAttr(name) + '\')"" title=""Duplicate"">&#10063;</button>' +
                        deleteBtn +
                        '</span></div>' +
                        '<ul class=""ab-rule-list"">' + rulesHtml + '</ul>' +
                        '<button class=""ab-add-rule"" onclick=""addProfileRule(\'' + escAttr(name) + '\')"">+ Add Rule</button>';
                    container.appendChild(card);
                }
            }

            function renderYamlPreview() {
                var el = document.getElementById('yamlPreview');
                if (el) el.textContent = buildYaml();
            }

            // ── YAML builder ──
            function buildYaml() {
                var lines = [];
                lines.push('activeProfile: ' + state.activeProfile);
                lines.push('');
                lines.push('profiles:');
                var names = Object.keys(state.profiles);
                for (var i = 0; i < names.length; i++) {
                    var name = names[i];
                    var rules = state.profiles[name];
                    if (!rules || rules.length === 0) {
                        lines.push('  ' + name + ': []');
                    } else {
                        lines.push('  ' + name + ':');
                        for (var ri = 0; ri < rules.length; ri++) {
                            lines.push('    - ""' + rules[ri].replace(/\""/g, '\\""') + '""');
                        }
                    }
                }
                lines.push('');
                lines.push('assignments:');
                for (var ai = 0; ai < state.assignments.length; ai++) {
                    lines.push('  - ' + state.assignments[ai]);
                }
                return lines.join('\n');
            }

            // ── Character-level operations ──
            function assignProfile(charIdx, profileName) {
                state.assignments[charIdx] = profileName;
                renderAll();
            }

            function addRule(charIdx) {
                openRuleModal(state.assignments[charIdx], -1);
            }

            function editRule(charIdx, ruleIdx) {
                openRuleModal(state.assignments[charIdx], ruleIdx);
            }

            function moveRule(charIdx, ruleIdx, dir) {
                moveProfileRule(state.assignments[charIdx], ruleIdx, dir);
            }

            function deleteRule(charIdx, ruleIdx) {
                deleteProfileRule(state.assignments[charIdx], ruleIdx);
            }

            // ── Profile-level operations ──
            function addProfile() {
                var name = prompt('New profile name:');
                if (!name || name.trim() === '') return;
                name = name.trim();
                if (state.profiles[name]) { alert('Profile already exists.'); return; }
                state.profiles[name] = [];
                renderAll();
            }

            function renameProfile(oldName) {
                var newName = prompt('New name for profile:', oldName);
                if (!newName || newName.trim() === '' || newName.trim() === oldName) return;
                newName = newName.trim();
                if (state.profiles[newName]) { alert('Profile name already exists.'); return; }
                state.profiles[newName] = state.profiles[oldName];
                delete state.profiles[oldName];
                for (var i = 0; i < state.assignments.length; i++) {
                    if (state.assignments[i] === oldName) state.assignments[i] = newName;
                }
                if (state.activeProfile === oldName) state.activeProfile = newName;
                renderAll();
            }

            function duplicateProfile(name) {
                var newName = prompt('Name for duplicate:', name + ' Copy');
                if (!newName || newName.trim() === '') return;
                newName = newName.trim();
                if (state.profiles[newName]) { alert('Profile name already exists.'); return; }
                state.profiles[newName] = (state.profiles[name] || []).slice();
                renderAll();
            }

            function deleteProfile(name) {
                if (!confirm('Delete profile ""' + name + '""?')) return;
                var names = Object.keys(state.profiles);
                if (names.length <= 1) { alert('Cannot delete the last profile.'); return; }
                delete state.profiles[name];
                var fallback = Object.keys(state.profiles)[0];
                for (var i = 0; i < state.assignments.length; i++) {
                    if (state.assignments[i] === name) state.assignments[i] = fallback;
                }
                if (state.activeProfile === name) state.activeProfile = fallback;
                renderAll();
            }

            function addProfileRule(profileName) {
                openRuleModal(profileName, -1);
            }

            function editProfileRule(profileName, ruleIdx) {
                openRuleModal(profileName, ruleIdx);
            }

            function moveProfileRule(profileName, ruleIdx, dir) {
                var rules = state.profiles[profileName];
                if (!rules) return;
                var newIdx = ruleIdx + dir;
                if (newIdx < 0 || newIdx >= rules.length) return;
                var tmp = rules[ruleIdx];
                rules[ruleIdx] = rules[newIdx];
                rules[newIdx] = tmp;
                renderAll();
            }

            function deleteProfileRule(profileName, ruleIdx) {
                var rules = state.profiles[profileName];
                if (!rules) return;
                rules.splice(ruleIdx, 1);
                renderAll();
            }

            // ── Rule editor modal ──
            var modalState = {
                profileName: '',
                ruleIdx: -1,
                conditions: [],
                actions: []
            };

            function parseDslToModal(dsl) {
                var conditions = [];
                var actions = [];

                if (!dsl || dsl.trim() === '') {
                    return { conditions: [{type:'Always', op:'=', value:''}], actions: [{type:'Atk Weak', repeat:1}] };
                }

                var condPart = '';
                var actionPart = dsl.trim();
                var arrows = ['\u2192', '->', '=>'];
                for (var ai = 0; ai < arrows.length; ai++) {
                    var idx = dsl.indexOf(arrows[ai]);
                    if (idx >= 0) {
                        condPart = dsl.substring(0, idx).trim();
                        actionPart = dsl.substring(idx + arrows[ai].length).trim();
                        break;
                    }
                }

                if (!condPart) {
                    conditions = [{type:'Always', op:'=', value:''}];
                } else {
                    var tokens = condPart.split('&');
                    for (var ti = 0; ti < tokens.length; ti++) {
                        var tok = tokens[ti].trim();
                        if (!tok) continue;
                        var m = tok.match(/^(\w+)\s*(<=|>=|!=|<|>|=)\s*(\d+\.?\d*)(%?)$/);
                        if (m) {
                            var statMap = {'hp':'HP','mp':'MP','bp':'BP','foes':'Foes','foe':'Foes','enemies':'Foes','allies':'Allies','ally':'Allies','turn':'Turn','turns':'Turn'};
                            var stat = statMap[m[1].toLowerCase()] || m[1];
                            conditions.push({type: stat, op: m[2], value: m[3]});
                        } else {
                            conditions.push({type:'Always', op:'=', value:''});
                        }
                    }
                }
                if (conditions.length === 0) conditions = [{type:'Always', op:'=', value:''}];

                var parts = actionPart.split(',');
                for (var pi = 0; pi < parts.length; pi++) {
                    var part = parts[pi].trim();
                    if (!part) continue;
                    var repeat = 1;
                    var rm = part.match(/\s+x(\d+)$/i);
                    if (rm) {
                        repeat = parseInt(rm[1]);
                        part = part.substring(0, rm.index).trim();
                    }
                    var lower = part.toLowerCase();
                    var actionType = 'Atk Weak';
                    if (lower === 'atk weak' || lower === 'attack weak') actionType = 'Atk Weak';
                    else if (lower === 'atk strong' || lower === 'attack strong') actionType = 'Atk Strong';
                    else if (lower === 'atk random' || lower === 'atk rnd') actionType = 'Atk Random';
                    else if (lower === 'cure self') actionType = 'Cure Self';
                    else if (lower === 'cure ally') actionType = 'Cure Ally';
                    else if (lower === 'guard' || lower === 'defend') actionType = 'Guard';
                    else if (lower === 'default') actionType = 'Default';
                    else actionType = part;
                    actions.push({type: actionType, repeat: repeat});
                }
                if (actions.length === 0) actions = [{type:'Atk Weak', repeat:1}];

                return { conditions: conditions, actions: actions };
            }

            function buildDslFromModal() {
                var condParts = [];
                for (var ci = 0; ci < modalState.conditions.length; ci++) {
                    var c = modalState.conditions[ci];
                    if (c.type === 'Always') continue;
                    var suffix = PERCENT_CONDITIONS[c.type] ? '%' : '';
                    condParts.push(c.type + ' ' + c.op + ' ' + c.value + suffix);
                }

                var actionParts = [];
                for (var ai = 0; ai < modalState.actions.length; ai++) {
                    var a = modalState.actions[ai];
                    var s = a.type;
                    if (a.repeat > 1) s += ' x' + a.repeat;
                    actionParts.push(s);
                }

                return condParts.join(' & ') + ' -> ' + actionParts.join(', ');
            }

            function openRuleModal(profileName, ruleIdx) {
                modalState.profileName = profileName;
                modalState.ruleIdx = ruleIdx;

                var rules = state.profiles[profileName] || [];
                var dsl = (ruleIdx >= 0 && ruleIdx < rules.length) ? rules[ruleIdx] : '';
                var parsed = parseDslToModal(dsl);
                modalState.conditions = parsed.conditions;
                modalState.actions = parsed.actions;

                renderModal();
            }

            function renderModal() {
                var existing = document.getElementById('abModal');
                if (existing) existing.remove();

                var overlay = document.createElement('div');
                overlay.id = 'abModal';
                overlay.className = 'ab-modal-overlay';
                overlay.onclick = function(e) { if (e.target === overlay) closeModal(); };

                var title = modalState.ruleIdx >= 0 ? 'Edit Rule' : 'Add Rule';

                var condsHtml = '';
                for (var ci = 0; ci < modalState.conditions.length; ci++) {
                    var c = modalState.conditions[ci];
                    var typeOptions = '';
                    for (var ti = 0; ti < CONDITION_TYPES.length; ti++) {
                        var t = CONDITION_TYPES[ti];
                        typeOptions += '<option value=""' + t + '""' + (t === c.type ? ' selected' : '') + '>' + t + '</option>';
                    }
                    var opOptions = '';
                    for (var oi = 0; oi < OPERATORS.length; oi++) {
                        var o = OPERATORS[oi];
                        opOptions += '<option value=""' + escAttr(o) + '""' + (o === c.op ? ' selected' : '') + '>' + escHtml(o) + '</option>';
                    }
                    var hideValueOp = c.type === 'Always' ? ' style=""display:none""' : '';
                    var suffix = PERCENT_CONDITIONS[c.type] ? '<span style=""color:#7777a0;"">%</span>' : '';
                    var removeBtn = modalState.conditions.length > 1
                        ? '<button class=""ab-btn-icon ab-btn-delete"" onclick=""removeCond(' + ci + ')"">&times;</button>'
                        : '';

                    condsHtml += '<div class=""ab-cond-row"">' +
                        '<select onchange=""updateCondType(' + ci + ', this.value)"">' + typeOptions + '</select>' +
                        '<select' + hideValueOp + ' id=""condOp' + ci + '"" onchange=""updateCondOp(' + ci + ', this.value)"">' + opOptions + '</select>' +
                        '<span' + hideValueOp + ' id=""condVal' + ci + '""><input type=""number"" value=""' + escAttr(c.value) + '"" onchange=""updateCondValue(' + ci + ', this.value)"" placeholder=""value"" /> ' + suffix + '</span>' +
                        removeBtn +
                        '</div>';
                }

                var actionsHtml = '';
                var totalActions = 0;
                for (var ai = 0; ai < modalState.actions.length; ai++) {
                    totalActions += modalState.actions[ai].repeat;
                }
                for (var ai = 0; ai < modalState.actions.length; ai++) {
                    var a = modalState.actions[ai];
                    var typeOptions = '';
                    for (var ti = 0; ti < ACTION_TYPES.length; ti++) {
                        var t = ACTION_TYPES[ti];
                        typeOptions += '<option value=""' + t + '""' + (t === a.type ? ' selected' : '') + '>' + t + '</option>';
                    }
                    if (ACTION_TYPES.indexOf(a.type) === -1) {
                        typeOptions += '<option value=""' + escAttr(a.type) + '"" selected>' + escHtml(a.type) + '</option>';
                    }
                    var repeatOptions = '';
                    for (var rn = 1; rn <= 4; rn++) {
                        repeatOptions += '<option value=""' + rn + '""' + (rn === a.repeat ? ' selected' : '') + '>' + (rn === 1 ? '1x' : rn + 'x') + '</option>';
                    }
                    var removeBtn = modalState.actions.length > 1
                        ? '<button class=""ab-btn-icon ab-btn-delete"" onclick=""removeAction(' + ai + ')"">&times;</button>'
                        : '';

                    actionsHtml += '<div class=""ab-action-row"">' +
                        '<select onchange=""updateActionType(' + ai + ', this.value)"">' + typeOptions + '</select>' +
                        '<select onchange=""updateActionRepeat(' + ai + ', this.value)"">' + repeatOptions + '</select>' +
                        removeBtn +
                        '</div>';
                }

                var actionWarning = '';
                if (totalActions > 4) {
                    actionWarning = '<span class=""ab-warning"" title=""More than 4 actions may exceed available BP"">&#9888; ' + totalActions + ' actions (needs ' + (totalActions-1) + ' BP)</span>';
                } else if (totalActions > 1) {
                    actionWarning = '<span style=""color:#7777a0;font-size:0.8em;"">' + totalActions + ' actions (' + (totalActions-1) + ' BP)</span>';
                }

                var addActionBtn = totalActions < 4
                    ? '<button class=""ab-add-rule"" onclick=""addAction()"" style=""margin-top:0.3em;"">+ Add Action</button>'
                    : '';

                var dslPreview = buildDslFromModal();

                overlay.innerHTML =
                    '<div class=""ab-modal"">' +
                    '<h3>' + title + ' — ' + escHtml(modalState.profileName) + '</h3>' +
                    '<div class=""ab-modal-section"">' +
                    '<div class=""ab-modal-section-title"">Conditions (AND)</div>' +
                    '<div id=""modalConds"">' + condsHtml + '</div>' +
                    '<button class=""ab-add-rule"" onclick=""addCond()"" style=""margin-top:0.3em;"">+ Add Condition</button>' +
                    '</div>' +
                    '<div class=""ab-modal-section"">' +
                    '<div class=""ab-modal-section-title"">Actions ' + actionWarning + '</div>' +
                    '<div id=""modalActions"">' + actionsHtml + '</div>' +
                    addActionBtn +
                    '</div>' +
                    '<div class=""ab-modal-section"">' +
                    '<div class=""ab-modal-section-title"">DSL Preview</div>' +
                    '<div class=""ab-dsl-preview"" id=""dslPreview"">' + escHtml(dslPreview) + '</div>' +
                    '</div>' +
                    '<div class=""ab-modal-btn-row"">' +
                    '<button class=""btn-secondary"" onclick=""closeModal()"">Cancel</button>' +
                    '<button class=""btn-primary"" onclick=""saveRule()"">Save Rule</button>' +
                    '</div>' +
                    '</div>';

                document.body.appendChild(overlay);
            }

            function closeModal() {
                var m = document.getElementById('abModal');
                if (m) m.remove();
            }

            function updateCondType(idx, val) {
                modalState.conditions[idx].type = val;
                if (val === 'Always') { modalState.conditions[idx].op = '='; modalState.conditions[idx].value = ''; }
                renderModal();
            }

            function updateCondOp(idx, val) {
                modalState.conditions[idx].op = val;
                updateDslPreview();
            }

            function updateCondValue(idx, val) {
                modalState.conditions[idx].value = val;
                updateDslPreview();
            }

            function addCond() {
                modalState.conditions.push({type:'HP', op:'<', value:'50'});
                renderModal();
            }

            function removeCond(idx) {
                modalState.conditions.splice(idx, 1);
                if (modalState.conditions.length === 0) modalState.conditions.push({type:'Always', op:'=', value:''});
                renderModal();
            }

            function updateActionType(idx, val) {
                modalState.actions[idx].type = val;
                updateDslPreview();
            }

            function updateActionRepeat(idx, val) {
                modalState.actions[idx].repeat = parseInt(val) || 1;
                renderModal();
            }

            function addAction() {
                var totalActions = 0;
                for (var i = 0; i < modalState.actions.length; i++) totalActions += modalState.actions[i].repeat;
                if (totalActions >= 4) { alert('Maximum 4 actions per rule.'); return; }
                modalState.actions.push({type:'Atk Weak', repeat:1});
                renderModal();
            }

            function removeAction(idx) {
                modalState.actions.splice(idx, 1);
                if (modalState.actions.length === 0) modalState.actions.push({type:'Atk Weak', repeat:1});
                renderModal();
            }

            function updateDslPreview() {
                var el = document.getElementById('dslPreview');
                if (el) el.textContent = buildDslFromModal();
            }

            function saveRule() {
                var dsl = buildDslFromModal();
                if (!state.profiles[modalState.profileName]) {
                    state.profiles[modalState.profileName] = [];
                }
                var rules = state.profiles[modalState.profileName];
                if (modalState.ruleIdx >= 0 && modalState.ruleIdx < rules.length) {
                    rules[modalState.ruleIdx] = dsl;
                } else {
                    rules.push(dsl);
                }
                closeModal();
                renderAll();
            }

            // ── Party profiles ──
            function savePartyProfile() {
                var name = prompt('Save party profile as:', 'Grinding');
                if (!name || name.trim() === '') return;
                name = name.trim();
                state.partyProfiles[name] = state.assignments.slice();
                renderPartyProfileSelect();
            }

            function newPartyProfile() {
                var name = prompt('New party profile name:');
                if (!name || name.trim() === '') return;
                name = name.trim();
                var first = Object.keys(state.profiles)[0] || 'Default';
                state.partyProfiles[name] = [first, first, first, first];
                state.assignments = state.partyProfiles[name].slice();
                renderPartyProfileSelect();
                renderAll();
            }

            function loadPartyProfile() {
                var sel = document.getElementById('partyProfileSelect');
                var val = sel.value;
                if (val === '__current__') return;
                if (state.partyProfiles[val]) {
                    state.assignments = state.partyProfiles[val].slice();
                    renderAll();
                }
            }

            function renderPartyProfileSelect() {
                var sel = document.getElementById('partyProfileSelect');
                var html = '<option value=""__current__"">Current Config</option>';
                var names = Object.keys(state.partyProfiles);
                for (var i = 0; i < names.length; i++) {
                    html += '<option value=""' + escAttr(names[i]) + '"">' + escHtml(names[i]) + '</option>';
                }
                sel.innerHTML = html;
            }

            // ── Save / Reload ──
            function saveAll() {
                var yaml = buildYaml();
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '/autobattle/editor', true);
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.onload = function() {
                    if (xhr.status === 200) {
                        document.open();
                        document.write(xhr.responseText);
                        document.close();
                    } else {
                        alert('Save failed: ' + xhr.statusText);
                    }
                };
                xhr.send('yaml=' + encodeURIComponent(yaml));
            }

            function reloadFromDisk() {
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '/autobattle/reload', true);
                xhr.onload = function() { location.reload(); };
                xhr.send();
            }

            // ── Init ──
            loadState();
            </script>
        ";
    }

    // ── Music ───────────────────────────────────────────────────

    /// <summary>
    /// BGM cue definitions: (cue_name, description) for each category.
    /// </summary>
    private static readonly (string Name, string Desc)[] BattleBgmCues = new[]
    {
        ("bgmbtl_01", "Normal battle"),
        ("bgmbtl_02", "Boss battle"),
        ("bgmbtl_03", "Asterisk holder"),
        ("bgmbtl_04", "Chapter boss"),
        ("bgmbtl_05", "Event battle"),
        ("bgmbtl_06", "Miniboss"),
        ("bgmbtl_07", "Dragon encounter"),
        ("bgmbtl_08", "Victory fanfare"),
        ("bgmbtl_09", "Defeat"),
        ("bgmbtl_10", "Rare encounter"),
        ("bgmbtl_11", "Nemesis battle"),
        ("bgmbtl_12", "Ba'al battle"),
        ("bgmbtl_13", "Friend summon"),
        ("bgmbtl_14", "Special attack"),
        ("bgmbtl_15", "Intense battle"),
        ("bgmbtl_16", "Final boss"),
    };

    private static readonly (string Category, string Label, (string Name, string Desc)[] Cues)[] CollapsibleBgmCategories = new[]
    {
        ("fld", "Field / Overworld", new (string, string)[]
        {
            ("bgmfld_01", "Overworld"),
            ("bgmfld_02", "Overworld (night)"),
            ("bgmfld_03", "Ship travel"),
            ("bgmfld_04", "Airship"),
        }),
        ("twn", "Towns", new (string, string)[]
        {
            ("bgmtwn_01", "Caldisla"),
            ("bgmtwn_02", "Florem"),
            ("bgmtwn_03", "Grandship"),
            ("bgmtwn_04", "Ancheim"),
            ("bgmtwn_05", "Hartschild"),
            ("bgmtwn_06", "Starkfort"),
            ("bgmtwn_07", "Eternia"),
            ("bgmtwn_08", "Norende"),
        }),
        ("dgn", "Dungeons", new (string, string)[]
        {
            ("bgmdgn_01", "Ruins"),
            ("bgmdgn_02", "Temples"),
            ("bgmdgn_03", "Crystal temple"),
            ("bgmdgn_04", "Tower"),
            ("bgmdgn_05", "Endgame dungeon"),
            ("bgmdgn_06", "Hidden dungeon"),
            ("bgmdgn_07", "Final dungeon"),
        }),
        ("evt", "Events", new (string, string)[]
        {
            ("bgmevt_01", "Prologue"),
            ("bgmevt_02", "Emotional scene"),
            ("bgmevt_03", "Tense scene"),
            ("bgmevt_04", "Comedy scene"),
            ("bgmevt_05", "Revelation"),
            ("bgmevt_06", "Dark scene"),
            ("bgmevt_07", "Hope theme"),
            ("bgmevt_08", "Flashback"),
            ("bgmevt_09", "Asterisk scene"),
            ("bgmevt_10", "Crystal awakening"),
            ("bgmevt_11", "Tragedy"),
            ("bgmevt_12", "Resolution"),
            ("bgmevt_13", "Ending part 1"),
            ("bgmevt_14", "Ending part 2"),
        }),
        ("sys", "System", new (string, string)[]
        {
            ("bgmsys_01", "Title screen"),
            ("bgmsys_02", "Menu"),
            ("bgmsys_03", "Save screen"),
            ("bgmsys_04", "Job select"),
            ("bgmsys_05", "Shop"),
            ("bgmsys_06", "Tutorial"),
            ("bgmsys_07", "Bestiary"),
            ("bgmsys_08", "Game over"),
            ("bgmsys_09", "Level up"),
            ("bgmsys_10", "Job master"),
            ("bgmsys_11", "Item jingle"),
            ("bgmsys_12", "Quest complete"),
            ("bgmsys_13", "Colony update"),
            ("bgmsys_14", "Abilink"),
            ("bgmsys_15", "Friend summon call"),
            ("bgmsys_16", "Send / receive"),
            ("bgmsys_17", "Bravely Second"),
            ("bgmsys_18", "Results screen"),
            ("bgmsys_19", "Chapter clear"),
            ("bgmsys_20", "Credits"),
            ("bgmsys_21", "Staff roll"),
            ("bgmsys_22", "Post-credits"),
        }),
    };

    /// <summary>
    /// Read current YAML config and return a dictionary of overrides.
    /// </summary>
    private static Dictionary<string, string> ReadMusicOverrides()
    {
        var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (File.Exists(MusicConfigPath))
            {
                string yaml = File.ReadAllText(MusicConfigPath);
                if (!string.IsNullOrWhiteSpace(yaml))
                {
                    var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
                        .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.CamelCaseNamingConvention.Instance)
                        .IgnoreUnmatchedProperties()
                        .Build();
                    var config = deserializer.Deserialize<NativeMusicPatch.MusicConfig>(yaml);
                    if (config?.Overrides != null)
                    {
                        foreach (var kv in config.Overrides)
                            overrides[kv.Key] = kv.Value;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[WebConfig] Error reading music overrides: {ex.Message}");
        }
        return overrides;
    }

    /// <summary>
    /// Build HTML table rows for a set of BGM cues.
    /// </summary>
    private static string BuildCueTableRows((string Name, string Desc)[] cues, Dictionary<string, string> overrides)
    {
        var sb = new StringBuilder();
        foreach (var (name, desc) in cues)
        {
            bool hasOverride = overrides.TryGetValue(name, out string overridePath) && !string.IsNullOrWhiteSpace(overridePath);
            string statusClass = hasOverride ? "bgm-status-custom" : "bgm-status-default";
            string statusText = hasOverride ? "Custom" : "Default";
            string pathValue = hasOverride ? WebUtility.HtmlEncode(overridePath) : "";
            string pathDisplay = hasOverride ? WebUtility.HtmlEncode(overridePath) : "<span class=\"dimmed\">&mdash;</span>";
            string encodedName = WebUtility.HtmlEncode(name);

            sb.Append($@"<tr class=""bgm-row"" data-cue=""{encodedName}"">
                <td class=""mono bgm-cue-name"">{encodedName}</td>
                <td class=""bgm-desc"">{WebUtility.HtmlEncode(desc)}</td>
                <td><span class=""{statusClass}"">{statusText}</span></td>
                <td class=""bgm-path-cell"">
                    <span class=""bgm-path-display"" id=""display_{encodedName}"">{pathDisplay}</span>
                    <div class=""bgm-path-edit"" id=""edit_{encodedName}"" style=""display:none"">
                        <input type=""text"" class=""bgm-path-input"" id=""input_{encodedName}"" value=""{pathValue}"" placeholder=""CustomBGM/filename.hca"" />
                    </div>
                </td>
                <td class=""bgm-actions"">
                    <button type=""button"" class=""btn-sm btn-set"" onclick=""toggleEdit('{encodedName}')"">{(hasOverride ? "Change" : "Set")}</button>
                    {(hasOverride ? $"<button type=\"button\" class=\"btn-sm btn-remove\" onclick=\"removeCue('{encodedName}')\">Remove</button>" : "")}
                </td>
            </tr>");
        }
        return sb.ToString();
    }

    private static string HandleMusicGet(string messageHtml = null)
    {
        string msgBlock = messageHtml ?? "";
        var overrides = ReadMusicOverrides();

        // Count active overrides
        int activeCount = overrides.Count;

        // Build available HCA files list
        var availableFiles = new List<string>();
        try
        {
            string bgmDir = CustomBgmDir;
            if (!string.IsNullOrEmpty(bgmDir) && Directory.Exists(bgmDir))
            {
                availableFiles = Directory.GetFiles(bgmDir, "*.hca")
                    .Select(f => Path.GetFileName(f))
                    .OrderBy(f => f)
                    .ToList();
            }
        }
        catch { }

        // Build available files HTML
        var availHtml = new StringBuilder();
        if (availableFiles.Count > 0)
        {
            availHtml.Append("<div class=\"file-list\" id=\"fileList\">");
            foreach (var f in availableFiles)
            {
                var path = $"CustomBGM/{WebUtility.HtmlEncode(f)}";
                availHtml.Append($"<span class=\"file-tag file-tag-click\" onclick=\"assignFile('{path}')\" title=\"Click to assign to selected cue\">{path}</span> ");
            }
            availHtml.Append("</div>");
        }
        else
        {
            availHtml.Append("<p class=\"dimmed\" id=\"fileList\">No .hca files found in CustomBGM/ folder.</p>");
        }

        // Build battle BGM table
        string battleRows = BuildCueTableRows(BattleBgmCues, overrides);

        // Build collapsible sections
        var collapseSb = new StringBuilder();
        foreach (var (catId, label, cues) in CollapsibleBgmCategories)
        {
            int catOverrides = 0;
            foreach (var (cn, _) in cues)
                if (overrides.ContainsKey(cn) && !string.IsNullOrWhiteSpace(overrides[cn]))
                    catOverrides++;

            string badge = catOverrides > 0 ? $" <span class=\"bgm-cat-badge\">{catOverrides} custom</span>" : "";
            string rows = BuildCueTableRows(cues, overrides);

            collapseSb.Append($@"
                <div class=""bgm-category"">
                    <div class=""bgm-category-header"" onclick=""toggleCategory('{catId}')"">
                        <span class=""bgm-toggle-arrow"" id=""arrow_{catId}"">&#9654;</span>
                        <span class=""bgm-category-label"">{WebUtility.HtmlEncode(label)}</span>{badge}
                    </div>
                    <div class=""bgm-category-body"" id=""cat_{catId}"" style=""display:none"">
                        <table class=""bgm-table"">
                            <thead><tr>
                                <th>Cue Name</th><th>Description</th><th>Status</th><th>Override Path</th><th>Actions</th>
                            </tr></thead>
                            <tbody>{rows}</tbody>
                        </table>
                    </div>
                </div>");
        }

        return WrapHtml("Music Config", "music", $@"
            <h2>Music Overrides</h2>
            <p class=""subtitle"">Replace BGM cues with custom HCA audio files. Files are resolved relative to StreamingAssets/.
                <span class=""bgm-summary"">{activeCount} override(s) active</span></p>

            {msgBlock}

            <!-- Upload Section -->
            <div class=""upload-section"">
                <div class=""section-label"">Upload Audio</div>
                <div id=""serverStatus"" class=""msg msg-warning"" style=""display:none"">
                    Music conversion server not detected on port 8889. Start it with:
                    <code>./scripts/start_music_server.sh</code>
                </div>
                <div class=""upload-area"" id=""uploadArea"">
                    <input type=""file"" id=""hcaFileInput"" accept="".hca,.mp3,.wav,.ogg,.flac,.m4a,.aac"" style=""display:none"" onchange=""uploadFile(this)""/>
                    <div class=""upload-prompt"" onclick=""document.getElementById('hcaFileInput').click()"">
                        <span class=""upload-icon"">&#8682;</span>
                        <span>Click to select audio file or drag &amp; drop<br/><small>.hca .mp3 .wav .ogg .flac .m4a .aac</small></span>
                    </div>
                    <div class=""upload-status"" id=""uploadStatus"" style=""display:none""></div>
                </div>
                <div style=""margin-top:12px;padding:12px;background:#1a1a2e;border-radius:6px"">
                    <div style=""margin-bottom:8px;color:#e4a040"">Or paste a file path from your system:</div>
                    <div style=""display:flex;gap:8px"">
                        <input type=""text"" id=""pathInput"" placeholder=""/home/user/music/song.mp3"" style=""flex:1;padding:8px;background:#0f0f1a;border:1px solid #333;color:#eee;border-radius:4px;font-family:monospace""/>
                        <button type=""button"" onclick=""convertFromPath()"" style=""padding:8px 16px;background:#e4a040;color:#000;border:none;border-radius:4px;cursor:pointer;font-weight:bold"">Convert</button>
                    </div>
                    <div id=""pathStatus"" style=""margin-top:8px;display:none""></div>
                </div>
            </div>

            <!-- Available Files -->
            <div class=""section-label"" style=""margin-top:1.5em"">Available HCA Files <span class=""dimmed"">(click to assign to selected cue)</span></div>
            {availHtml}

            <!-- Battle BGM Table (expanded by default) -->
            <div class=""section-label"" style=""margin-top:1.5em"">Battle BGM Overrides</div>
            <table class=""bgm-table"">
                <thead><tr>
                    <th>Cue Name</th><th>Description</th><th>Status</th><th>Override Path</th><th>Actions</th>
                </tr></thead>
                <tbody>{battleRows}</tbody>
            </table>

            <!-- Collapsible Categories -->
            {collapseSb}

            <!-- Save Button -->
            <div class=""btn-row bgm-save-row"">
                <button type=""button"" class=""btn-primary"" onclick=""saveAllOverrides()"">Save &amp; Reload</button>
                <button type=""button"" class=""btn-secondary"" onclick=""doReloadMusic()"">Reload from Disk</button>
                <span id=""saveStatus"" class=""bgm-save-status""></span>
            </div>

            <script>
            var MUSIC_SERVER = 'http://localhost:8889';
            var musicServerAvailable = false;
            var selectedCue = null; // currently selected cue for file assignment

            // Check if the music conversion server is running
            (function checkServer() {{
                fetch(MUSIC_SERVER + '/health')
                    .then(function(r) {{ return r.json(); }})
                    .then(function(d) {{
                        if (d.ok) {{
                            musicServerAvailable = true;
                            var el = document.getElementById('serverStatus');
                            if (el) el.style.display = 'none';
                        }}
                    }})
                    .catch(function() {{
                        var el = document.getElementById('serverStatus');
                        if (el) el.style.display = 'block';
                    }});
            }})();

            function doReloadMusic() {{
                fetch('/music/reload', {{method:'POST'}}).then(function() {{ location.reload(); }});
            }}

            // Toggle inline edit for a cue row
            function toggleEdit(cue) {{
                var display = document.getElementById('display_' + cue);
                var edit = document.getElementById('edit_' + cue);
                var input = document.getElementById('input_' + cue);
                if (edit.style.display === 'none') {{
                    display.style.display = 'none';
                    edit.style.display = 'block';
                    input.focus();
                    selectedCue = cue;
                    // Highlight the row
                    highlightSelectedRow(cue);
                }} else {{
                    applyEdit(cue);
                }}
            }}

            function highlightSelectedRow(cue) {{
                // Remove previous selection
                document.querySelectorAll('.bgm-row-selected').forEach(function(r) {{
                    r.classList.remove('bgm-row-selected');
                }});
                var row = document.querySelector('tr[data-cue=""' + cue + '""]');
                if (row) row.classList.add('bgm-row-selected');
            }}

            // Apply the edit (commit text input value)
            function applyEdit(cue) {{
                var input = document.getElementById('input_' + cue);
                var display = document.getElementById('display_' + cue);
                var edit = document.getElementById('edit_' + cue);
                var val = input.value.trim();

                display.style.display = '';
                edit.style.display = 'none';

                if (val) {{
                    display.innerHTML = escHtml(val);
                    updateRowStatus(cue, true, val);
                }} else {{
                    display.innerHTML = '<span class=""dimmed"">&mdash;</span>';
                    updateRowStatus(cue, false, '');
                }}
            }}

            // Handle Enter/Escape in edit inputs
            document.addEventListener('keydown', function(e) {{
                if (e.target.classList.contains('bgm-path-input')) {{
                    if (e.key === 'Enter') {{
                        e.preventDefault();
                        var cue = e.target.id.replace('input_', '');
                        applyEdit(cue);
                    }} else if (e.key === 'Escape') {{
                        var cue = e.target.id.replace('input_', '');
                        var display = document.getElementById('display_' + cue);
                        var edit = document.getElementById('edit_' + cue);
                        display.style.display = '';
                        edit.style.display = 'none';
                    }}
                }}
            }});

            // Remove override from a cue
            function removeCue(cue) {{
                var input = document.getElementById('input_' + cue);
                var display = document.getElementById('display_' + cue);
                var edit = document.getElementById('edit_' + cue);
                input.value = '';
                display.innerHTML = '<span class=""dimmed"">&mdash;</span>';
                display.style.display = '';
                edit.style.display = 'none';
                updateRowStatus(cue, false, '');
            }}

            // Update the status badge and action buttons for a row
            function updateRowStatus(cue, hasOverride, path) {{
                var row = document.querySelector('tr[data-cue=""' + cue + '""]');
                if (!row) return;
                var statusCell = row.children[2];
                var actionsCell = row.children[4];

                if (hasOverride) {{
                    statusCell.innerHTML = '<span class=""bgm-status-custom"">Custom</span>';
                    actionsCell.innerHTML =
                        '<button type=""button"" class=""btn-sm btn-set"" onclick=""toggleEdit(\'' + cue + '\')"">Change</button>' +
                        '<button type=""button"" class=""btn-sm btn-remove"" onclick=""removeCue(\'' + cue + '\')"">Remove</button>';
                }} else {{
                    statusCell.innerHTML = '<span class=""bgm-status-default"">Default</span>';
                    actionsCell.innerHTML =
                        '<button type=""button"" class=""btn-sm btn-set"" onclick=""toggleEdit(\'' + cue + '\')"">Set</button>';
                }}
            }}

            // Assign an available file to a cue
            function assignFile(path) {{
                if (!selectedCue) {{
                    // If no cue is selected, find the first cue without an override
                    var rows = document.querySelectorAll('.bgm-row');
                    for (var i = 0; i < rows.length; i++) {{
                        var c = rows[i].getAttribute('data-cue');
                        var inp = document.getElementById('input_' + c);
                        if (inp && !inp.value.trim()) {{
                            selectedCue = c;
                            break;
                        }}
                    }}
                    if (!selectedCue) {{
                        showToast('Click Set on a cue first, then click a file to assign it.');
                        return;
                    }}
                }}

                var input = document.getElementById('input_' + selectedCue);
                var display = document.getElementById('display_' + selectedCue);
                var edit = document.getElementById('edit_' + selectedCue);

                input.value = path;
                display.innerHTML = escHtml(path);
                display.style.display = '';
                edit.style.display = 'none';
                updateRowStatus(selectedCue, true, path);
                showToast('Assigned ' + path + ' to ' + selectedCue);
                selectedCue = null;
                document.querySelectorAll('.bgm-row-selected').forEach(function(r) {{
                    r.classList.remove('bgm-row-selected');
                }});
            }}

            // Collect all overrides from the table and POST to /music/save
            function saveAllOverrides() {{
                var overrides = {{}};
                document.querySelectorAll('.bgm-row').forEach(function(row) {{
                    var cue = row.getAttribute('data-cue');
                    var input = document.getElementById('input_' + cue);
                    if (input && input.value.trim()) {{
                        overrides[cue] = input.value.trim();
                    }}
                }});

                var statusEl = document.getElementById('saveStatus');
                statusEl.textContent = 'Saving...';
                statusEl.className = 'bgm-save-status bgm-save-info';

                fetch('/music/save', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ overrides: overrides }})
                }})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    if (d.error) {{
                        statusEl.textContent = 'Error: ' + d.error;
                        statusEl.className = 'bgm-save-status bgm-save-error';
                    }} else {{
                        statusEl.textContent = d.message || 'Saved!';
                        statusEl.className = 'bgm-save-status bgm-save-success';
                        setTimeout(function() {{ statusEl.textContent = ''; }}, 3000);
                    }}
                }})
                .catch(function(err) {{
                    statusEl.textContent = 'Save failed: ' + err;
                    statusEl.className = 'bgm-save-status bgm-save-error';
                }});
            }}

            // Toggle collapsible category
            function toggleCategory(catId) {{
                var body = document.getElementById('cat_' + catId);
                var arrow = document.getElementById('arrow_' + catId);
                if (body.style.display === 'none') {{
                    body.style.display = 'block';
                    arrow.innerHTML = '&#9660;';
                }} else {{
                    body.style.display = 'none';
                    arrow.innerHTML = '&#9654;';
                }}
            }}

            function escHtml(s) {{
                var d = document.createElement('div');
                d.textContent = s;
                return d.innerHTML;
            }}

            function showToast(msg) {{
                var t = document.getElementById('toast');
                if (!t) {{
                    t = document.createElement('div');
                    t.id = 'toast';
                    t.style.cssText = 'position:fixed;bottom:2em;right:2em;background:#2ecc71;color:#0f0f1a;padding:10px 20px;border-radius:6px;font-weight:bold;z-index:1000;transition:opacity 0.3s;';
                    document.body.appendChild(t);
                }}
                t.textContent = msg;
                t.style.opacity = '1';
                clearTimeout(t._timer);
                t._timer = setTimeout(function() {{ t.style.opacity = '0'; }}, 2000);
            }}

            function uploadFile(input) {{
                var file = input.files[0];
                if (!file) return;
                var validExts = ['.hca', '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac'];
                var ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
                if (validExts.indexOf(ext) < 0) {{
                    showUploadStatus('Unsupported format. Accepted: ' + validExts.join(', '), 'error');
                    return;
                }}
                var isHca = ext === '.hca';

                if (isHca) {{
                    showUploadStatus('Uploading ' + file.name + '...', 'info');
                    var fd = new FormData();
                    fd.append('file', file);
                    fetch('/music/upload', {{ method: 'POST', body: fd }})
                        .then(function(r) {{ return r.json(); }})
                        .then(function(data) {{
                            if (data.error) {{
                                showUploadStatus('Error: ' + data.error, 'error');
                            }} else {{
                                showUploadStatus(data.path, 'success'); showCopyBtn(data.path);
                                refreshFileList();
                            }}
                        }})
                        .catch(function(err) {{
                            showUploadStatus('Upload failed: ' + err, 'error');
                        }});
                }} else {{
                    if (!musicServerAvailable) {{
                        showUploadStatus('Music conversion server is not running. Start it: ./scripts/start_music_server.sh', 'error');
                        return;
                    }}
                    showUploadStatus('Uploading ' + file.name + ' to conversion server...', 'info');
                    var fd = new FormData();
                    fd.append('file', file);
                    fetch(MUSIC_SERVER + '/convert', {{ method: 'POST', body: fd }})
                        .then(function(r) {{ return r.json(); }})
                        .then(function(data) {{
                            if (data.error) {{
                                showUploadStatus('Error: ' + data.error, 'error');
                            }} else if (data.converting) {{
                                showUploadStatus('Converting ' + file.name + ' to HCA... (this may take a moment)', 'info');
                                pollConversion(data.name);
                            }} else if (data.success) {{
                                showUploadStatus(data.path, 'success'); showCopyBtn(data.path);
                                refreshFileList();
                            }}
                        }})
                        .catch(function(err) {{
                            showUploadStatus('Upload failed. Is the music server running? Error: ' + err, 'error');
                        }});
                }}
                input.value = '';
            }}

            function pollConversion(name) {{
                var attempts = 0;
                var maxAttempts = 120;
                var timer = setInterval(function() {{
                    attempts++;
                    fetch(MUSIC_SERVER + '/convert-status?name=' + encodeURIComponent(name))
                        .then(function(r) {{ return r.json(); }})
                        .then(function(data) {{
                            if (data.done) {{
                                clearInterval(timer);
                                if (data.error) {{
                                    showUploadStatus('Conversion failed: ' + data.error, 'error');
                                }} else {{
                                    showUploadStatus('Converted: ' + data.path + ' (' + formatSize(data.size) + ')', 'success');
                                    refreshFileList();
                                }}
                            }} else if (attempts >= maxAttempts) {{
                                clearInterval(timer);
                                showUploadStatus('Conversion timed out.', 'error');
                            }}
                        }})
                        .catch(function() {{
                            if (attempts >= maxAttempts) {{
                                clearInterval(timer);
                                showUploadStatus('Could not reach conversion server.', 'error');
                            }}
                        }});
                }}, 1000);
            }}

            function convertFromPath() {{
                var p = document.getElementById('pathInput').value.trim();
                if (!p) return;
                if (!musicServerAvailable) {{
                    var s = document.getElementById('pathStatus');
                    s.style.display = 'block';
                    s.style.color = '#ff4444';
                    s.textContent = 'Music conversion server is not running. Start it: ./scripts/start_music_server.sh';
                    return;
                }}
                var s = document.getElementById('pathStatus');
                s.style.display = 'block';
                s.style.color = '#aaa';
                s.textContent = 'Converting...';
                fetch(MUSIC_SERVER + '/convert-path', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
                    body: 'path=' + encodeURIComponent(p)
                }})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    if (d.error) {{
                        s.style.color = '#ff4444';
                        s.textContent = 'Error: ' + d.error;
                    }} else if (d.converting) {{
                        s.style.color = '#e4a040';
                        s.textContent = 'Converting to HCA...';
                        pollConversionPath(d.name, s);
                    }} else if (d.success) {{
                        s.style.color = '#44ff44';
                        s.textContent = 'Ready: ' + d.path;
                        refreshFileList();
                    }}
                }})
                .catch(function(e) {{
                    s.style.color = '#ff4444';
                    s.textContent = 'Failed: ' + e;
                }});
            }}

            function pollConversionPath(name, statusEl) {{
                var attempts = 0;
                var timer = setInterval(function() {{
                    attempts++;
                    fetch(MUSIC_SERVER + '/convert-status?name=' + encodeURIComponent(name))
                        .then(function(r) {{ return r.json(); }})
                        .then(function(d) {{
                            if (d.done) {{
                                clearInterval(timer);
                                if (d.error) {{
                                    statusEl.style.color = '#ff4444';
                                    statusEl.textContent = 'Error: ' + d.error;
                                }} else {{
                                    statusEl.style.color = '#44ff44';
                                    statusEl.textContent = 'Ready: ' + d.path;
                                    refreshFileList();
                                }}
                            }} else if (attempts >= 120) {{
                                clearInterval(timer);
                                statusEl.style.color = '#ff4444';
                                statusEl.textContent = 'Conversion timed out.';
                            }}
                        }})
                        .catch(function() {{
                            if (attempts >= 120) {{
                                clearInterval(timer);
                                statusEl.style.color = '#ff4444';
                                statusEl.textContent = 'Lost connection to conversion server.';
                            }}
                        }});
                }}, 1000);
            }}

            function showUploadStatus(msg, type) {{
                var el = document.getElementById('uploadStatus');
                el.style.display = 'block';
                el.innerHTML = msg;
                el.className = 'upload-status upload-status-' + type;
            }}

            function showCopyBtn(path) {{
                var el = document.getElementById('uploadStatus');
                var btn = document.createElement('button');
                btn.textContent = 'Copy Path';
                btn.style.cssText = 'margin-left:8px;padding:2px 10px;background:#e4a040;color:#000;border:none;border-radius:3px;cursor:pointer;font-size:12px';
                btn.onclick = function() {{ navigator.clipboard.writeText(path); btn.textContent = 'Copied!'; }};
                el.appendChild(document.createTextNode(' '));
                el.appendChild(btn);
            }}

            function formatSize(bytes) {{
                if (bytes < 1024) return bytes + ' B';
                if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
                return (bytes/(1024*1024)).toFixed(1) + ' MB';
            }}

            function refreshFileList() {{
                var url = musicServerAvailable ? MUSIC_SERVER + '/files' : '/music/files';
                fetch(url)
                    .then(function(r) {{ return r.json(); }})
                    .then(function(data) {{
                        var container = document.getElementById('fileList');
                        if (!container) return;
                        if (data.files && data.files.length > 0) {{
                            var html = '';
                            data.files.forEach(function(f) {{
                                html += '<span class=""file-tag file-tag-click"" onclick=""assignFile(\'' + f.path + '\')"" title=""Click to assign to selected cue"">' + f.path + '</span> ';
                            }});
                            container.innerHTML = html;
                            container.className = 'file-list';
                        }} else {{
                            container.textContent = 'No .hca files found.';
                            container.className = 'dimmed';
                        }}
                    }})
                    .catch(function() {{
                        if (url !== '/music/files') {{
                            fetch('/music/files')
                                .then(function(r) {{ return r.json(); }})
                                .then(function(data) {{
                                    var container = document.getElementById('fileList');
                                    if (!container) return;
                                    if (data.files && data.files.length > 0) {{
                                        var html = '';
                                        data.files.forEach(function(f) {{
                                            html += '<span class=""file-tag file-tag-click"" onclick=""assignFile(\'' + f.path + '\')"" title=""Click to assign to selected cue"">' + f.path + '</span> ';
                                        }});
                                        container.innerHTML = html;
                                        container.className = 'file-list';
                                    }}
                                }});
                        }}
                    }});
            }}

            // Drag and drop support
            (function() {{
                var area = document.getElementById('uploadArea');
                if (!area) return;
                area.addEventListener('dragover', function(e) {{
                    e.preventDefault();
                    area.classList.add('upload-area-hover');
                }});
                area.addEventListener('dragleave', function(e) {{
                    area.classList.remove('upload-area-hover');
                }});
                area.addEventListener('drop', function(e) {{
                    e.preventDefault();
                    area.classList.remove('upload-area-hover');
                    var files = e.dataTransfer.files;
                    if (files.length > 0) {{
                        var input = document.getElementById('hcaFileInput');
                        input.files = files;
                        uploadFile(input);
                    }}
                }});
            }})();
            </script>
        ");
    }

    private static string HandleMusicPost(HttpListenerRequest request)
    {
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
                return HandleMusicGet(MsgBox("Error: No YAML content received.", "error"));
            }

            // Basic validation: try to parse the YAML
            var validationErrors = ValidateMusicConfig(yaml);
            if (validationErrors.Count > 0)
            {
                var sb = new StringBuilder();
                sb.Append(MsgBoxOpen("warning"));
                sb.Append("<strong>Saved with warnings:</strong><ul>");
                foreach (var w in validationErrors)
                    sb.Append($"<li>{WebUtility.HtmlEncode(w)}</li>");
                sb.Append("</ul>");
                sb.Append(MsgBoxClose());

                // Save anyway (warnings only), then show
                File.WriteAllText(MusicConfigPath, yaml);
                NativeMusicPatch.ReloadConfig();
                return HandleMusicGet(sb.ToString());
            }

            File.WriteAllText(MusicConfigPath, yaml);
            NativeMusicPatch.ReloadConfig();
            return HandleMusicGet(MsgBox("Saved and reloaded! Music overrides updated.", "success"));
        }
        catch (Exception ex)
        {
            return HandleMusicGet(MsgBox($"Error: {ex.Message}", "error"));
        }
    }

    private static string HandleMusicReload()
    {
        try
        {
            NativeMusicPatch.ReloadConfig();
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[WebConfig] Music reload error: {ex.Message}");
        }
        return HandleMusicGet(MsgBox("Reloaded music config from disk.", "success"));
    }

    /// <summary>
    /// POST /music/save - Accepts JSON { overrides: { cue: path, ... } } from the table UI.
    /// Builds YAML, saves it, and hot-reloads the music config.
    /// </summary>
    private static string HandleMusicSave(HttpListenerRequest request)
    {
        try
        {
            string body;
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                body = reader.ReadToEnd();
            }

            if (string.IsNullOrWhiteSpace(body))
                return "{\"error\":\"Empty request body\"}";

            // Simple JSON parsing for { "overrides": { "key": "value", ... } }
            // We parse manually to avoid adding a JSON library dependency
            var overrides = new Dictionary<string, string>();
            int ovIdx = body.IndexOf("\"overrides\"", StringComparison.Ordinal);
            if (ovIdx >= 0)
            {
                int braceStart = body.IndexOf('{', ovIdx);
                if (braceStart >= 0)
                {
                    int depth = 0;
                    int braceEnd = -1;
                    for (int i = braceStart; i < body.Length; i++)
                    {
                        if (body[i] == '{') depth++;
                        else if (body[i] == '}') { depth--; if (depth == 0) { braceEnd = i; break; } }
                    }
                    if (braceEnd > braceStart)
                    {
                        string inner = body.Substring(braceStart + 1, braceEnd - braceStart - 1);
                        // Parse key-value pairs: "key":"value"
                        int pos = 0;
                        while (pos < inner.Length)
                        {
                            int keyStart = inner.IndexOf('"', pos);
                            if (keyStart < 0) break;
                            int keyEnd = inner.IndexOf('"', keyStart + 1);
                            if (keyEnd < 0) break;
                            string key = inner.Substring(keyStart + 1, keyEnd - keyStart - 1);

                            int valStart = inner.IndexOf('"', keyEnd + 1);
                            if (valStart < 0) break;
                            int valEnd = inner.IndexOf('"', valStart + 1);
                            if (valEnd < 0) break;
                            string val = inner.Substring(valStart + 1, valEnd - valStart - 1);

                            // Unescape basic JSON escapes
                            val = val.Replace("\\\\", "\\").Replace("\\\"", "\"").Replace("\\/", "/");

                            if (!string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(val))
                                overrides[key] = val;

                            pos = valEnd + 1;
                        }
                    }
                }
            }

            // Build YAML
            var yamlSb = new StringBuilder();
            yamlSb.AppendLine("# BravelyMod Music Config");
            yamlSb.AppendLine("# Generated by Music Manager UI");
            yamlSb.AppendLine("overrides:");
            if (overrides.Count == 0)
            {
                yamlSb.AppendLine("  # No overrides configured");
            }
            else
            {
                foreach (var kv in overrides.OrderBy(x => x.Key))
                {
                    yamlSb.AppendLine($"  {kv.Key}: {kv.Value}");
                }
            }

            string yaml = yamlSb.ToString();

            // Validate paths
            var warnings = new List<string>();
            string bgmDir = "";
            try { bgmDir = UnityEngine.Application.streamingAssetsPath; } catch { }

            foreach (var kv in overrides)
            {
                if (!string.IsNullOrEmpty(bgmDir))
                {
                    var fullPath = Path.Combine(bgmDir, kv.Value);
                    if (!File.Exists(fullPath))
                        warnings.Add($"File not found: {kv.Value}");
                }
            }

            // Save and reload
            File.WriteAllText(MusicConfigPath, yaml);
            NativeMusicPatch.ReloadConfig();

            Melon<Core>.Logger.Msg($"[WebConfig] Music config saved via table UI: {overrides.Count} override(s)");

            if (warnings.Count > 0)
            {
                string warnMsg = $"Saved {overrides.Count} override(s) with warnings: " + string.Join("; ", warnings);
                return $"{{\"success\":true,\"message\":\"{EscapeJson(warnMsg)}\",\"warnings\":{warnings.Count}}}";
            }

            return $"{{\"success\":true,\"message\":\"Saved {overrides.Count} override(s). Music config reloaded.\"}}";
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[WebConfig] Music save error: {ex.Message}");
            return $"{{\"error\":\"{EscapeJson(ex.Message)}\"}}";
        }
    }

    /// <summary>
    /// GET /music/files - Returns a JSON array of HCA files available in CustomBGM/.
    /// </summary>
    private static string HandleMusicFiles()
    {
        var sb = new StringBuilder();
        sb.Append("{\"files\":[");
        try
        {
            string bgmDir = CustomBgmDir;
            if (!string.IsNullOrEmpty(bgmDir) && Directory.Exists(bgmDir))
            {
                var files = Directory.GetFiles(bgmDir, "*.hca")
                    .Select(f => Path.GetFileName(f))
                    .OrderBy(f => f)
                    .ToArray();

                for (int i = 0; i < files.Length; i++)
                {
                    if (i > 0) sb.Append(",");
                    var name = files[i];
                    var fullPath = Path.Combine(bgmDir, name);
                    var size = new FileInfo(fullPath).Length;
                    sb.Append($"{{\"name\":\"{EscapeJson(name)}\",\"path\":\"CustomBGM/{EscapeJson(name)}\",\"size\":{size}}}");
                }
            }
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[WebConfig] Music files error: {ex.Message}");
        }
        sb.Append("]}");
        return sb.ToString();
    }

    /// <summary>
    /// POST /music/upload - Accepts a multipart HCA file upload and saves to CustomBGM/.
    /// Returns JSON with the relative path on success.
    /// </summary>
    private static string HandleMusicUpload(HttpListenerRequest request)
    {
        try
        {
            string bgmDir = CustomBgmDir;
            if (string.IsNullOrEmpty(bgmDir))
                return "{\"error\":\"CustomBGM directory not available (game not running?).\"}";

            Directory.CreateDirectory(bgmDir);

            // Parse multipart form data to extract the uploaded file
            string contentTypeHeader = request.ContentType;
            if (contentTypeHeader == null || !contentTypeHeader.Contains("multipart/form-data"))
                return "{\"error\":\"Expected multipart/form-data content type.\"}";

            // Extract boundary from content type
            string boundary = null;
            foreach (var part in contentTypeHeader.Split(';'))
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("boundary=", StringComparison.OrdinalIgnoreCase))
                {
                    boundary = trimmed.Substring("boundary=".Length).Trim('"');
                    break;
                }
            }

            if (boundary == null)
                return "{\"error\":\"Could not parse multipart boundary.\"}";

            // Read the entire body
            byte[] bodyBytes;
            using (var ms = new MemoryStream())
            {
                request.InputStream.CopyTo(ms);
                bodyBytes = ms.ToArray();
            }

            // Simple multipart parser: find the file part
            var boundaryBytes = Encoding.UTF8.GetBytes("--" + boundary);
            string fileName = null;
            byte[] fileData = null;

            int pos = 0;
            while (pos < bodyBytes.Length)
            {
                // Find next boundary
                int boundaryStart = FindBytes(bodyBytes, boundaryBytes, pos);
                if (boundaryStart < 0) break;

                int headerStart = boundaryStart + boundaryBytes.Length;
                // Skip CRLF after boundary
                if (headerStart + 1 < bodyBytes.Length && bodyBytes[headerStart] == '\r' && bodyBytes[headerStart + 1] == '\n')
                    headerStart += 2;

                // Check for closing boundary (--boundary--)
                if (headerStart < bodyBytes.Length && bodyBytes[headerStart] == '-' && headerStart + 1 < bodyBytes.Length && bodyBytes[headerStart + 1] == '-')
                    break;

                // Find end of headers (double CRLF)
                int headerEnd = FindBytes(bodyBytes, new byte[] { 0x0D, 0x0A, 0x0D, 0x0A }, headerStart);
                if (headerEnd < 0) break;

                string headers = Encoding.UTF8.GetString(bodyBytes, headerStart, headerEnd - headerStart);
                int dataStart = headerEnd + 4; // skip double CRLF

                // Find next boundary to determine data end
                int nextBoundary = FindBytes(bodyBytes, boundaryBytes, dataStart);
                if (nextBoundary < 0) break;

                // Data ends before CRLF before next boundary
                int dataEnd = nextBoundary - 2; // skip CRLF before boundary
                if (dataEnd < dataStart) dataEnd = dataStart;

                // Check if this part has a filename
                if (headers.Contains("filename="))
                {
                    // Extract filename from Content-Disposition
                    foreach (var line in headers.Split(new[] { "\r\n" }, StringSplitOptions.None))
                    {
                        if (line.StartsWith("Content-Disposition:", StringComparison.OrdinalIgnoreCase))
                        {
                            int fnIdx = line.IndexOf("filename=\"", StringComparison.OrdinalIgnoreCase);
                            if (fnIdx >= 0)
                            {
                                fnIdx += "filename=\"".Length;
                                int fnEnd = line.IndexOf('"', fnIdx);
                                if (fnEnd > fnIdx)
                                    fileName = line.Substring(fnIdx, fnEnd - fnIdx);
                            }
                        }
                    }

                    fileData = new byte[dataEnd - dataStart];
                    Array.Copy(bodyBytes, dataStart, fileData, 0, fileData.Length);
                    break; // take first file
                }

                pos = nextBoundary + boundaryBytes.Length;
            }

            if (fileName == null || fileData == null || fileData.Length == 0)
                return "{\"error\":\"No file found in upload.\"}";

            // Sanitize filename
            fileName = Path.GetFileName(fileName); // strip directory components
            if (string.IsNullOrWhiteSpace(fileName))
                return "{\"error\":\"Invalid filename.\"}";

            string ext = Path.GetExtension(fileName).ToLowerInvariant();
            var allowedExts = new HashSet<string> { ".hca", ".mp3", ".wav", ".ogg", ".flac" };
            if (!allowedExts.Contains(ext))
                return $"{{\"error\":\"Unsupported file format '{EscapeJson(ext)}'. Accepted: .hca, .mp3, .wav, .ogg, .flac\"}}";

            bool isHca = ext == ".hca";

            if (isHca)
            {
                // Validate HCA magic bytes
                if (fileData.Length < 4 || fileData[0] != 0x48 || fileData[1] != 0x43 || fileData[2] != 0x41)
                    return "{\"error\":\"File does not appear to be a valid HCA file (bad magic bytes).\"}";

                // Write HCA directly to CustomBGM/
                string destPath = Path.Combine(bgmDir, fileName);
                File.WriteAllBytes(destPath, fileData);

                string relativePath = $"CustomBGM/{fileName}";
                Melon<Core>.Logger.Msg($"[WebConfig] Uploaded HCA file: {relativePath} ({fileData.Length} bytes)");

                return $"{{\"success\":true,\"path\":\"{EscapeJson(relativePath)}\",\"name\":\"{EscapeJson(fileName)}\",\"size\":{fileData.Length}}}";
            }
            else
            {
                // Non-HCA: save the source file and attempt conversion
                // Sanitize name for filesystem: replace special chars with hyphens
                string baseName = Path.GetFileNameWithoutExtension(fileName);
                string safeBase = System.Text.RegularExpressions.Regex.Replace(baseName, @"[^a-zA-Z0-9._-]", "-");
                safeBase = System.Text.RegularExpressions.Regex.Replace(safeBase, @"-{2,}", "-").Trim('-');
                if (string.IsNullOrWhiteSpace(safeBase)) safeBase = "upload";

                string safeFileName = safeBase + ext;
                string destPath = Path.Combine(bgmDir, safeFileName);
                File.WriteAllBytes(destPath, fileData);

                Melon<Core>.Logger.Msg($"[WebConfig] Saved audio file for conversion: {safeFileName} ({fileData.Length} bytes)");

                // Attempt server-side conversion via shell script
                string hcaName = safeBase + ".hca";
                string convertScript = FindConvertScript();
                string manualCmd = $"scripts/convert_music.sh \"{destPath}\"";

                if (convertScript != null)
                {
                    // Track conversion in progress
                    lock (_conversions)
                    {
                        _conversions[safeBase] = new ConversionStatus
                        {
                            SourcePath = destPath,
                            HcaName = hcaName,
                            ManualCmd = manualCmd,
                            StartedAt = DateTime.UtcNow
                        };
                    }

                    // Start conversion in background thread
                    string _key = safeBase, _script = convertScript, _src = destPath, _bgm = bgmDir;
                    var convThread = new Thread(() => RunConversion(_key, _script, _src, _bgm))
                    { IsBackground = true, Name = "BravelyMod-Convert" };
                    convThread.Start();

                    return $"{{\"converting\":true,\"name\":\"{EscapeJson(safeBase)}\",\"source\":\"{EscapeJson(safeFileName)}\"}}";
                }
                else
                {
                    // No convert script found — tell user to run manually
                    Melon<Core>.Logger.Warning("[WebConfig] convert_music.sh not found — manual conversion needed");
                    return $"{{\"error\":\"File saved to CustomBGM/{EscapeJson(safeFileName)} but automatic conversion is not available. Run manually: {EscapeJson(manualCmd)}\"}}";
                }
            }
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[WebConfig] Music upload error: {ex.Message}");
            return $"{{\"error\":\"{EscapeJson(ex.Message)}\"}}";
        }
    }

    /// <summary>Find a byte sequence within a larger byte array, starting at offset.</summary>
    private static int FindBytes(byte[] haystack, byte[] needle, int offset)
    {
        for (int i = offset; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    // ── Audio conversion support ───────────────────────────────

    private class ConversionStatus
    {
        public string SourcePath;
        public string HcaName;
        public string ManualCmd;
        public DateTime StartedAt;
        public bool Done;
        public bool Success;
        public string Error;
        public string HcaPath; // relative path if successful
        public long HcaSize;
    }

    private static readonly Dictionary<string, ConversionStatus> _conversions = new();

    /// <summary>
    /// Locate the convert_music.sh script. Searches relative to the game directory
    /// and common project paths.
    /// </summary>
    private static string FindConvertScript()
    {
        // Try common locations
        var candidates = new List<string>();

        // Relative to game's StreamingAssets (mod project may be alongside)
        try
        {
            string streamingAssets = UnityEngine.Application.streamingAssetsPath;
            if (!string.IsNullOrEmpty(streamingAssets))
            {
                // Walk up from StreamingAssets to find the project
                string gameDir = Path.GetDirectoryName(Path.GetDirectoryName(streamingAssets));
                if (gameDir != null)
                    candidates.Add(Path.Combine(gameDir, "scripts", "convert_music.sh"));
            }
        }
        catch { }

        // Common dev paths
        string home = Environment.GetEnvironmentVariable("HOME") ?? "";
        candidates.Add(Path.Combine(home, "projects", "bravely-default-rm", "scripts", "convert_music.sh"));
        candidates.Add(Path.Combine(home, "projects", "bravely-default-mod", "scripts", "convert_music.sh"));

        // Check BDFFHD_MOD_DIR env var
        string modDir = Environment.GetEnvironmentVariable("BDFFHD_MOD_DIR");
        if (!string.IsNullOrEmpty(modDir))
            candidates.Add(Path.Combine(modDir, "scripts", "convert_music.sh"));

        foreach (var path in candidates)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    /// <summary>
    /// Run convert_music.sh in a background thread and update ConversionStatus.
    /// </summary>
    private static void RunConversion(string key, string scriptPath, string sourcePath, string bgmDir)
    {
        ConversionStatus status;
        lock (_conversions)
        {
            if (!_conversions.TryGetValue(key, out status)) return;
        }

        try
        {
            Melon<Core>.Logger.Msg($"[WebConfig] Starting conversion: {Path.GetFileName(sourcePath)}");

            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"-c '{scriptPath} \"{sourcePath}\"'",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            // Set environment so the script knows where StreamingAssets is
            try
            {
                string streamingAssets = UnityEngine.Application.streamingAssetsPath;
                if (!string.IsNullOrEmpty(streamingAssets))
                    psi.EnvironmentVariables["BDFFHD_STREAMING_ASSETS"] = Path.GetDirectoryName(streamingAssets) != null
                        ? Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(streamingAssets)) ?? "", "BDFFHD_Data", "StreamingAssets")
                        : streamingAssets;
            }
            catch { }

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                status.Done = true;
                status.Error = "Failed to start conversion process";
                return;
            }

            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();

            proc.WaitForExit(120_000); // 2 minute timeout

            if (!proc.HasExited)
            {
                try { proc.Kill(); } catch { }
                status.Done = true;
                status.Error = "Conversion timed out (2 minutes)";
                Melon<Core>.Logger.Warning($"[WebConfig] Conversion timed out for {key}");
                return;
            }

            if (proc.ExitCode == 0)
            {
                // Check if the HCA file was created
                string hcaPath = Path.Combine(bgmDir, status.HcaName);
                if (File.Exists(hcaPath))
                {
                    status.Done = true;
                    status.Success = true;
                    status.HcaPath = $"CustomBGM/{status.HcaName}";
                    status.HcaSize = new FileInfo(hcaPath).Length;
                    Melon<Core>.Logger.Msg($"[WebConfig] Conversion successful: {status.HcaPath} ({status.HcaSize} bytes)");
                }
                else
                {
                    status.Done = true;
                    status.Error = "Conversion script succeeded but HCA file not found in CustomBGM/";
                    Melon<Core>.Logger.Warning($"[WebConfig] Conversion output not found: {hcaPath}");
                }
            }
            else
            {
                status.Done = true;
                string errMsg = !string.IsNullOrWhiteSpace(stderr) ? stderr.Trim() : stdout.Trim();
                if (errMsg.Length > 500) errMsg = errMsg.Substring(0, 500) + "...";
                status.Error = $"Conversion failed (exit {proc.ExitCode}): {errMsg}";
                Melon<Core>.Logger.Warning($"[WebConfig] Conversion failed for {key}: exit {proc.ExitCode}");
            }
        }
        catch (Exception ex)
        {
            status.Done = true;
            status.Error = $"Conversion error: {ex.Message}";
            Melon<Core>.Logger.Warning($"[WebConfig] Conversion exception for {key}: {ex.Message}");
        }
    }

    /// <summary>
    /// GET /music/convert-status?name=xxx - Poll conversion progress.
    /// </summary>
    private static string HandleConvertStatus(HttpListenerRequest request)
    {
        string name = request.QueryString["name"];
        if (string.IsNullOrWhiteSpace(name))
            return "{\"done\":true,\"error\":\"Missing name parameter\"}";

        ConversionStatus status;
        lock (_conversions)
        {
            if (!_conversions.TryGetValue(name, out status))
                return "{\"done\":true,\"error\":\"No conversion found for this name\"}";
        }

        if (!status.Done)
            return $"{{\"done\":false,\"manual_cmd\":\"{EscapeJson(status.ManualCmd)}\"}}";

        if (status.Success)
        {
            // Clean up tracking entry
            lock (_conversions) { _conversions.Remove(name); }
            return $"{{\"done\":true,\"success\":true,\"path\":\"{EscapeJson(status.HcaPath)}\",\"size\":{status.HcaSize}}}";
        }
        else
        {
            lock (_conversions) { _conversions.Remove(name); }
            return $"{{\"done\":true,\"error\":\"{EscapeJson(status.Error)}\",\"manual_cmd\":\"{EscapeJson(status.ManualCmd)}\"}}";
        }
    }

    private static string HandleConvertFromPath(HttpListenerRequest request)
    {
        try
        {
            string body;
            using (var sr = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
                body = sr.ReadToEnd();

            // Parse path= from form data
            string filePath = null;
            foreach (var pair in body.Split('&'))
            {
                var parts = pair.Split(new[] { '=' }, 2);
                if (parts.Length == 2 && Uri.UnescapeDataString(parts[0].Trim()) == "path")
                    filePath = Uri.UnescapeDataString(parts[1].Trim());
            }

            if (string.IsNullOrWhiteSpace(filePath))
                return "{\"error\":\"No path provided\"}";

            // Convert Wine path to Linux path if needed
            if (filePath.StartsWith("Z:\\") || filePath.StartsWith("Z:/"))
                filePath = filePath.Substring(2).Replace('\\', '/');

            if (!File.Exists(filePath))
                return $"{{\"error\":\"File not found: {EscapeJson(filePath)}\"}}";

            string name = Path.GetFileNameWithoutExtension(filePath);
            string ext = Path.GetExtension(filePath).ToLowerInvariant();

            if (ext == ".hca")
            {
                // Just copy it
                string dest = Path.Combine(CustomBgmDir, Path.GetFileName(filePath));
                File.Copy(filePath, dest, true);
                return $"{{\"success\":true,\"path\":\"CustomBGM/{EscapeJson(Path.GetFileName(filePath))}\",\"size\":{new FileInfo(dest).Length}}}";
            }

            // Start conversion
            string scriptPath = FindConvertScript();
            if (scriptPath == null)
                return $"{{\"error\":\"convert_music.sh not found\",\"manual_cmd\":\"./scripts/convert_music.sh \\\"{EscapeJson(filePath)}\\\"\"}}";

            var status = new ConversionStatus { ManualCmd = $"{scriptPath} \"{filePath}\"" };
            lock (_conversions) { _conversions[name] = status; }

            var n = name; var sp = scriptPath; var fp = filePath; var bd = CustomBgmDir;
            new System.Threading.Thread(() => RunConversion(n, sp, fp, bd)) { IsBackground = true }.Start();

            return $"{{\"converting\":true,\"name\":\"{EscapeJson(name)}\"}}";
        }
        catch (Exception ex)
        {
            return $"{{\"error\":\"{EscapeJson(ex.Message)}\"}}";
        }
    }

    // ── Settings ────────────────────────────────────────────────

    private static string HandleSettingsGet(string messageHtml = null)
    {
        string msgBlock = messageHtml ?? "";

        // Helper to build a checkbox input
        string Checkbox(string name, bool value, string label, string hint = "")
        {
            string chk = value ? "checked" : "";
            string hintHtml = hint != null ? $"<span class=\"setting-hint\">{WebUtility.HtmlEncode(hint)}</span>" : "";
            return $@"<label class=""setting-toggle"">
                <input type=""checkbox"" name=""{name}"" value=""true"" {chk}/>
                <span class=""toggle-label"">{WebUtility.HtmlEncode(label)}</span>{hintHtml}
            </label>";
        }

        // Helper to build a number input for float
        string FloatInput(string name, float value, string label, string hint = null)
        {
            string hintHtml = hint != null ? $"<span class=\"setting-hint\">{WebUtility.HtmlEncode(hint)}</span>" : "";
            return $@"<div class=""setting-field"">
                <label for=""{name}"">{WebUtility.HtmlEncode(label)}</label>{hintHtml}
                <input type=""number"" name=""{name}"" id=""{name}"" value=""{value}"" step=""any"" class=""num-input""/>
            </div>";
        }

        // Helper to build a number input for int
        string IntInput(string name, int value, string label, string hint = null)
        {
            string hintHtml = hint != null ? $"<span class=\"setting-hint\">{WebUtility.HtmlEncode(hint)}</span>" : "";
            return $@"<div class=""setting-field"">
                <label for=""{name}"">{WebUtility.HtmlEncode(label)}</label>{hintHtml}
                <input type=""number"" name=""{name}"" id=""{name}"" value=""{value}"" step=""1"" class=""num-input""/>
            </div>";
        }

        return WrapHtml("Settings", "settings", $@"
            <h2>Mod Settings</h2>
            <p class=""subtitle"">Edit all mod parameters live. Most changes take effect immediately.</p>

            {msgBlock}

            <form method=""POST"" action=""/settings"" id=""settingsForm"">
                <div class=""settings-grid"">

                    <!-- EXP / JP / Gold -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">EXP / JP / Gold</div>
                        {Checkbox("ExpBoostEnabled", Core.ExpBoostEnabled.Value, "Enable EXP/JP/Gold Multiplier")}
                        {FloatInput("ExpMultiplier", Core.ExpMultiplier.Value, "EXP Multiplier", "Default: 10")}
                        {FloatInput("JexpMultiplier", Core.JexpMultiplier.Value, "JP Multiplier", "Default: 1000")}
                        {FloatInput("GoldMultiplier", Core.GoldMultiplier.Value, "Gold Multiplier", "Default: 100")}
                    </div>

                    <!-- Damage Cap -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">Damage Cap</div>
                        {Checkbox("DamageCapEnabled", Core.DamageCapEnabled.Value, "Enable Damage Cap Override")}
                        {IntInput("DamageCapOverride", Core.DamageCapOverride.Value, "Damage Cap", "Default: 999999")}
                    </div>

                    <!-- BP -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">Brave Points (BP)</div>
                        <div class=""restart-badge"">Requires restart</div>
                        {Checkbox("BpModEnabled", Core.BpModEnabled.Value, "Enable BP Modifications")}
                        {IntInput("BpLimitOverride", Core.BpLimitOverride.Value, "BP Limit", "Default: 9")}
                        {IntInput("BpPerTurn", Core.BpPerTurn.Value, "BP Per Turn", "Default: 2 (vanilla: 1)")}
                    </div>

                    <!-- Battle Speed -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">Battle Speed</div>
                        {Checkbox("SpeedModEnabled", Core.SpeedModEnabled.Value, "Enable Battle Speed Mod")}
                        {FloatInput("BattleSpeedMultiplier", Core.BattleSpeedMultiplier.Value, "Speed Multiplier", "Default: 4 (on top of in-game speed)")}
                    </div>

                    <!-- Colony -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">Colony</div>
                        {Checkbox("ColonyModEnabled", Core.ColonyModEnabled.Value, "Enable Colony Speed Mod")}
                        {FloatInput("ColonySpeedMultiplier", Core.ColonySpeedMultiplier.Value, "Colony Speed Multiplier", "Default: 10")}
                    </div>

                    <!-- Scene Skip -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">Scene Skip</div>
                        {Checkbox("ForceSceneSkip", Core.ForceSceneSkip.Value, "Force Scene Skip Always Available")}
                    </div>

                    <!-- Support Cost -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">Support Ability Cost</div>
                        <div class=""restart-badge"">Requires restart</div>
                        {Checkbox("SupportCostModEnabled", Core.SupportCostModEnabled.Value, "Enable Support Cost Override")}
                        {IntInput("SupportCostOverride", Core.SupportCostOverride.Value, "Equip Cost", "Default: 1 (vanilla: 1-4)")}
                    </div>

                    <!-- Walk Speed -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">Walk Speed</div>
                        {Checkbox("WalkSpeedModEnabled", Core.WalkSpeedModEnabled.Value, "Enable Speed Walk")}
                        {FloatInput("WalkSpeedMultiplier", Core.WalkSpeedMultiplier.Value, "Walk Speed Multiplier", "Default: 2.5 (on top of dash)")}
                    </div>

                    <!-- Custom Music -->
                    <div class=""settings-group"">
                        <div class=""settings-group-title"">Custom Music</div>
                        <div class=""restart-badge"">Requires restart</div>
                        {Checkbox("CustomBattleMusicEnabled", Core.CustomBattleMusicEnabled.Value, "Replace Battle BGM with Custom Music")}
                    </div>

                </div>

                <div class=""btn-row settings-actions"">
                    <button type=""submit"" class=""btn-primary"">Save Settings</button>
                    <button type=""button"" class=""btn-secondary"" onclick=""doReset()"">Reset to Defaults</button>
                </div>
            </form>

            <script>
            function doReset() {{
                if (confirm('Reset all settings to their default values?')) {{
                    fetch('/settings/reset', {{method:'POST'}}).then(()=>location.reload());
                }}
            }}
            </script>
        ");
    }

    private static string HandleSettingsPost(HttpListenerRequest request)
    {
        try
        {
            string body;
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                body = reader.ReadToEnd();
            }

            var changes = new List<string>();
            var warnings = new List<string>();

            // Helper to read a bool (checkbox: present=true, absent=false)
            bool ReadBool(string name)
            {
                string val = ExtractFormValue(body, name);
                return val != null && val == "true";
            }

            // Helper to read a float
            float ReadFloat(string name, float fallback)
            {
                string val = ExtractFormValue(body, name);
                if (val != null && float.TryParse(val, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out float result))
                    return result;
                return fallback;
            }

            // Helper to read an int
            int ReadInt(string name, int fallback)
            {
                string val = ExtractFormValue(body, name);
                if (val != null && int.TryParse(val, out int result))
                    return result;
                return fallback;
            }

            // Track changes for user feedback
            void SetBool(MelonPreferences_Entry<bool> entry, bool newVal, string label, bool requiresRestart = false)
            {
                if (entry.Value != newVal)
                {
                    entry.Value = newVal;
                    string note = requiresRestart ? " (requires restart)" : "";
                    changes.Add($"{label}: {(newVal ? "ON" : "OFF")}{note}");
                }
            }

            void SetFloat(MelonPreferences_Entry<float> entry, float newVal, string label, bool requiresRestart = false)
            {
                if (Math.Abs(entry.Value - newVal) > 0.0001f)
                {
                    entry.Value = newVal;
                    string note = requiresRestart ? " (requires restart)" : "";
                    changes.Add($"{label}: {newVal}{note}");
                }
            }

            void SetInt(MelonPreferences_Entry<int> entry, int newVal, string label, bool requiresRestart = false)
            {
                if (entry.Value != newVal)
                {
                    entry.Value = newVal;
                    string note = requiresRestart ? " (requires restart)" : "";
                    changes.Add($"{label}: {newVal}{note}");
                }
            }

            // Apply all settings
            SetBool(Core.ExpBoostEnabled, ReadBool("ExpBoostEnabled"), "EXP Boost");
            SetFloat(Core.ExpMultiplier, ReadFloat("ExpMultiplier", Core.ExpMultiplier.Value), "EXP Multiplier");
            SetFloat(Core.JexpMultiplier, ReadFloat("JexpMultiplier", Core.JexpMultiplier.Value), "JP Multiplier");
            SetFloat(Core.GoldMultiplier, ReadFloat("GoldMultiplier", Core.GoldMultiplier.Value), "Gold Multiplier");

            SetBool(Core.DamageCapEnabled, ReadBool("DamageCapEnabled"), "Damage Cap");
            SetInt(Core.DamageCapOverride, ReadInt("DamageCapOverride", Core.DamageCapOverride.Value), "Damage Cap Value");

            SetBool(Core.BpModEnabled, ReadBool("BpModEnabled"), "BP Mod", requiresRestart: true);
            SetInt(Core.BpLimitOverride, ReadInt("BpLimitOverride", Core.BpLimitOverride.Value), "BP Limit", requiresRestart: true);
            SetInt(Core.BpPerTurn, ReadInt("BpPerTurn", Core.BpPerTurn.Value), "BP Per Turn", requiresRestart: true);

            SetBool(Core.SpeedModEnabled, ReadBool("SpeedModEnabled"), "Battle Speed");
            SetFloat(Core.BattleSpeedMultiplier, ReadFloat("BattleSpeedMultiplier", Core.BattleSpeedMultiplier.Value), "Battle Speed Multiplier");

            SetBool(Core.ColonyModEnabled, ReadBool("ColonyModEnabled"), "Colony Speed");
            SetFloat(Core.ColonySpeedMultiplier, ReadFloat("ColonySpeedMultiplier", Core.ColonySpeedMultiplier.Value), "Colony Speed Multiplier");

            SetBool(Core.ForceSceneSkip, ReadBool("ForceSceneSkip"), "Scene Skip");

            SetBool(Core.SupportCostModEnabled, ReadBool("SupportCostModEnabled"), "Support Cost Mod", requiresRestart: true);
            SetInt(Core.SupportCostOverride, ReadInt("SupportCostOverride", Core.SupportCostOverride.Value), "Support Cost", requiresRestart: true);

            SetBool(Core.WalkSpeedModEnabled, ReadBool("WalkSpeedModEnabled"), "Walk Speed");
            SetFloat(Core.WalkSpeedMultiplier, ReadFloat("WalkSpeedMultiplier", Core.WalkSpeedMultiplier.Value), "Walk Speed Multiplier");

            SetBool(Core.CustomBattleMusicEnabled, ReadBool("CustomBattleMusicEnabled"), "Custom Battle Music", requiresRestart: true);

            // Save to disk
            Core.Config.SaveToFile(false);

            if (changes.Count == 0)
            {
                return HandleSettingsGet(MsgBox("No changes detected.", "warning"));
            }

            bool hasRestartWarning = changes.Any(c => c.Contains("(requires restart)"));

            var sb = new StringBuilder();
            sb.Append(MsgBoxOpen("success"));
            sb.Append($"<strong>Saved {changes.Count} change(s)!</strong><ul>");
            foreach (var c in changes)
                sb.Append($"<li>{WebUtility.HtmlEncode(c)}</li>");
            sb.Append("</ul>");
            if (hasRestartWarning)
                sb.Append("<em>Settings marked \"requires restart\" are saved but won't fully apply until the game is restarted.</em>");
            sb.Append(MsgBoxClose());

            Melon<Core>.Logger.Msg($"[WebConfig] Settings updated: {string.Join(", ", changes)}");

            return HandleSettingsGet(sb.ToString());
        }
        catch (Exception ex)
        {
            return HandleSettingsGet(MsgBox($"Error saving settings: {ex.Message}", "error"));
        }
    }

    private static string HandleSettingsReset()
    {
        try
        {
            Core.ExpBoostEnabled.Value = true;
            Core.ExpMultiplier.Value = 10.0f;
            Core.JexpMultiplier.Value = 1000.0f;
            Core.GoldMultiplier.Value = 100.0f;

            Core.DamageCapEnabled.Value = true;
            Core.DamageCapOverride.Value = 999999;

            Core.BpModEnabled.Value = true;
            Core.BpLimitOverride.Value = 9;
            Core.BpPerTurn.Value = 2;

            Core.SpeedModEnabled.Value = true;
            Core.BattleSpeedMultiplier.Value = 4.0f;

            Core.ColonyModEnabled.Value = true;
            Core.ColonySpeedMultiplier.Value = 10.0f;

            Core.ForceSceneSkip.Value = true;

            Core.SupportCostModEnabled.Value = true;
            Core.SupportCostOverride.Value = 1;

            Core.WalkSpeedModEnabled.Value = true;
            Core.WalkSpeedMultiplier.Value = 2.5f;

            Core.CustomBattleMusicEnabled.Value = true;

            Core.Config.SaveToFile(false);

            Melon<Core>.Logger.Msg("[WebConfig] Settings reset to defaults.");

            return HandleSettingsGet(MsgBox("All settings reset to defaults.", "success"));
        }
        catch (Exception ex)
        {
            return HandleSettingsGet(MsgBox($"Error resetting settings: {ex.Message}", "error"));
        }
    }

    // ── Status ──────────────────────────────────────────────────

    private static string HandleStatus()
    {
        var sb = new StringBuilder();

        // Mod Settings table
        sb.Append("<h2>Mod Status</h2>");
        sb.Append("<p class=\"subtitle\">Current configuration and hook state. Values are read from MelonPreferences.cfg.</p>");

        sb.Append("<div class=\"status-grid\">");

        // Left column: Mod settings
        sb.Append("<div class=\"status-col\">");
        sb.Append("<div class=\"section-label\">Mod Settings</div>");
        sb.Append("<table>");

        void Row(string label, string value, string status = "neutral") =>
            sb.Append($"<tr><td><strong>{WebUtility.HtmlEncode(label)}</strong></td>" +
                       $"<td><span class=\"status-{status}\">{WebUtility.HtmlEncode(value)}</span></td></tr>");

        Row("Version", "0.2.0");
        Row("EXP Boost", Core.ExpBoostEnabled.Value ? $"x{Core.ExpMultiplier.Value}" : "OFF",
            Core.ExpBoostEnabled.Value ? "on" : "off");
        Row("JP Boost", Core.ExpBoostEnabled.Value ? $"x{Core.JexpMultiplier.Value}" : "OFF",
            Core.ExpBoostEnabled.Value ? "on" : "off");
        Row("Gold Boost", Core.ExpBoostEnabled.Value ? $"x{Core.GoldMultiplier.Value}" : "OFF",
            Core.ExpBoostEnabled.Value ? "on" : "off");
        Row("Damage Cap", Core.DamageCapEnabled.Value ? $"{Core.DamageCapOverride.Value}" : "OFF",
            Core.DamageCapEnabled.Value ? "on" : "off");
        Row("BP Limit", Core.BpModEnabled.Value ? $"{Core.BpLimitOverride.Value}" : "OFF",
            Core.BpModEnabled.Value ? "on" : "off");
        Row("BP/Turn", $"{Core.BpPerTurn.Value}", Core.BpPerTurn.Value > 1 ? "on" : "neutral");
        Row("Battle Speed", Core.SpeedModEnabled.Value ? $"x{Core.BattleSpeedMultiplier.Value}" : "OFF",
            Core.SpeedModEnabled.Value ? "on" : "off");
        Row("Colony Speed", Core.ColonyModEnabled.Value ? $"x{Core.ColonySpeedMultiplier.Value}" : "OFF",
            Core.ColonyModEnabled.Value ? "on" : "off");
        Row("Scene Skip", Core.ForceSceneSkip.Value ? "ON" : "OFF",
            Core.ForceSceneSkip.Value ? "on" : "off");
        Row("Support Cost", Core.SupportCostModEnabled.Value ? $"{Core.SupportCostOverride.Value}" : "OFF",
            Core.SupportCostModEnabled.Value ? "on" : "off");
        Row("Walk Speed", Core.WalkSpeedModEnabled.Value ? $"x{Core.WalkSpeedMultiplier.Value}" : "OFF",
            Core.WalkSpeedModEnabled.Value ? "on" : "off");
        Row("Custom BGM", Core.CustomBattleMusicEnabled.Value ? "ON" : "OFF",
            Core.CustomBattleMusicEnabled.Value ? "on" : "off");

        sb.Append("</table>");
        sb.Append("</div>");

        // Right column: AutoBattle info
        sb.Append("<div class=\"status-col\">");
        sb.Append("<div class=\"section-label\">AutoBattle State</div>");

        var engine = NativeAutoBattlePatch.RuleEngine;
        var charNames = new[] { "Tiz", "Agnes", "Ringabel", "Edea" };

        sb.Append("<table>");
        Row("Active Profile", engine.ActiveProfileName, "on");
        Row("Available Profiles", string.Join(", ", engine.ProfileNames));

        for (int i = 0; i < engine.CharacterProfiles.Length && i < charNames.Length; i++)
        {
            var profile = engine.GetProfileForCharacter(i);
            var pName = profile?.Name ?? "(default)";
            var ruleCount = profile?.Rules?.Count ?? 0;
            Row($"{charNames[i]}", $"{pName} ({ruleCount} rules)");
        }
        sb.Append("</table>");

        // Profile details
        sb.Append("<div class=\"section-label\" style=\"margin-top:1em;\">Profile Rules</div>");
        foreach (var profileName in engine.ProfileNames)
        {
            if (engine.AllProfiles.TryGetValue(profileName, out var profile))
            {
                sb.Append($"<div class=\"profile-block\"><strong>{WebUtility.HtmlEncode(profileName)}</strong>");
                if (profile.Rules.Count == 0)
                {
                    sb.Append(" <span class=\"dimmed\">(empty - default behavior)</span>");
                }
                else
                {
                    sb.Append("<ol class=\"rule-list\">");
                    foreach (var rule in profile.Rules)
                    {
                        sb.Append($"<li class=\"mono\">{WebUtility.HtmlEncode(rule.ToShortString())}</li>");
                    }
                    sb.Append("</ol>");
                }
                sb.Append("</div>");
            }
        }

        sb.Append("</div>"); // status-col
        sb.Append("</div>"); // status-grid

        return WrapHtml("Mod Status", "status", sb.ToString());
    }

    // ── API endpoints ───────────────────────────────────────────

    private static string HandleApiStatus()
    {
        // Simple JSON status for external tools
        var engine = NativeAutoBattlePatch.RuleEngine;
        var charNames = new[] { "Tiz", "Agnes", "Ringabel", "Edea" };

        var sb = new StringBuilder();
        sb.Append("{");
        sb.Append("\"version\":\"0.2.0\",");
        sb.Append($"\"activeProfile\":\"{EscapeJson(engine.ActiveProfileName)}\",");
        sb.Append("\"assignments\":[");
        for (int i = 0; i < engine.CharacterProfiles.Length && i < charNames.Length; i++)
        {
            var profile = engine.GetProfileForCharacter(i);
            if (i > 0) sb.Append(",");
            sb.Append($"{{\"name\":\"{EscapeJson(charNames[i])}\",\"profile\":\"{EscapeJson(profile?.Name ?? "(default)")}\"}}");
        }
        sb.Append("],");
        sb.Append($"\"profiles\":[{string.Join(",", engine.ProfileNames.Select(n => $"\"{EscapeJson(n)}\""))}]");
        sb.Append("}");
        return sb.ToString();
    }

    // ── Music validation ────────────────────────────────────────

    private static List<string> ValidateMusicConfig(string yaml)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(yaml))
            return errors; // empty is fine

        try
        {
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
                .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.CamelCaseNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();
            var config = deserializer.Deserialize<NativeMusicPatch.MusicConfig>(yaml);

            if (config?.Overrides != null)
            {
                string bgmDir = "";
                try { bgmDir = UnityEngine.Application.streamingAssetsPath; } catch { }

                foreach (var kv in config.Overrides)
                {
                    if (string.IsNullOrWhiteSpace(kv.Value))
                    {
                        errors.Add($"Override '{kv.Key}' has empty path.");
                        continue;
                    }

                    if (!string.IsNullOrEmpty(bgmDir))
                    {
                        var fullPath = Path.Combine(bgmDir, kv.Value);
                        if (!File.Exists(fullPath))
                        {
                            errors.Add($"HCA file not found: {kv.Value} (expected at {fullPath})");
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add($"YAML parse error: {ex.Message}");
        }

        return errors;
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

    private static string EscapeJson(string s) =>
        (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");

    private static string MsgBox(string text, string type) =>
        $"<div class=\"msg msg-{type}\">{WebUtility.HtmlEncode(text)}</div>";

    private static string MsgBoxOpen(string type) =>
        $"<div class=\"msg msg-{type}\">";

    private static string MsgBoxClose() => "</div>";

    private static string GetDefaultAutoBattleYaml()
    {
        return @"# BravelyMod AutoBattle Profiles
# Rules are evaluated top-to-bottom; first match wins.
# Format: conditions -> actions
# See the cheat sheet on the right for available conditions and actions.

activeProfile: Attack 4x

profiles:
  Attack 4x:
    - ""-> Atk Weak x4""

  Healer:
    - ""HP < 30% -> Cure Self""
    - ""-> Atk Weak""

  Boss Fight:
    - ""HP < 50% -> Cure Ally, Atk Strong x2""
    - ""Foes = 1 -> Atk Strong x4""
    - ""-> Atk Weak x3""

  Nuke:
    - ""BP > 2 & HP > 50% -> Atk Strong x4""
    - ""-> Atk Weak""

  Default: []

# Character slot assignments (Tiz, Agnes, Ringabel, Edea)
assignments:
  - Attack 4x
  - Attack 4x
  - Healer
  - Attack 4x
";
    }

    /// <summary>
    /// Wrap body content in a styled HTML page with navigation.
    /// </summary>
    private static string WrapHtml(string title, string activePage, string bodyContent)
    {
        string NavLink(string href, string label, string page) =>
            page == activePage
                ? $"<a href=\"{href}\" class=\"nav-link nav-active\">{label}</a>"
                : $"<a href=\"{href}\" class=\"nav-link\">{label}</a>";

        string nav = $@"
            <nav class=""navbar"">
                <div class=""nav-brand"">BravelyMod</div>
                <div class=""nav-links"">
                    {NavLink("/", "Dashboard", "")}
                    {NavLink("/autobattle", "AutoBattle", "autobattle")}
                    {NavLink("/music", "Music", "music")}
                    {NavLink("/settings", "Settings", "settings")}
                    {NavLink("/status", "Status", "status")}
                </div>
            </nav>";

        return $@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""utf-8""/>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1""/>
    <title>{WebUtility.HtmlEncode(title)} - BravelyMod</title>
    <style>
        *, *::before, *::after {{ box-sizing: border-box; }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
            margin: 0; padding: 0;
            background: #0f0f1a;
            color: #d0d0d8;
            line-height: 1.6;
        }}

        /* ── Navigation ── */
        .navbar {{
            background: #16162a;
            border-bottom: 2px solid #e4a040;
            padding: 0 2em;
            display: flex;
            align-items: center;
            gap: 2em;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        .nav-brand {{
            font-size: 1.3em;
            font-weight: bold;
            color: #e4a040;
            padding: 0.7em 0;
            letter-spacing: 0.05em;
        }}
        .nav-links {{ display: flex; gap: 0; }}
        .nav-link {{
            color: #8888aa;
            text-decoration: none;
            padding: 0.8em 1.2em;
            font-size: 0.95em;
            border-bottom: 2px solid transparent;
            transition: color 0.2s, border-color 0.2s;
        }}
        .nav-link:hover {{ color: #e0e0e0; border-bottom-color: #5dade2; }}
        .nav-active {{ color: #e0e0e0 !important; border-bottom-color: #e4a040 !important; }}

        /* ── Container ── */
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 1.5em 2em 3em;
        }}

        /* ── Typography ── */
        h2 {{ color: #e4a040; margin-top: 0.5em; margin-bottom: 0.2em; font-size: 1.6em; }}
        .subtitle {{ color: #7777a0; margin-top: 0; margin-bottom: 1.5em; }}
        a {{ color: #5dade2; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .dimmed {{ color: #666688; }}
        .mono {{ font-family: 'Consolas', 'Courier New', monospace; font-size: 0.9em; }}
        code {{ background: #1a1a30; padding: 0.15em 0.4em; border-radius: 3px; font-size: 0.9em; color: #70c0e8; }}

        /* ── Cards (dashboard) ── */
        .hero {{ margin-bottom: 1.5em; }}
        .card-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.2em;
        }}
        .card {{
            background: #16162a;
            border: 1px solid #2a2a44;
            border-radius: 8px;
            padding: 1.5em;
            text-decoration: none;
            color: #d0d0d8;
            transition: border-color 0.2s, transform 0.15s;
            display: block;
        }}
        .card:hover {{ border-color: #e4a040; transform: translateY(-2px); text-decoration: none; }}
        .card-icon {{ font-size: 2em; margin-bottom: 0.3em; }}
        .card-title {{ font-size: 1.2em; font-weight: bold; color: #e4a040; margin-bottom: 0.4em; }}
        .card-desc {{ color: #9999bb; font-size: 0.9em; line-height: 1.5; }}
        .card-footer {{ margin-top: 1em; font-size: 0.8em; color: #666688; }}

        .badge {{
            display: inline-block;
            background: #1a1a30;
            padding: 0.15em 0.6em;
            border-radius: 3px;
            font-size: 0.85em;
            color: #8888bb;
            margin: 0.1em 0;
        }}

        /* ── Editor layout ── */
        .editor-layout {{
            display: grid;
            grid-template-columns: 1fr 340px;
            gap: 1.5em;
            align-items: start;
        }}
        @media (max-width: 900px) {{
            .editor-layout {{ grid-template-columns: 1fr; }}
        }}
        .editor-main {{ min-width: 0; }}
        .editor-sidebar {{ min-width: 0; }}

        .section-label {{
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: #7777a0;
            margin-bottom: 0.6em;
            margin-top: 1em;
        }}

        textarea {{
            width: 100%;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            background: #12122a;
            color: #d0d0d8;
            border: 1px solid #333355;
            padding: 12px;
            border-radius: 6px;
            resize: vertical;
            tab-size: 2;
            line-height: 1.5;
        }}
        textarea:focus {{ outline: none; border-color: #e4a040; }}

        /* ── Buttons ── */
        .btn-row {{ display: flex; gap: 0.8em; margin-top: 0.8em; }}
        .btn-primary {{
            background: #e4a040; color: #0f0f1a; border: none;
            padding: 10px 24px; font-size: 14px; font-weight: bold;
            cursor: pointer; border-radius: 5px;
        }}
        .btn-primary:hover {{ background: #f0b860; }}
        .btn-secondary {{
            background: transparent; color: #8888aa;
            border: 1px solid #444466; padding: 10px 24px;
            font-size: 14px; cursor: pointer; border-radius: 5px;
        }}
        .btn-secondary:hover {{ color: #d0d0d8; border-color: #5dade2; }}

        /* ── Messages ── */
        .msg {{
            padding: 12px 18px;
            border-radius: 6px;
            margin: 1em 0;
            border-left: 4px solid #444;
            line-height: 1.6;
        }}
        .msg ul {{ margin: 0.5em 0 0 0; padding-left: 1.5em; }}
        .msg li {{ margin-bottom: 0.2em; }}
        .msg-success {{ background: #0a2a1a; border-left-color: #2ecc71; color: #a0e8c0; }}
        .msg-error {{ background: #2a0a0a; border-left-color: #e74c3c; color: #e8a0a0; }}
        .msg-warning {{ background: #2a2200; border-left-color: #e4a040; color: #e8d0a0; }}

        /* ── Tables ── */
        table {{ border-collapse: collapse; width: 100%; margin: 0.5em 0; }}
        td, th {{ padding: 8px 12px; border-bottom: 1px solid #222244; text-align: left; }}
        th {{ color: #7777a0; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }}
        tr:hover {{ background: #1a1a30; }}

        .assign-table {{ margin-bottom: 1.5em; }}

        /* ── Cheatsheet ── */
        .cheatsheet {{
            background: #12122a;
            border: 1px solid #2a2a44;
            border-radius: 6px;
            padding: 1em;
            font-size: 0.88em;
        }}
        .cs-section {{ margin-bottom: 1em; }}
        .cs-section:last-child {{ margin-bottom: 0; }}
        .cs-title {{ font-weight: 600; color: #e4a040; margin-bottom: 0.4em; font-size: 0.95em; }}
        .cs-table {{ margin: 0; font-size: 0.95em; }}
        .cs-table td {{ padding: 3px 8px; border-bottom: none; }}
        .cs-note {{ color: #7777a0; margin: 0.3em 0 0; font-size: 0.9em; }}
        .cs-example {{
            background: #0f0f1a;
            padding: 0.6em;
            border-radius: 4px;
            font-size: 0.9em;
            color: #a0c8e0;
            margin: 0.3em 0 0;
            overflow-x: auto;
        }}

        /* ── Status page ── */
        .status-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2em;
            align-items: start;
        }}
        @media (max-width: 800px) {{
            .status-grid {{ grid-template-columns: 1fr; }}
        }}
        .status-col {{ min-width: 0; }}

        .status-on {{ color: #2ecc71; font-weight: 600; }}
        .status-off {{ color: #e74c3c; }}
        .status-neutral {{ color: #d0d0d8; }}

        .profile-block {{
            background: #12122a;
            border: 1px solid #2a2a44;
            border-radius: 6px;
            padding: 0.8em 1em;
            margin-bottom: 0.6em;
        }}
        .rule-list {{
            margin: 0.4em 0 0;
            padding-left: 1.5em;
            color: #a0c8e0;
        }}
        .rule-list li {{ margin-bottom: 0.15em; }}

        /* ── Music page ── */
        .file-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.4em;
            margin: 0.5em 0 1em;
        }}
        .file-tag {{
            display: inline-block;
            background: #0a2a1a;
            border: 1px solid #2a4a3a;
            color: #a0e8c0;
            padding: 0.2em 0.7em;
            border-radius: 4px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.85em;
        }}
        .file-tag-click {{
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s;
        }}
        .file-tag-click:hover {{
            background: #0e3a24;
            border-color: #4a8a6a;
        }}

        /* ── Upload area ── */
        .upload-section {{
            margin-top: 1em;
        }}
        .upload-area {{
            border: 2px dashed #333355;
            border-radius: 8px;
            padding: 1.2em;
            text-align: center;
            transition: border-color 0.2s, background 0.2s;
            margin-top: 0.5em;
        }}
        .upload-area-hover {{
            border-color: #e4a040;
            background: #1a1a2a;
        }}
        .upload-prompt {{
            cursor: pointer;
            color: #7777a0;
            font-size: 0.95em;
        }}
        .upload-prompt:hover {{
            color: #d0d0d8;
        }}
        .upload-icon {{
            font-size: 1.5em;
            display: block;
            margin-bottom: 0.3em;
        }}
        .upload-status {{
            margin-top: 0.8em;
            padding: 8px 12px;
            border-radius: 5px;
            font-size: 0.9em;
        }}
        .upload-status-info {{ background: #1a1a30; color: #8888bb; }}
        .upload-status-success {{ background: #0a2a1a; color: #a0e8c0; }}
        .upload-status-error {{ background: #2a0a0a; color: #e8a0a0; }}

        .cue-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.8em;
            margin: 0.5em 0;
        }}
        @media (max-width: 500px) {{
            .cue-grid {{ grid-template-columns: 1fr; }}
        }}
        .cue-group {{
            background: #12122a;
            border: 1px solid #2a2a44;
            border-radius: 6px;
            padding: 0.8em;
            font-size: 0.85em;
            line-height: 1.7;
        }}

        /* ── BGM Override Table ── */
        .bgm-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 0.5em 0 1.5em;
            font-size: 0.9em;
        }}
        .bgm-table thead th {{
            background: #16162a;
            color: #7777a0;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
            padding: 10px 12px;
            border-bottom: 2px solid #2a2a44;
            text-align: left;
            position: sticky;
            top: 0;
        }}
        .bgm-table tbody tr {{
            border-bottom: 1px solid #1a1a30;
            transition: background 0.15s;
        }}
        .bgm-table tbody tr:nth-child(even) {{
            background: #12122a;
        }}
        .bgm-table tbody tr:nth-child(odd) {{
            background: #0f0f1a;
        }}
        .bgm-table tbody tr:hover {{
            background: #1a1a35;
        }}
        .bgm-row-selected {{
            background: #1a2a3a !important;
            outline: 1px solid #5dade2;
        }}
        .bgm-table td {{
            padding: 8px 12px;
            vertical-align: middle;
        }}
        .bgm-cue-name {{
            font-family: 'Consolas', 'Courier New', monospace;
            color: #70c0e8;
            font-weight: 600;
            white-space: nowrap;
        }}
        .bgm-desc {{
            color: #9999bb;
        }}
        .bgm-status-custom {{
            color: #2ecc71;
            font-weight: 600;
            font-size: 0.85em;
        }}
        .bgm-status-custom::before {{
            content: '\2713 ';
        }}
        .bgm-status-default {{
            color: #666688;
            font-size: 0.85em;
        }}
        .bgm-path-cell {{
            min-width: 200px;
            max-width: 350px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.85em;
            color: #a0e8c0;
            word-break: break-all;
        }}
        .bgm-path-input {{
            width: 100%;
            padding: 6px 8px;
            background: #0f0f1a;
            color: #d0d0d8;
            border: 1px solid #5dade2;
            border-radius: 4px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.95em;
        }}
        .bgm-path-input:focus {{
            outline: none;
            border-color: #e4a040;
        }}
        .bgm-actions {{
            white-space: nowrap;
        }}
        .btn-sm {{
            padding: 4px 10px;
            font-size: 0.8em;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-weight: 600;
            margin-right: 4px;
            transition: background 0.15s;
        }}
        .btn-set {{
            background: #2a3a5a;
            color: #70c0e8;
        }}
        .btn-set:hover {{
            background: #3a4a6a;
        }}
        .btn-remove {{
            background: #3a1a1a;
            color: #e8a0a0;
        }}
        .btn-remove:hover {{
            background: #4a2a2a;
        }}

        /* BGM category collapsible sections */
        .bgm-category {{
            margin-bottom: 0.5em;
        }}
        .bgm-category-header {{
            display: flex;
            align-items: center;
            gap: 0.6em;
            padding: 10px 14px;
            background: #16162a;
            border: 1px solid #2a2a44;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s;
            user-select: none;
        }}
        .bgm-category-header:hover {{
            background: #1a1a35;
            border-color: #5dade2;
        }}
        .bgm-toggle-arrow {{
            color: #7777a0;
            font-size: 0.8em;
            width: 1em;
            text-align: center;
        }}
        .bgm-category-label {{
            font-weight: 600;
            color: #d0d0d8;
            font-size: 0.95em;
        }}
        .bgm-cat-badge {{
            font-size: 0.75em;
            background: #0a2a1a;
            color: #2ecc71;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: 600;
        }}
        .bgm-category-body {{
            padding: 0.5em 0 0;
        }}

        /* BGM save row */
        .bgm-save-row {{
            margin-top: 1.5em;
            padding-top: 1em;
            border-top: 1px solid #2a2a44;
            align-items: center;
        }}
        .bgm-save-status {{
            font-size: 0.9em;
            margin-left: 1em;
        }}
        .bgm-save-info {{ color: #8888bb; }}
        .bgm-save-success {{ color: #2ecc71; font-weight: 600; }}
        .bgm-save-error {{ color: #e74c3c; }}

        .bgm-summary {{
            display: inline-block;
            background: #0a2a1a;
            color: #2ecc71;
            padding: 2px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 600;
            margin-left: 0.5em;
        }}

        /* ── Settings page ── */
        .settings-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.2em;
            margin-bottom: 1.5em;
        }}
        .settings-group {{
            background: #16162a;
            border: 1px solid #2a2a44;
            border-radius: 8px;
            padding: 1.2em 1.4em;
        }}
        .settings-group-title {{
            font-size: 1em;
            font-weight: 700;
            color: #e4a040;
            margin-bottom: 0.8em;
            padding-bottom: 0.4em;
            border-bottom: 1px solid #2a2a44;
        }}
        .setting-toggle {{
            display: flex;
            align-items: center;
            gap: 0.6em;
            margin-bottom: 0.7em;
            cursor: pointer;
            flex-wrap: wrap;
        }}
        .setting-toggle input[type=""checkbox""] {{
            width: 18px;
            height: 18px;
            accent-color: #e4a040;
            cursor: pointer;
            flex-shrink: 0;
        }}
        .toggle-label {{
            color: #d0d0d8;
            font-size: 0.93em;
        }}
        .setting-hint {{
            font-size: 0.8em;
            color: #666688;
            margin-left: 0.3em;
        }}
        .setting-field {{
            margin-bottom: 0.7em;
        }}
        .setting-field label {{
            display: block;
            font-size: 0.9em;
            color: #9999bb;
            margin-bottom: 0.3em;
        }}
        .num-input {{
            width: 100%;
            max-width: 200px;
            background: #12122a;
            color: #d0d0d8;
            border: 1px solid #333355;
            padding: 8px 10px;
            border-radius: 5px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 14px;
        }}
        .num-input:focus {{
            outline: none;
            border-color: #e4a040;
        }}
        .restart-badge {{
            display: inline-block;
            background: #2a2200;
            border: 1px solid #e4a040;
            color: #e4a040;
            font-size: 0.72em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 0.2em 0.6em;
            border-radius: 3px;
            margin-bottom: 0.8em;
        }}
        .settings-actions {{
            margin-top: 0.5em;
            padding-top: 1em;
            border-top: 1px solid #2a2a44;
        }}
    </style>
</head>
<body>
    {nav}
    <div class=""container"">
        {bodyContent}
    </div>
</body>
</html>";
    }
}
