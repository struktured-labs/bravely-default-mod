using System;
using System.Collections.Generic;
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

                case "/music" when method == "GET":
                    responseBody = HandleMusicGet();
                    break;

                case "/music" when method == "POST":
                    responseBody = HandleMusicPost(request);
                    break;

                case "/music/reload" when method == "POST":
                    responseBody = HandleMusicReload();
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
                <a href=""/status"" class=""card"">
                    <div class=""card-icon"">&#9881;</div>
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

    // ── Music ───────────────────────────────────────────────────

    private static string HandleMusicGet(string messageHtml = null)
    {
        string yaml = "";
        try
        {
            if (File.Exists(MusicConfigPath))
                yaml = File.ReadAllText(MusicConfigPath);
            else
                yaml = "# No music config found. Save to create one.\noverrides:\n  # bgmbtl_01: CustomBGM/your-file.hca\n";
        }
        catch (Exception ex)
        {
            yaml = $"# Error reading file: {ex.Message}";
        }

        string msgBlock = messageHtml ?? "";

        // List available HCA files
        var hcaHtml = new StringBuilder();
        hcaHtml.Append("<div class=\"section-label\">Available HCA Files in CustomBGM/</div>");
        try
        {
            string bgmDir = CustomBgmDir;
            if (!string.IsNullOrEmpty(bgmDir) && Directory.Exists(bgmDir))
            {
                var files = Directory.GetFiles(bgmDir, "*.hca")
                    .Select(f => Path.GetFileName(f))
                    .OrderBy(f => f)
                    .ToArray();

                if (files.Length > 0)
                {
                    hcaHtml.Append("<div class=\"file-list\">");
                    foreach (var f in files)
                        hcaHtml.Append($"<span class=\"file-tag\">CustomBGM/{WebUtility.HtmlEncode(f)}</span> ");
                    hcaHtml.Append("</div>");
                }
                else
                {
                    hcaHtml.Append("<p class=\"dimmed\">No .hca files found in CustomBGM/ folder.</p>");
                }
            }
            else
            {
                hcaHtml.Append("<p class=\"dimmed\">CustomBGM/ folder not found at StreamingAssets path.</p>");
            }
        }
        catch (Exception ex)
        {
            hcaHtml.Append($"<p class=\"dimmed\">Error scanning folder: {WebUtility.HtmlEncode(ex.Message)}</p>");
        }

        // Build cue name reference
        var cueRefHtml = @"
            <div class=""section-label"">BGM Cue Reference</div>
            <div class=""cue-grid"">
                <div class=""cue-group"">
                    <div class=""cs-title"">Battle</div>
                    <code>bgmbtl_01</code> Normal battle<br/>
                    <code>bgmbtl_02</code> Boss battle<br/>
                    <code>bgmbtl_03</code> Asterisk holder<br/>
                    <code>bgmbtl_08</code> Victory fanfare<br/>
                    <code>bgmbtl_10</code> Rare encounter<br/>
                    <code>bgmbtl_16</code> Final boss
                </div>
                <div class=""cue-group"">
                    <div class=""cs-title"">Field/Town</div>
                    <code>bgmfld_01</code> Overworld<br/>
                    <code>bgmfld_04</code> Airship<br/>
                    <code>bgmtwn_01</code> Caldisla<br/>
                    <code>bgmtwn_02</code> Florem<br/>
                    <code>bgmtwn_03</code> Grandship
                </div>
                <div class=""cue-group"">
                    <div class=""cs-title"">Dungeon</div>
                    <code>bgmdgn_01</code> Ruins<br/>
                    <code>bgmdgn_02</code> Temples<br/>
                    <code>bgmdgn_05</code> Endgame
                </div>
                <div class=""cue-group"">
                    <div class=""cs-title"">Event/System</div>
                    <code>bgmevt_01</code> Prologue<br/>
                    <code>bgmsys_01</code> Title screen<br/>
                    <code>bgmsys_08</code> Game over
                </div>
            </div>
        ";

        return WrapHtml("Music Config", "music", $@"
            <h2>Music Overrides</h2>
            <p class=""subtitle"">Replace BGM cues with custom HCA audio files. Files are resolved relative to StreamingAssets/.</p>

            {msgBlock}
            {hcaHtml}

            <div class=""editor-layout"">
                <div class=""editor-main"">
                    <div class=""section-label"">Music Config Editor</div>
                    <form method=""POST"" action=""/music"">
                        <textarea name=""yaml"" rows=""28"" spellcheck=""false"">{WebUtility.HtmlEncode(yaml)}</textarea>
                        <div class=""btn-row"">
                            <button type=""submit"" class=""btn-primary"">Save &amp; Reload</button>
                            <button type=""button"" class=""btn-secondary"" onclick=""doReloadMusic()"">Reload from Disk</button>
                        </div>
                    </form>
                </div>
                <div class=""editor-sidebar"">
                    {cueRefHtml}
                    <div class=""section-label"" style=""margin-top:1.5em;"">Config Format</div>
                    <div class=""cheatsheet"">
                        <pre class=""cs-example"">overrides:
  bgmbtl_01: CustomBGM/my-battle.hca
  bgmbtl_02: CustomBGM/boss-theme.hca</pre>
                        <p class=""cs-note"">Paths are relative to StreamingAssets/.</p>
                    </div>
                </div>
            </div>

            <script>
            function doReloadMusic() {{
                fetch('/music/reload', {{method:'POST'}}).then(()=>location.reload());
            }}
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
