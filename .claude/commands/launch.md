Launch BDFFHD via Steam with MelonLoader, then fullscreen it.

IMPORTANT: Never run Xvfb or virtual displays while launching for the user.

Steps:
1. Kill any Xvfb instances: `pkill -f Xvfb 2>/dev/null; rm -f /tmp/.X99-lock`
2. Kill any running BDFFHD processes: `pkill -9 -f "BDFFHD" 2>/dev/null; pkill -9 -f "reaper.*2833580" 2>/dev/null; pkill -9 -f "pressure-vessel.*2833580" 2>/dev/null`
3. Wait 8 seconds for full cleanup
4. Delete old log: `rm -f ~/.steam/debian-installation/steamapps/common/BDFFHD/MelonLoader/Latest.log`
5. Launch via: `xdg-open "steam://rungameid/2833580" 2>/dev/null &` (this works more reliably than `steam -applaunch`)
6. Wait 50 seconds for Proton + MelonLoader + IL2CPP
7. Fullscreen the window via KWin script:
   ```bash
   cat > /tmp/kwin_fs.js << 'EOF'
   var clients = workspace.windowList();
   for (var i = 0; i < clients.length; i++) {
       var c = clients[i];
       if (c.caption === "BRAVELY DEFAULT FLYING FAIRY") {
           c.fullScreen = true;
       }
   }
   EOF
   qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.loadScript "/tmp/kwin_fs.js"
   qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.start
   ```
8. Check `~/.steam/debian-installation/steamapps/common/BDFFHD/MelonLoader/Latest.log` for `[BravelyMod]` messages
9. Report: which hooks attached, any errors, mod version
