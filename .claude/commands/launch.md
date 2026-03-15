Launch BDFFHD via Steam with MelonLoader, then fullscreen it.

IMPORTANT: Never run Xvfb or virtual displays while launching for the user.

Steps:
1. Kill any Xvfb: `pkill -f Xvfb 2>/dev/null; rm -f /tmp/.X99-lock`
2. Kill game processes: `pkill -9 -f "BDFFHD" 2>/dev/null; pkill -9 -f "reaper.*2833580" 2>/dev/null; pkill -9 -f "pressure-vessel.*2833580" 2>/dev/null; pkill -9 -f "steam-launch-wrapper.*2833580" 2>/dev/null`
3. Kill stale wineserver (critical — prevents Steam from thinking game is still running):
   ```
   WINEPREFIX="$HOME/.steam/debian-installation/steamapps/compatdata/2833580/pfx" \
     "$HOME/.steam/debian-installation/steamapps/common/Proton - Experimental/files/bin/wineserver" -k 2>/dev/null
   ```
4. Wait 8 seconds
5. Delete old log: `rm -f ~/.steam/debian-installation/steamapps/common/BDFFHD/MelonLoader/Latest.log`
6. Launch: `xdg-open "steam://rungameid/2833580" 2>/dev/null &`
7. Wait 50 seconds
8. Fullscreen via KWin:
   ```bash
   cat > /tmp/kwin_fs.js << 'EOF'
   var clients = workspace.windowList();
   for (var i = 0; i < clients.length; i++) {
       if (clients[i].caption === "BRAVELY DEFAULT FLYING FAIRY") clients[i].fullScreen = true;
   }
   EOF
   qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.loadScript "/tmp/kwin_fs.js"
   qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.start
   ```
9. Check log for `[BravelyMod]` messages and report status
