Launch BDFFHD via Steam with MelonLoader.

IMPORTANT: Never run Xvfb or virtual displays while launching for the user. Their multi-monitor KDE Wayland setup is fragile. Kill any Xvfb instances first.

Steps:
1. Kill any Xvfb instances: `pkill -f Xvfb; rm -f /tmp/.X99-lock`
2. Kill any running BDFFHD processes: `pkill -f "BDFFHD.exe" 2>/dev/null`
3. Wait 5 seconds for full cleanup
4. Delete old log: `rm ~/.steam/debian-installation/steamapps/common/BDFFHD/MelonLoader/Latest.log`
5. Launch via: `steam -applaunch 2833580 &` (NOT xdg-open, NOT steam:// protocol — direct applaunch is most reliable)
6. Wait 45 seconds for Proton + MelonLoader + IL2CPP assembly generation
7. Check `~/.steam/debian-installation/steamapps/common/BDFFHD/MelonLoader/Latest.log` for `[BravelyMod]` messages
8. Report: which hooks attached, any errors, mod version
9. If no log after 45s, check `~/.steam/steam/logs/console-linux.txt` for launch errors
