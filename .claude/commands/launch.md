Launch BDFFHD via Steam with MelonLoader. Kill any existing game processes first, then launch and monitor the MelonLoader log for mod loading status.

Steps:
1. Kill any running BDFFHD/wine processes for app 2833580
2. Wait 2 seconds for cleanup
3. Delete the MelonLoader Latest.log so we get a fresh one
4. Launch via: `xdg-open "steam://rungameid/2833580" &`
4. Wait 25 seconds for MelonLoader to initialize
5. Read and display the tail of `~/.steam/debian-installation/steamapps/common/BDFFHD/MelonLoader/Latest.log`
6. Report whether BravelyMod loaded successfully
