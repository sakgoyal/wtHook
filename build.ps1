# start developer command prompt
Push-Location "C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/Tools";
./Launch-VsDevShell.ps1 -arch amd64;
Pop-Location;

# if hotkey.exe is already running, kill it, so we can overwrite the file
Get-Process hotkey -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() };


clang-cl hotkey.cpp /EHsc /MD /W4 /std:c++latest /O2 /Gw /Gy;
Write-Host "Build complete. Run hotkey.exe" -ForegroundColor DarkGreen;
