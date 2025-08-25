# Windows Terminal Hook Hotkey

Simply utility to open the current directory in Windows Terminal with ``Ctrl + \`` hotkey.

## How it works

* It uses Windows API to set a global hotkey.
* When the hotkey is pressed, it finds the current explorer.exe process
* It gets the cwd of the explorer.exe process
* It launches Windows Terminal with cwd

## Build

* Requires Visual Studio 2022 with C++ workload
* `build.ps1` script to build the project using `clang-cl`
