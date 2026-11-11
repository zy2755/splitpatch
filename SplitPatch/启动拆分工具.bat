@echo off
chcp 65001 >nul
cd /d "%~dp0"
title SplitPatch - Integrated Package Splitter

rem Pick the first Python that actually has tkinter (some minimal builds omit it).
rem You can also drag a .apk/.zip onto this .bat to preload it.

py -3.14 -c "import tkinter" >nul 2>&1
if not errorlevel 1 (
    py -3.14 "%~dp0splitpatch_gui.py" %*
    goto :done
)

py -c "import tkinter" >nul 2>&1
if not errorlevel 1 (
    py "%~dp0splitpatch_gui.py" %*
    goto :done
)

python -c "import tkinter" >nul 2>&1
if not errorlevel 1 (
    python "%~dp0splitpatch_gui.py" %*
    goto :done
)

echo.
echo [ERROR] No Python interpreter with tkinter was found on this machine.
echo The command-line engine still works with any Python 3.10+:
echo     python splitpatch.py "your_package.zip"
echo.
pause
exit /b 1

:done
if errorlevel 1 (
    echo.
    echo [GUI exited with an error] See the message above.
    pause
)
