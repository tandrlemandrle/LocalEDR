@echo off
echo Building LocalEDR...
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:LocalEDR.exe /platform:x64 /target:exe /win32icon:..\Autorun.ico /win32manifest:LocalEDR.manifest /reference:System.Management.dll /reference:System.ServiceProcess.dll /optimize+ LocalEDR.cs
if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful: LocalEDR.exe
    echo.
    echo   Double-click or run it = installs + starts service automatically
    echo   LocalEDR.exe uninstall = stops + removes everything
) else (
    echo.
    echo Build failed.
)
pause
