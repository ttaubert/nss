@ECHO OFF

SET todo=%1

SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

REM Reset some env vars and set some others.
SET CYGWIN=
SET INCLUDE=
SET LIB=
IF NOT DEFINED MOZ_NO_RESET_PATH (
  SET PATH=%SystemRoot%\System32;%SystemRoot%;%SystemRoot%\System32\Wbem
)

REM mintty is available as an alternate terminal, but is not enabled by default due
REM to various usability regressions. Set USE_MINTTY to 1 to enable it.
IF NOT DEFINED USE_MINTTY (
  SET USE_MINTTY=
)

SET ERROR=
SET MOZILLABUILD=%~dp0
SET TOOLCHAIN=

REM Figure out if we're on a 32-bit or 64-bit host OS.
REM NOTE: Use IF ERRORLEVEL X to check if the last ERRORLEVEL was GEQ(greater or equal than) X.
SET WINCURVERKEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
REG QUERY "%WINCURVERKEY%" /v "ProgramFilesDir (x86)" >nul 2>nul
IF NOT ERRORLEVEL 1 (
  SET WIN64=1
) ELSE (
  REM Bail early if the x64 MSVC start script is invoked on a 32-bit host OS.
  REM Note: We explicitly aren't supporting x86->x64 cross-compiles.
  IF "%MOZ_MSVCBITS%" == "64" (
    SET ERROR=The MSVC 64-bit toolchain is not supported on a 32-bit host OS. Exiting.
    GOTO _QUIT
  )
  SET WIN64=0
)

REM Append moztools to PATH
IF "%WIN64%" == "1" (
  SET MOZ_TOOLS=%MOZILLABUILD%moztools-x64
) ELSE (
  SET MOZ_TOOLS=%MOZILLABUILD%moztools
)
SET PATH=%PATH%;%MOZ_TOOLS%\bin

REM Set up LLVM if present.
SET LLVMDIR=
IF "%WIN64%" == "1" (
  SET LLVMKEY=HKLM\SOFTWARE\Wow6432Node\LLVM\LLVM
) ELSE (
  SET LLVMKEY=HKLM\SOFTWARE\LLVM\LLVM
)
REM Find the LLVM installation directory
REG QUERY "!LLVMKEY!" /ve >nul 2>nul
IF NOT ERRORLEVEL 1 (
  FOR /F "tokens=2*" %%A IN ('REG QUERY "!LLVMKEY!" /ve') DO SET LLVMDIR=%%B
  SET PATH=%PATH%;!LLVMDIR!\bin
)

REM Set up the MSVC environment if called from one of the start-shell-msvc batch files.
IF DEFINED MOZ_MSVCVERSION (
  IF NOT DEFINED VCDIR (
    REM Set the MSVC registry key.
    IF "%WIN64%" == "1" (
      SET MSVCKEY=HKLM\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\%MOZ_MSVCVERSION%.0\Setup\VC
    ) ELSE (
      SET MSVCKEY=HKLM\SOFTWARE\Microsoft\VisualStudio\%MOZ_MSVCVERSION%.0\Setup\VC
    )

    REM Find the MSVC installation directory and bail if none is found.
    REG QUERY !MSVCKEY! /v ProductDir >nul 2>nul
    IF ERRORLEVEL 1 (
      SET ERROR=Microsoft Visual C++ %MOZ_MSVCYEAR% was not found. Exiting.
      GOTO _QUIT
    )
    FOR /F "tokens=2*" %%A IN ('REG QUERY !MSVCKEY! /v ProductDir') DO SET VCDIR=%%B
  )

  IF NOT DEFINED SDKDIR (
    REM Set the Windows SDK registry keys.
    IF "%WIN64%" == "1" (
      SET SDKPRODUCTKEY=HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Microsoft SDKs\Windows\v8.1
    ) ELSE (
      SET SDKPRODUCTKEY=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.1
    )

    REM Windows SDK 8.1
    REG QUERY "!SDKPRODUCTKEY!" /v ProductName >nul 2>nul
    IF NOT ERRORLEVEL 1 (
      FOR /F "tokens=2*" %%A IN ('REG QUERY "!SDKPRODUCTKEY!" /v InstallationFolder') DO (
        REM The Installed Products key still exists even if the SDK is uninstalled.
        REM Verify that the Windows.h header exists to confirm that the SDK is installed.
        IF EXIST "%%B\Include\um\Windows.h" (
          SET SDKDIR=%%B
        )
      )

      REM Bail if no Windows SDK is found.
      IF NOT DEFINED SDKDIR (
        SET ERROR=No Windows SDK found. Exiting.
        GOTO _QUIT
      )

      SET SDKVER=8
      SET SDKMINORVER=1
    )
  )

  REM Prepend MSVC paths.
  IF "%MOZ_MSVCBITS%" == "32" (
    REM Prefer cross-compiling 32-bit builds using the 64-bit toolchain if able to do so.
    IF "%WIN64%" == "1" IF EXIST "!VCDIR!\bin\amd64_x86\vcvarsamd64_x86.bat" (
      CALL "!VCDIR!\bin\amd64_x86\vcvarsamd64_x86.bat"
      SET TOOLCHAIN=64-bit cross-compile
    )

    REM LIB will be defined if vcvarsamd64_x86.bat has already run.
    REM Fall back to vcvars32.bat if it hasn't.
    IF NOT DEFINED LIB (
      IF EXIST "!VCDIR!\bin\vcvars32.bat" (
        CALL "!VCDIR!\bin\vcvars32.bat"
        SET TOOLCHAIN=32-bit
      )
    )
  ) ELSE IF "%MOZ_MSVCBITS%" == "64" (
      IF EXIST "!VCDIR!\bin\amd64\vcvars64.bat" (
        CALL "!VCDIR!\bin\amd64\vcvars64.bat"
        SET TOOLCHAIN=64-bit
      )
  )

  REM LIB will be defined if a vcvars script has run. Bail if it isn't.
  IF NOT DEFINED LIB (
    SET ERROR=Unable to call a suitable vcvars script. Exiting.
    GOTO _QUIT
  )

  REM Add the DIA SDK paths needed for dump_syms.
  SET INCLUDE=!VCDIR!..\DIA SDK\include;!INCLUDE!
  IF "%MOZ_MSVCBITS%" == "32" (
    SET LIB=!VCDIR!..\DIA SDK\lib;!LIB!
  ) ELSE (
    SET LIB=!VCDIR!..\DIA SDK\lib\amd64;!LIB!
  )
)

cd "%USERPROFILE%"
IF "%USE_MINTTY%" == "1" (
  START %MOZILLABUILD%msys\bin\mintty -e %MOZILLABUILD%msys\bin\console %MOZILLABUILD%msys\bin\bash --login %todo%
) ELSE (
  %MOZILLABUILD%msys\bin\bash --login -i %todo%
)
EXIT /B

:_QUIT
ECHO MozillaBuild Install Directory: %MOZILLABUILD%
IF DEFINED VCDIR (ECHO Visual C++ %MOZ_MSVCYEAR% Directory: !VCDIR!)
IF DEFINED SDKDIR (ECHO Windows SDK Directory: !SDKDIR!)
IF DEFINED TOOLCHAIN (ECHO Trying to use the MSVC %MOZ_MSVCYEAR% !TOOLCHAIN! toolchain.)
ECHO.
ECHO %ERROR%
ECHO.
PAUSE
EXIT /B
