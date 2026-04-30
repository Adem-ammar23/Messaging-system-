@echo off
setlocal


set SODIUM_DIR=%~dp0third_party\libsodium
set INC_DIR=%SODIUM_DIR%\include


set LIB_DIR=%SODIUM_DIR%\x64\Release\v143\dynamic

cl /nologo /O2 /LD crypto.c ^
  /I "%INC_DIR%" ^
  /link /DEF:crypto.def ^
  /LIBPATH:"%LIB_DIR%" libsodium.lib ^
  /OUT:crypto.dll

endlocal
  