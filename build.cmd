@echo off
setlocal

cmake "%~dp0/src" -B "%~dp0/obj" -DCMAKE_INSTALL_PREFIX="%~dp0/bin"
set exit_code=%errorlevel%
if not %exit_code% == 0 (
    exit /b %exit_code%
)

cmake --build "%~dp0/obj" --target install
