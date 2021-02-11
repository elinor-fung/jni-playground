@echo off
setlocal

set __generate=0
if not exist "%~dp0/obj/CMakeCache.txt" set __generate=1
if "%1"=="regenerate" set __generate=1

if %__generate%==1 (
    cmake "%~dp0/src" -B "%~dp0/obj" -DCMAKE_INSTALL_PREFIX="%~dp0/bin"
)

cmake --build "%~dp0/obj" --target install
