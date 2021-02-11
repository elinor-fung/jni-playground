# jni-playground

Simple console application that loads the JVM

## Requirements

- [CMake 3.15+](https://cmake.org/install/)
- [OpenJDK 8](https://openjdk.java.net/install/)

## Build/Run

- Set `JAVA_HOME` to JDK install path
- Update `PATH`/`LD_LIBRARY_PATH` with path to JVM (e.g. `<JAVA_HOME>/jre/bin/server`)
- Run the build script (`build.cmd`/`build.sh`) at the root of the repo
- Run one of the hosts:
    - Native: `bin/nativehost`
    - .NET: `bin/DotNetHost`