## Running

### Linux

``` shell
cd $DPS_FOR_IOT/build/dist/go
./simple_pub
```

### Windows
Note that DPS must be built with the MinGW toolchain for use with Go.
``` shell
scons --tool=mingw bindings=go
```

``` shell
cd %DPS_FOR_IOT%\build\dist\go
simple_pub
```
