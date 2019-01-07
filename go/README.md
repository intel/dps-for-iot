## Building and running

### Linux

``` shell
cd $DPS_FOR_IOT/go/src
GOPATH=$GOPATH:$DPS_FOR_IOT/go go install *
```

``` shell
cd $DPS_FOR_IOT/go/bin
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$DPS_FOR_IOT/build/dist/lib ./simple_pub
```

### Windows
Note that DPS must be built with the MinGW toolchain for use with Go.

``` shell
set GOPATH=%GOPATH%;%DPS_FOR_IOT%\go
cd %DPS_FOR_IOT%\go\src
go install dps simple_pub simple_pub_ks simple_sub simple_sub_ks
```

``` shell
cd %DPS_FOR_IOT%\go\bin
simple_pub
```
