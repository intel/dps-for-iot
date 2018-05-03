#!/bin/sh
set -ex
git clone https://github.com/swig/swig.git swig/swig
cd swig/swig
git checkout rel-3.0.12
wget -O 968.patch https://github.com/swig/swig/pull/968.patch
git am 968.patch
./autogen.sh
./configure --prefix=/usr
make -j 4
sudo make install
