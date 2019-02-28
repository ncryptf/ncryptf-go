#!/bin/sh
# The purpose of this file is to install libsodium in
# the Travis CI environment. Outside this environment,
# you would probably not want to install it like this.

set -e

# check if libsodium is already installed
if [ ! -d "$HOME/libsodium/lib" ]; then
  wget https://github.com/jedisct1/libsodium/releases/download/$LIBSODIUM_VERSION/libsodium-$LIBSODIUM_VERSION.tar.gz
  tar xvfz libsodium-$LIBSODIUM_VERSION.tar.gz
  cd libsodium-$LIBSODIUM_VERSION
  ./configure --prefix=$HOME/libsodium-$LIBSODIUM_VERSION
  make
  make install
else
  echo 'Using cached directory.'
fi