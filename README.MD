# torut
[![Build Status](https://travis-ci.org/teawithsand/torut.svg?branch=master)](https://travis-ci.org/teawithsand/torut)

Torut is tor controller written in rust similar to 
[stem](https://stem.torproject.org/) or [bine](https://github.com/cretz/bine).
It tries to reasonably implement [specification of tor control port proto](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)
It works asynchronously with tokio and async/await.

It implements onion service key and address generation and serialization on it's own without tor process.

Right now logic is quite tightly coupled with tokio so there is no way to
remove tokio from dependencies and make all functions synchronous.

## Status of onion service V2
For now, code handling them is still in this library, but it will be removed soon.
See [This page](https://blog.torproject.org/v2-deprecation-timeline)

## Usage considerations
In case there is no OpenSSL installed on your target machine you can embbed it into rust binary.
In order to do that use `vendored_openssl` feature.

# Testing 
Tests in torut are split into two parts:
these which do use tor and these which do not use tor.
In order to enable tests which use tor use `RUSTFLAGS="--cfg=testtor"`
and provide `TORUT_TESTING_TOR_BINARY` environment variable containing path to tor binary.
Testing tor binary MUST be run with `--test-threads=1` for instance like:

`$ RUSTFLAGS="--cfg testtor" cargo test -- --test-threads=1`

Please also note that some of tests may fail against older 
versions of tor(for instance with apt-get installed one on default ubuntu installation)