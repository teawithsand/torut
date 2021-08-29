# torut
[![Build Status](https://travis-ci.org/teawithsand/torut.svg?branch=master)](https://travis-ci.org/teawithsand/torut)

Torut is tor controller written in rust similar to 
[stem](https://stem.torproject.org/) or [bine](https://github.com/cretz/bine).
It tries to reasonably implement [specification of tor control port proto](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)
It works asynchronously with tokio and async/await.

It implements onion service key and address generation and serialization on its own without tor process.

Right now logic is quite tightly coupled with tokio so there is no way to
remove tokio from dependencies and make all functions synchronous.

## Status of onion service V2
Code handling V2 services has been removed in 0.2 release, since tor project removed(should have?) v2 handling code 
from their codebase as well.
See [This page](https://blog.torproject.org/v2-deprecation-timeline)

# Testing 
Tests in torut are split into two parts:
these which do use tor and these which do not use tor.
In order to enable tests which use tor use `RUSTFLAGS="--cfg=testtor"`
and provide `TORUT_TESTING_TOR_BINARY` environment variable containing path to tor binary.
Testing tor binary MUST be run with `--test-threads=1` for instance like:

`$ RUSTFLAGS="--cfg testtor" cargo test -- --test-threads=1`