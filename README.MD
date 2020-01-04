# torut
[![Build Status](https://travis-ci.org/teawithsand/torut.svg?branch=master)](https://travis-ci.org/teawithsand/torut)

Torut is tor controller written in rust similar to 
[stem](https://stem.torproject.org/) or [bine](https://github.com/cretz/bine).
It tries to reasonably implement [specification of tor control port proto](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)
It works asynchronously with tokio and async/await.

It does implements onion service key and address generation and serialization on it's own without tor process.

Right now logic is quite tightly coupled with tokio so there is no way to
remove tokio from dependencies and make all functions synchronous.

# Security considerations
Right now comparing keys/onion services *IS NOT CONSTANT TIME* which may lead to leaking some values.
All constant time compared types are explicitly marked at least in their documentation.

Also please note that this library is relatively new and may contain bugs(and dynamically changing APIs) thus I personally think
that it should not be used for any security critical project yet.

This crate is of course as safe as tor instance that you are using so keep your software up to date.

Right now it uses `1.0.0-pre.3` version of `ed25519-dalek` library for v3 onion services
The library may not be well-established yet until 1.0 release will be available. 

## Attack scenario
So one may think that torCP client is not an attack surface but it may lead to deanonymization of client under
some circumstances(or even RCE in case of bug in tor or "feature" of tor control protocol intended for trusted input
but it's much less probable. Tor has really good security history compared to other C projects).
Imagine that `RESOLVE` command is implemented badly and input is untrusted(for example we resolve domain from some email software)

Then attacker can put domain like: 
`example.com\r\nDROPGUARDS`
so command looks like 
`RESOLVE example.com\r\nDROPGUARDS\r\n`

which would cause `DROPGUARDS` command to be issued on tor instance.
Knowing timing of when this happened eavesdropper may try to deanonymize client. 

## Less important security considerations
Right now it also does not implement server authenticity check when one is connecting to tor control protocol
but it's hardly an issue. 
Once implemented it may prevent us from using cookie in wrong tor process instance in best case.
Right now we do not reveal cookie event if connected to wrong tor process anyway due to how HMAC works.

#### Unsafe code
Right now this crate uses `#![forbid(unsafe_code)]` 
annotation which means that it contains 0 unsafe code blocks so it should not be a concern
despite the fact that usually(almost always) tor process is considered trusted.

# Testing 
Tests in torut are split into two parts:
these which do use tor and these which do not use tor.
In order to enable tests which use tor use `RUSTFLAGS="--cfg=testtor"`
and provide `TORUT_TESTING_TOR_BINARY` environment variable containing path to tor binary.
Testing tor binary MUST be run with `--test-threads=1` for instance like:

`$ RUSTFLAGS="--cfg testtor" cargo test -- --test-threads=1`

Please also note that some of tests may fail against older 
versions of tor(for instance with apt-get installed one on default ubuntu installation)