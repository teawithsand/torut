# torut

Torut is tor controller written in rust similar to 
[stem](https://stem.torproject.org/) or [bine](https://github.com/cretz/bine).
It tries to reasonably implement [specification of tor control port proto](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)
It works in asynchronously with tokio and async/await.

It does implements onion service key and address generation and serialization on it's own without tor process.

Right now logic is quite tightly coupled with tokio so there is no way to
remove tokio from dependencies and make all functions synchronous.

# Security considerations
Right now comparing keys/onion services *IS NOT CONSTANT TIME* which may lead to leaking some values.
All constant time compared types are explicitly marked at least in their documentation.

Also please note that this library is relatively new and may contain bugs(and dynamically changing APIs) thus I personally think
that it should not be used for any security critical project yet.

This crate is of course as safe as tor instance that you are using so keep your software up to date.

Also right now due to some issues I was not able to fetch(compile to be precise) ed25519-dalek from crates.io
so right now this dependency is fetched from it's github master branch.
It's *probably* secure because right now it's used only for key generation but keep that in mind before using it. I'll fix this ASAP.
You may also want to take a [look at it's github repo](https://github.com/dalek-cryptography/ed25519-dalek) first.

# Testing 
Tests in torut are split into two parts:
these which do use tor and these which do not use tor.
In order to enable tests which use tor use `RUSTFLAGS="--cfg=testtor"`

Please also note that some of tests may fail against older 
versions of tor(for instance with apt-get installed one on default ubuntu installation)

# Note
Some of checks used in the protocol implementation may be overly restrictive.
If one was really found to be so open an issue.