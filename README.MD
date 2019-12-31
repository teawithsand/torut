# torut

Torut is tor controller written in rust similar to 
[stem](https://stem.torproject.org/) or [bine](https://github.com/cretz/bine).
It tries to reasonably implement [specification of tor control port proto](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)
It works in asynchronously with tokio and async/await.

It does implements key generation and serialization on it's own without tor process.

Right now logic is quite tightly coupled with tokio so there is no way to
remove tokio from dependencies and make all functions synchronous.

# Testing 
Tests in torut are split into two parts:
these which do use tor and these which do not use tor.
In order to enable tests which use tor use `RUSTFLAGS="--cfg=testtor"`

Please also note that some of tests may fail against older 
versions of tor(for instance with apt-get installed one on default ubuntu installation)