#!/bin/sh
RUSTFLAGS="--cfg testtor" cargo test -- --test-threads=1
