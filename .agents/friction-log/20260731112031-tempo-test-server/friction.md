---
title: 'Tempo test server returns HTTP 400 before first block'
severity: 'minor'
---

## Expected Behavior

The Tempo test harness waits until the first canonical block is readable before suite setup queries `latest`.

## Current Behavior

The server reports that it started, but `eth_getBlockByNumber(latest, false)` immediately returns HTTP 400 and all 74 focused Earn tests are skipped. The failure reproduced twice with different generated RPC paths.

## Possible Solution

Poll the server until `getBlock` succeeds with a nonzero timestamp before running suite setup.

## Minimal Reproducible Example

Run `./node_modules/.bin/vitest -c ./test/vitest.config.ts src/tempo/actions/earn.test.ts --run`.

## Context

This blocks focused validation of Tempo Earn actions even though TypeScript validation passes.
