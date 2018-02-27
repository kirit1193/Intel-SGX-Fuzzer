# Intel SGX Fuzzer

This program is aimed towards the fuzzing of the sealing and unsealing of data within a Secure Enclave, using [Intel SGX](https://github.com/01org/linux-sgx/) on Linux.

This template is based on the SampleEnclave app of the sample enclaves provided with the Intel SGX Linux [drivers](https://github.com/01org/linux-sgx-driver) and [SDK](https://github.com/01org/linux-sgx/).

## Features

- Safe file-read to receive fuzzing input
- Proper error handling to allow AFL to detect crashes
- Sealing and Unsealing of Data

## Compiling

Due to the way SGX is coded, it cannot be instrumented properly. So the best way to compile this code is to first compile using afl-gcc (edit the Makefile). This will build the instrumented app, but not the enclave binaries. Rename this app to app2 and now compile using gcc (recommended 4.8). This will build the enclave binaries and another app file which you can ignore. Use app2 to fuzz.

## Contribute

Any help for the above TODOs or any general feedback will be much appreciated! Go ahead and submit those PRs in!
