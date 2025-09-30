# Testing

To improve code robustness and discover potential program defects or logical vulnerabilities, attention should be paid to writing test programs during project development. For this purpose, unit tests have been written following Rust program conventions in this project.

## Unit Tests

This project currently supports running in multiple different TEE environments. Since some logic depends on specific TEE environment support, some tests will be skipped in non-TEE environments. Therefore, it is recommended to run unit tests separately in non-TEE and TEE environments.

- Run unit tests in non-TEE environment or TDX environment

    ```sh
    just run-test-in-host
    ```

- Run unit tests in Occlum environment

    ```sh
    just run-test-in-occlum
    ```

This project also adds [automated testing](/.github/workflows/build-and-test.yaml) in the form of Github Actions (CI/CD), which runs unit tests for every new Commit/Pull Request to ensure that new submissions do not break existing functionality. Nevertheless, corresponding unit tests should be created as much as possible when adding new features.

## Code Coverage

Calculating code coverage provides guidance for understanding the coverage scope of program testing and writing unit tests. This project provides [instrumentation-based code coverage](https://doc.rust-lang.org/rustc/instrument-coverage.html#instrumentation-based-code-coverage) calculation, which can calculate code coverage results while running unit tests.

The project has encapsulated the related processes, and you can directly use the following statement to run coverage calculation:

```sh
just code-coverage
```
> [!IMPORTANT]  
> Since some unit tests depend on specific TEE environment support, this means that complete code coverage calculation needs to be run in different TEE environments separately, and then merged to obtain accurate coverage. In the current implementation, the above statement needs to be run on an SGX platform and will only calculate code coverage for non-TEE and Occlum environments (SGX).
>
> This limitation exists because the TDX and SGX environments used for development are not on the same instance, so future improvements are needed to implement automated merging of code coverage data across multiple TEE instances.

The program instance output is as follows:
```txt
Filename                                     Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
transport/spdm/transport.rs                       56                14    75.00%          11                 3    72.73%         131                20    84.73%          12                 4    66.67%
transport/spdm/io/framed_stream.rs                66                23    65.15%          11                 5    54.55%         103                18    82.52%          16                 5    68.75%
transport/spdm/secret/asym_crypto.rs              86                41    52.33%           7                 1    85.71%         181                80    55.80%           8                 5    37.50%
transport/spdm/secret/measurement.rs              84                34    59.52%          10                 3    70.00%         189                37    80.42%          20                 9    55.00%
transport/spdm/secret/cert_validation.rs          20                 4    80.00%           6                 0   100.00%          48                 5    89.58%           2                 1    50.00%
transport/spdm/secret/cert_provider.rs            22                 6    72.73%           5                 0   100.00%          64                12    81.25%           4                 2    50.00%
transport/spdm/requester.rs                      104                48    53.85%           9                 4    55.56%         303                84    72.28%           6                 1    83.33%
transport/spdm/half.rs                            35                10    71.43%           3                 0   100.00%          89                12    86.52%           6                 3    50.00%
transport/spdm/responder.rs                      112                46    58.93%          12                 5    58.33%         365                86    76.44%           4                 1    75.00%
crypto/mod.rs                                     58                20    65.52%           7                 1    85.71%          80                20    75.00%           0                 0         -
errors.rs                                         31                22    29.03%          17                12    29.41%          85                55    35.29%           0                 0         -
cert/verify.rs                                   155                44    71.61%          13                 1    92.31%         192                25    86.98%          14                 2    85.71%
cert/dice/extensions.rs                           18                 6    66.67%           8                 4    50.00%          50                12    76.00%           0                 0         -
cert/dice/mod.rs                                  42                 7    83.33%           3                 1    66.67%          56                 1    98.21%           0                 0         -
cert/dice/cbor.rs                                108                24    77.78%          15                 0   100.00%         172                18    89.53%           2                 1    50.00%
cert/create.rs                                    76                17    77.63%          11                 1    90.91%         116                 4    96.55%           2                 0   100.00%
tee/sgx_dcap/evidence.rs                          32                13    59.38%           9                 0   100.00%          88                40    54.55%          22                16    27.27%
tee/sgx_dcap/claims.rs                             1                 0   100.00%           1                 0   100.00%          78                 0   100.00%           0                 0         -
tee/sgx_dcap/verifier.rs                          55                22    60.00%           4                 1    75.00%          89                32    64.04%           6                 4    33.33%
tee/sgx_dcap/attester.rs                          22                 6    72.73%           3                 0   100.00%          37                 5    86.49%           4                 1    75.00%
tee/sgx_dcap/mod.rs                               17                 2    88.24%           1                 0   100.00%          20                 0   100.00%           2                 0   100.00%
tee/mod.rs                                        54                 5    90.74%          14                 0   100.00%         101                 9    91.09%           6                 0   100.00%
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                           1254               414    66.99%         180                42    76.67%        2637               575    78.19%         136                55    59.56%
```

The output shows that line coverage has reached 78.19%

Related artifacts will be stored in the `target-sbcc/coverage/` directory. In addition to the code coverage output in the command line, you can also view the code execution coverage in each file through a browser. First, you need to start a static file server:

```sh
python3 -m http.server --directory target-sbcc/coverage/www/
```

Then open http://localhost:8000/ in your browser to view.
