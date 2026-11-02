# Study checks

These beginner-friendly scripts are simplified study adaptations of the test and packet-inspection files in the [secure-inline-channel repository](https://github.com/arelibaghdadian/secure-inline-channel). The repository is the source for the original design and examples; credit it when reusing them.

Run the small checks from the `sc` project folder with `python3 -m checks.<module_name>`. For example: `python3 -m checks.cache_check`.

`inspect_queue` is different: it listens to Linux NFQUEUE and requires a configured lab queue and administrator privileges. It only prints packet information and accepts packets unchanged. Use it only in your isolated project lab.

These are learning checks, not a complete test suite or proof of production security. The nonce example shows only that some input changes produce different nonces; it does not prove uniqueness for every TCP case.
