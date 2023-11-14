# README

This is engine for PASTIS, that allows to launch Sydr-Fuzz framework.
Sydr-Fuzz is a proprietary hybrid fuzzing tool that combines AFL++
fuzzer with symbolic execution engine named Sydr.

## Installation

`pastis-sydr` depends on `libpastis`, which could be installed by pip:

```bash
pip install pastis-framework
```

To install `pastis-sydr` just run `pip install .` in pastis-sydr directory.

### Running it in offline mode

1. Set environment variables:

```bash
export SYDR_PATH=</path/to/sydr-fuzz>  # by default sydr-fuzz is expected at /fuzz/sydr/sydr-fuzz
export SYDR_WS=</path/to/workspace>    # the default value is /tmp/sydr_workspace
```

2. Run:

For binary-only fuzzing (Qemu mode) Sydr and AFL++ are launched on the same target <fuzz_target>.
When using file as input source, `@@` would be automatically added to <ARGS> if it wasn't specified.

```bash
# stdin input source
pastis-sydr offline --corpus inputs --input-source STDIN --fuzzmode BINARY_ONLY <fuzz_target> <ARGS>

# File input source
pastis-sydr offline --corpus inputs --input-source ARGV --fuzzmode BINARY_ONLY <fuzz_target> <ARGS>
```

For source-instrumentation fuzzing AFL++ use instrumented target <fuzz_target>. Uninstrumented target for Sydr
expected to be in package.other_files in package.zip:

```bash
zip -r package.zip <fuzz_target> <sydr_target>
pastis-sydr offline --corpus inputs --input-source STDIN --fuzzmode INSTRUMENTED -p package.zip <fuzz_target> <ARGS>
```

### Running it in online mode

1. Set environment variables:

```bash
export SYDR_PATH=</path/to/sydr-fuzz>
export SYDR_WS=</path/to/workspace>    # the default value is /tmp/sydr_workspace
```

2. Run Client:

```bash
pastis-sydr online -h <ip> -p <port>
```

### Launching pastis-sydr with PastisBroker

1. Build pastis (https://github.com/quarkslab/pastis.git) and install sydrbroker:
```bash
git clone https://github.com/quarkslab/pastis.git pastis
cd pastis
docker build -t pastis-framework .
docker run --rm -it -p 5555:5555 -v $PWD:/mnt pastis-framework bash
cd /mnt/engines && git clone https://github.com/apach301/pastis-sydr.git
cd pastis-sydr/broker-addon && pip install .
```

2. Build pastis-sydr (in another container):
```bash
git clone https://github.com/apach301/pastis-sydr.git
cd pastis-sydr
docker build -t pastis-sydr .
docker run --rm -it -v $PWD:/mnt pastis-sydr bash
```

3. Launch broker and pastis-sydr in the corresponding containers:
```bash
[pastis-framework] ./bin/pastis-benchmark run --workspace /mnt/output --bins </path/to/target/bin> --seeds </path/to/init_corpus> --mode NO_TRANSMIT --injloc ARGV --timeout 300 --port 5555 --start-quorum 1 --allow-remote
[pastis-sydr] cd /pastis && SYDR_WS=/mnt/sydr-workspace ./bin/pastis-sydr online -h <ip> -p 5555
```
