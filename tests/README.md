# Tests

This directory contains the test suite for the Mole project.

## Running Tests

### Build Test Binaries

Before running slicing tests, compile the test binaries:

```bash
cd tests/data
make all
```

To cross-compile the binaries for a specific architecture:

```bash
CC=arm-linux-gcc CXX=arm-linux-g++ EXT=.linux-armv7 make
```

### Run All Tests

```bash
pytest
```

### Run Specific Test Files

```bash
pytest tests/test_data.py
pytest tests/slicing/test_pointer.py
```

### Run Specific Test Classes or Methods

```bash
pytest tests/slicing/test_pointer.py::TestPointerAnalysis
pytest tests/slicing/test_pointer.py::TestPointerAnalysis::test_pointer_analysis_01
```

### Run Slicing Tests for a Specific Architecture

To run tests with a specific architecture extension, use the `EXT` parameter that matches the one used during compilation:

```bash
EXT=".linux-armv7" pytest
```