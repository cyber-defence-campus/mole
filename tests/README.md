# Tests

This directory contains the test suite for the Mole project.

## Structure

```
tests/
├── __init__.py
├── data/                       # Test assets (source files, Makefile, binaries)
│   ├── Makefile               # Makefile to compile test binaries
│   ├── src/                   # C/C++ source files for test cases
│   └── bin/                   # Compiled test binaries (generated, not in git)
├── slicing/                   # Slicing-related tests
│   ├── conftest.py            # Shared pytest fixtures and base classes
│   ├── test_function_calling.py
│   ├── test_pointer.py
│   ├── test_mangling.py
│   ├── test_struct.py
│   ├── test_simple_server.py
│   ├── test_various.py
│   ├── test_serialization.py
│   └── test_multithreading.py
├── test_data.py               # Data serialization tests
└── test_logic_expr_parsing.py # Logical expression parser tests
```

## Running Tests

### Build Test Binaries

Before running slicing tests, compile the test binaries:

```bash
cd tests/data
make all
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

### Run Slicing Tests Against a Specific Architecture

First, cross-compile the binaries for the desired architecture:

```bash
CC=arm-linux-gcc CXX=arm-linux-g++ EXT=.linux-armv7 make
```

Then run the tests with the extension parameter:

```bash
EXT=".linux-armv7" pytest
```