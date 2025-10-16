# Tests

This directory contains the test suite for the mole package, migrated to pytest framework.

## Test Structure

- `tests/slicing/` - Tests for backward slicing functionality
  - `conftest.py` - Shared fixtures and base test class for slicing tests
  - `test_various.py` - Tests for various slicing scenarios (gets, sscanf, memcpy, fread)
  - `test_function_calling.py` - Tests for function calling scenarios
  - `test_pointer.py` - Tests for pointer analysis
  - `test_struct.py` - Tests for struct handling
  - `test_mangling.py` - Tests for C++ name mangling
  - `test_simple_server.py` - Tests for simple HTTP server scenarios
  - `test_serialization.py` - Tests for path serialization
  - `test_multithreading.py` - Tests for multi-threading consistency

- `tests/test_data.py` - Tests for data classes and configuration serialization
- `tests/test_logic_expr_parsing.py` - Tests for logical expression parsing

- `tests/data/` - Test assets
  - `src/` - C/C++ source files for test cases
  - `Makefile` - Makefile to compile test binaries
  - `bin/` - Compiled test binaries (generated, not in version control)

## Running Tests

To run all tests:
```bash
pytest
```

To run tests for a specific module:
```bash
pytest tests/slicing/test_pointer.py
```

To run a specific test:
```bash
pytest tests/slicing/test_pointer.py::TestPointerAnalysis::test_pointer_analysis_01
```

## Compiling Test Binaries

Before running slicing tests, compile the test binaries:
```bash
cd tests/data
make
```

To compile for different architectures:
```bash
CC=arm-linux-gcc CXX=arm-linux-g++ EXT=.linux-armv7 make
```

## Requirements

- pytest >= 8.0.0
- Binary Ninja (for slicing tests)
