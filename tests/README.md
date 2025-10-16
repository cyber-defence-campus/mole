# Tests

This directory contains the test suite for the Mole project, migrated to pytest framework.

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

### Build test binaries

Before running slicing tests, you need to compile the test binaries:

```bash
cd tests/data
make all
```

### Run all tests

```bash
pytest
```

### Run specific test files

```bash
pytest tests/test_data.py
pytest tests/slicing/test_pointer.py
```

### Run specific test classes or methods

```bash
pytest tests/slicing/test_pointer.py::TestPointerAnalysis
pytest tests/slicing/test_pointer.py::TestPointerAnalysis::test_pointer_analysis_01
```

## Migration from unittest

The tests have been migrated from `unittest` to `pytest`:

- `unittest.TestCase` → `pytest` fixtures and classes
- `self.assertEqual()` → `assert` statements
- `self.assertTrue()` → `assert` statements
- `@unittest.expectedFailure` → `@pytest.mark.xfail`
- `setUp()` → `@pytest.fixture(autouse=True)`

## Test Categories

- **Slicing tests** (`tests/slicing/`): Test backward slicing functionality
  - Function calling patterns
  - Pointer analysis
  - Name mangling (C++)
  - Struct handling
  - Simple HTTP server scenarios
  - Serialization
  - Multi-threading consistency

- **Data tests** (`tests/test_data.py`): Test data class serialization

- **Parser tests** (`tests/test_logic_expr_parsing.py`): Test logical expression parsing
