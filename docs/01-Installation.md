# Installation

## Plugin Manager
*Mole* is available through the *Binary Ninja* [Plugin Manager](https://docs.binary.ninja/guide/plugins.html#plugin-manager):
- Open Binary Ninja
- Navigate to `Plugins` / `Manage Plugins`
- Search for `Mole`
- Click `Install`

This is the simplest available installation method. However, if you also want to use *Mole* in **headless mode** or contribute to development, follow the manual installation instructions below.

## Manual Installation
In the following, we assume that the variables `$BINJA_BIN` and `$BINJA_USR` point to your *Binary Ninja*'s [binary path](https://docs.binary.ninja/guide/index.html#binary-path) and [user folder](https://docs.binary.ninja/guide/index.html#user-folder), respectively.

Use the following steps to install *Mole* manually:

1. Clone the repository into the *Binary Ninja* user plugins directory:
    ```shell
    cd $BINJA_USR/plugins/
    git clone https://github.com/cyber-defence-campus/mole.git mole-dev && cd mole-dev/
    ```
    **Warning:** Avoid naming the target directory `mole`. Using `mole` may conflict with installations managed by the Plugin Manager.

2. Install *Mole* using one of the following options:
    
    **Option 1**: Using `uv`:
    ```shell
    # Option 1.A: Standard installation
    uv run python $BINJA_BIN/scripts/install_api.py
    # Option 1.B: Development installation
    uv run --extra dev python $BINJA_BIN/scripts/install_api.py
    uv run pre-commit install
    # Run Mole headless
    uv run mole -h
    ```
    **Option 2**: Using `python-pip`:
    ```shell
    # Create and activate a Python virtual environment (optional, but recommended)
    python3 -m venv .venv
    source .venv/bin/activate
    # Install the Binary Ninja Python API
    python $BINJA_BIN/scripts/install_api.py
    # Option 2.A: Standard installation
    pip install .
    # Option 2.B: Development installation
    pip install -e .[dev]
    pre-commit install
    # Run Mole headless
    mole -h
    ```

3. Depending on your setup, you may need to configure *Binary Ninja* to use the same **Python interpreter** and **virtual environment** as *Mole*.

    Relevant settings:
    - `python.interpreter`
    - `python.virtualenv`

    Example values:

    `python.interpreter` (or):
    - `~/.local/share/uv/python/cpython-3.11-linux-x86_64-gnu/lib/libpython3.11.so`
    - `/usr/lib/x86_64-linux-gnu/libpython3.11.so.1.0`

    `python.virtualenv`:
    - `$BINJA_USR/plugins/mole-dev/.venv/lib/python3.11/site-packages`

----------------------------------------------------------------------------------------------------
[Back-To-README](../README.md#documentation)