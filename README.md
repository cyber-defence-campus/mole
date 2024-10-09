[![Publish Release](https://github.com/pdamian/mole/actions/workflows/release.yml/badge.svg)](https://github.com/pdamian/mole/actions/workflows/release.yml)
# Mole
*Mole* is a *Binary Ninja* plugin that tries to identify **interesting paths** (from sources to
sinks) using **static backward slicing**. The plugin can be run both in *Binary Ninja* and in
headless mode.
## Installation
In the following, we assume that the variables `$BINJA_BIN` and `$BINJA_USR` point to your
*Binary Ninja*'s [binary path](https://docs.binary.ninja/guide/index.html#binary-path) and
[user folder](https://docs.binary.ninja/guide/index.html#user-folder), respectively.

Clone the *Mole* plugin to your *Binary Ninja*'s user folder:
```shell
cd $BINJA_USR/plugins/
git clone https://github.com/pdamian/mole.git && cd mole/
```
### Standard
Create and activate a new Python virtual environment for *Mole* (optional, but recommended):
```shell
python3 -m venv venv/mole
source venv/mole/bin/activate
```

Install *Binary Ninja*'s Python [API](https://docs.binary.ninja/dev/batch.html#install-the-api):
```shell
$BINJA_BIN/scripts/install_api.py
```

Install *Mole*:
```shell
pip install .
```
### Development
```shell
# Python virtual environment
python3 -m venv venv/mole_dev
source venv/mole_dev/bin/activate

# Binary Ninja Python API
$BINJA_BIN/scripts/install_api.py

# Mole
pip install .[develop]
```
