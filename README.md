# mole
Binary Ninja Plugin for Vulnerability Discovery
## Installation
In the following, we assume that the variables `$BINJA_BIN` and `$BINJA_USR` point to your _Binary Ninja_'s [binary path](https://docs.binary.ninja/guide/index.html#binary-path) and [user folder](https://docs.binary.ninja/guide/index.html#user-folder), respectively.
Clone the _Mole_ plugin to your _Binary Ninja_'s user folder:
```shell
cd $BINJA_USR/plugins/
git clone https://github.com/pdamian/mole.git && cd mole/
```
### Standard
Create and activate a new Python virtual environment for _Mole_ (optional, but recommended):
```shell
python3 -m venv venv/mole
source venv/mole/bin/activate
```

Install _Binary Ninja_'s Python [API](https://docs.binary.ninja/dev/batch.html#install-the-api):
```shell
$BINJA_BIN/scripts/install_api.py
```

Install _Mole_:
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
