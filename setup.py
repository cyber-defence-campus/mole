from setuptools import setup, find_packages

setup(
    name = "mole",
    version = "0.0.1",
    description = "A Binary Ninja plugin for vulneraiblity discovery",
    packages = find_packages(include = ["mole", "mole.*"]),
    install_requires = [
        "termcolor==2.4.0"
    ],
    extras_require = {
        "develop": [
            "debugpy==1.8.1",
        ]
    },
    entry_points = {
        "console_scripts": [
            "mole=mole.plugin:main"
        ]
    }
)