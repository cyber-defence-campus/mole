from setuptools import setup, find_packages

setup(
    name = "mole",
    version = "0.0.4",
    author = 'Damian Pfammatter',
    description = "A Binary Ninja plugin for vulneraiblity discovery",
    packages = find_packages(include = ["mole", "mole.*"]),
    python_requires = '>= 3.10',
    install_requires = [
        "lark==1.2.2",
        "PySide6==6.7.2",
        "PyYAML==6.0.2",
        "termcolor==2.4.0",
    ],
    extras_require = {
        "develop": [
            "debugpy==1.8.1",
        ]
    },
    entry_points = {
        "console_scripts": [
            "mole=mole.main:main"
        ]
    }
)