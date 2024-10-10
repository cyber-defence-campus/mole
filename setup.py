from setuptools import setup, find_packages

setup(
    name = "mole",
    version = "0.0.2",
    author = 'Damian Pfammatter',
    description = "A Binary Ninja plugin for vulneraiblity discovery",
    packages = find_packages(include = ["mole", "mole.*"]),
    python_requires = '>= 3.8',
    install_requires = [
        "termcolor==2.4.0",
        "PyYAML==6.0.2",
        "PySide6==6.7.3"
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