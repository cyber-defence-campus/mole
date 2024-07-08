from setuptools import setup, find_packages

setup(
    name = 'mole',
    version = '0.0.1',
    packages = find_packages(include = ['mole', 'mole.*']),
    install_requires = [
        'debugpy==1.8.1',
        'termcolor==2.4.0'
    ],
    entry_points = {
        'console_scripts': [
            'mole=mole.plugin:main'
        ]
    }
)