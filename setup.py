# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    package_dir={"": "src"},
    packages=find_packages(
        where="src",
        exclude=["test*"]
    ),
    entry_points={
        "console_scripts": [
            "fakegw = fakegw:main",
        ],
    },      
    install_requires=[
        "scapy",
    ]
)
