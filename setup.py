#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="pastis-sydr",
    version="0.1",
    description="Pastis SydrFuzz driver",
    packages=find_packages(),
    install_requires=[
        "click",
        "coloredlogs",
        "watchdog",
        "toml",
    ],
    scripts=['bin/pastis-sydr']
)
