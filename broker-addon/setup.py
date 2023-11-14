#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="pastis-sydr-broker-addon",
    version="0.1",
    description="Sydr wrapper - Broker Addon",
    packages=find_packages(),
    install_requires=[
        "lief"        # Should install whether as client or broker !
    ],
)
