#!/usr/bin/env python

import os.path

from setuptools import setup

ROOT = os.path.dirname(__file__)

setup(
    version="0.1",
    url="https://github.com/thefreshuk/aws-python-sns-message-validator",
    name="aws_sns_validator",
    description=("Validate the integrity of Amazon SNS message with support"
                 "for use with Fake_SNS"),
    long_description=open("README.md").read(),
    author="Neil Hickman",
    author_email="neil@thefreshuk.com",
    packages=["aws_sns_validator"],
    package_dir={"":"src"},
    install_requires=["m2crypto"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4"
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ]
)
