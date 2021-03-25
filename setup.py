#!/usr/bin/env python3
import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="strudra",
    version="0.1.0",
    author="domenukk",
    author_email="mail@dmnk.co",
    description="Craft Ghidra structs in python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/domenukk/strudra",
    packages=["strudra"],
    install_requires=requirements,
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 3 - Alpha",
        # Indicate who your project is intended for
        # 'Intended Audience :: Developers',
        "License :: OSI Approved :: MIT License",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    zip_safe=False,  # This might be needed for requirements.txt
)