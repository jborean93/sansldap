# sansldap - Python Sans-IO LDAP Library

[![Test workflow](https://github.com/jborean93/sansldap/actions/workflows/ci.yml/badge.svg)](https://github.com/jborean93/sansldap/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/sansldap/branch/main/graph/badge.svg?token=UEA7VoocS5)](https://codecov.io/gh/jborean93/sansldap)
[![PyPI version](https://badge.fury.io/py/sansldap.svg)](https://badge.fury.io/py/sansldap)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/sansldap/blob/main/LICENSE)

Library for LDAP in Python.
It does not provide any IO or concurrency logic as it's designed to be a pure Python implementation that is then used by other libraries.
This follows the [sans-IO](https://sans-io.readthedocs.io/) paradigm to promote re-usability and have it focus purely on the protocol logic.
Some examples that utilitise this library can be found in [tests/examples](./tests/examples/)


## Documentation

Documentation is available at https://sansldap.readthedocs.io/.


## Requirements

* CPython 3.7+


## Install

### From PyPI

```bash
pip install sansldap
```

### From Source

```bash
git clone https://github.com/jborean93/sansldap.git
cd sansldap
pip install -e .
```
