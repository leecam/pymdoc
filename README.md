# py_isomdoc

A Python3 library for creating and verifying ISO 18013-5 mdocs.

## Installation

This module is available on **PyPi**

`pip install isomdoc`

## Requirements

- Python 3.8 and later

## Usage

This library provides the following methods on the `isomdoc` module

- `create_mdoc`
- `verify_device_response`

These methods can be used to create mdoc credentials that can issued to wallets and verify responses from wallets. See examples below for usage

### Issuing an mdoc

See **examples/create_mdoc.py** for an example of creating an mdoc.

You can run the example with the following:

```sh
# See "Development" for venv setup instructions
venv $> python -m examples.create_mdl testdata/issuer_cert.pem testdata/issuer_private_key.pem testdata/device_public_key.pem testdata/device_private_key.pem
```

### Verifying a mdoc

See **examples/verify_mdoc.py** for an example of verifying an mdoc DeviceResponse

You can run the example with the following:
```sh
# See "Development" for venv setup instructions
venv $> python -m examples.verify_mdl testdata/issuer_cert.pem testdata/issuer_private_key.pem testdata/device_public_key.pem testdata/device_private_key.pem
```

### Test data

The **testdata/** folder contains test keys that are used by the examples.

A sample issuer cert can be generated with:

```sh
venv $> python -m examples.generate_issuer_cert
```

A device key for testing can be generated with:
```sh
venv $> python -m examples.generate_device_key
```

## Development

### Installation

Use a python3 virtual enviroment

```sh
$> python3 -m venv venv
$> source venv/bin/activate
venv $> pip install -r requirements.txt
```


