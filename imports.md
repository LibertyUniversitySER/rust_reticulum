131 total unique imports

Examining dependencies may give us some insight into the program, and what pieces do what.

### Reticulum.py:
``` python
from .vendor.platformutils import get_platform
    from .Interfaces.Android import RNodeInterface
    from .Interfaces.Android import SerialInterface
    from .Interfaces.Android import KISSInterface
    from .Interfaces import *
from .vendor.configobj import ConfigObj
import configparser
import multiprocessing.connection
import signal
import atexit
import array
```
### Link.py:
```python
import inspect
from RNS.Cryptography import X25519PrivateKey, X25519PublicKey, Ed25519PrivateKey, Ed25519PublicKey
from RNS.Cryptography import Fernet
from RNS.Channel import Channel, LinkChannelOutlet
```

### Buffer.py:
```python
from threading import RLock
from RNS.Channel import Channel, MessageBase, SystemMessageTypes
from io import RawIOBase, BufferedRWPair, BufferedReader, BufferedWriter
from typing import Callable
from contextlib import AbstractContextManager
```


### Cryptography/HKDF.py:
```python
from math import ceil
```

### __init__.py:
```python
from RNS._version import __version__
from .Cryptography import HKDF
from .Cryptography import Hashes
from ._version import __version__
import random
from .Reticulum import Reticulum
from .Identity import Identity
from .Link import Link, RequestReceipt
from .Channel import MessageBase
from .Buffer import Buffer, RawChannelReader, RawChannelWriter
from .Transport import Transport
from .Destination import Destination
from .Packet import Packet
from .Resource import Resource, ResourceAdvertisement
```

# Cryptography
### Cryptography/Fernet.py:
```python
from RNS.Cryptography import PKCS7
from RNS.Cryptography.AES import AES_128_CBC
from RNS.Cryptography import HMAC
```

### Cryptography/__init__.py:    
```python
from .Hashes import sha256
from .Hashes import sha512
from .HKDF import hkdf
from .PKCS7 import PKCS7
from .Fernet import Fernet
from .Provider import backend

from RNS.Cryptography.X25519 import X25519PrivateKey, X25519PublicKey
from RNS.Cryptography.Ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from RNS.Cryptography.Proxies import X25519PrivateKeyProxy as X25519PrivateKey
from RNS.Cryptography.Proxies import X25519PublicKeyProxy as X25519PublicKey
from RNS.Cryptography.Proxies import Ed25519PrivateKeyProxy as Ed25519PrivateKey
from RNS.Cryptography.Proxies import Ed25519PublicKeyProxy as Ed25519PublicKey
```

### Cryptography/pure25519/eddsa.py:
```python
from RNS.Cryptography.Hashes import sha512
Cryptography/pure25519/basic.py:import binascii, hashlib, itertools
```

### Cryptography/Provider.py:
```python
        import cryptography
    if importlib.util.find_spec('cryptography') != None:
```

### Cryptography/AES.py:
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
```

### Cryptography/Proxies.py:
```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
```

### Cryptography/Hashes.py:
```python
from hashlib import sha512 as ext_sha512
from hashlib import sha256 as ext_sha256
import importlib
if importlib.util.find_spec('hashlib') != None:
from .SHA512 import sha512 as ext_sha512
from .SHA256 import sha256 as ext_sha256
```
### Cryptography/aes/aes.py:
```python
from .utils import *
```

### Cryptography/aes/__init__.py:
```python
from .aes import AES
```

### Cryptography/SHA256.py:
```python
import copy
```

### Cryptography/Ed25519.py:
```python
from .pure25519 import ed25519_oop as ed25519
```

### Cryptography/HMAC.py:
```python
import warnings as _warnings
```

### Cryptography/pure25519/eddsa.py:
```python
from .basic import (bytes_to_clamped_scalar,
from . import eddsa
from . import _ed25519
```


# Utilities - Kaelyn
Utilities/__init__.py:
```python
import glob
```
[Glob crate](https://docs.rs/glob/latest/glob/)

### Utilities/rnid.py:
```python
import base64
```
[Base64 crate](https://docs.rs/base64/latest/base64/)

### Utilities/rnstatus.py:
```python
import RNS
import json
```
(RNS is the network stack itself)
[Json crate](https://docs.rs/json/latest/json/)


### Utilities/rncp.py:
```python
import time
import sys
import os 
from tempfile import TemporaryFile
```

### Utilities/rnx.py:
```python
import tty
import subprocess
import shlex
```

Utilities/rnodeconf.py:
```python
from time import sleep
import datetime
import threading
import struct
import math
import hashlib
import zipfile
import zipfile
from urllib.request import urlretrieve
from importlib import util
import serial
from serial.tools import list_ports
import shutil
from shutil import which
import stat
from subprocess import call
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
```
### Resource.py:
```python
import bz2
from .vendor import umsgpack as umsgpack
```

### RNS/Chanel.py
```python
from __future__ import annotations
import collections
import enum
from types import TracebackType
from typing import Type, Callable, TypeVar, Generic, NewType
import abc
import contextlib
from abc import ABC, abstractmethod
```

# Interfaces
### Interfaces/RNodeInterface.py:
```python
if importlib.util.find_spec('serial') != None:
```

### Interfaces/I2PInterface.py:
```python
import platform
import socket
import asyncio
```
### Interfaces/AutoInterface.py:
```python
from collections import deque
import re
from RNS.vendor.ifaddr import niwrapper
```

### Interfaces/Android/RNodeInterface.py:
```python
if importlib.util.find_spec('usbserial4a') != None:
if importlib.util.find_spec('jnius') == None:
from jnius import autoclass
from usbserial4a import serial4a as pyserial
from usbserial4a import serial4a as serial
```

Interfaces/Android/SerialInterface.py:
```python
from usb4a import usb
from RNS.Interfaces.Interface import Interface
from usbserial4a.cdcacmserial4a import CdcAcmSerial
```


