#!/usr/bin/python

# Copyright: (c) 2025, Tom Andrivet (CanardConfit) <canardconfit.development@gmail.com>
# Mozilla Public License 2.0 (see https://www.mozilla.org/MPL/2.0/)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: sha512_hash_module

short_description: Computes the SHA-512 hash of a given input.

version_added: "2.17.5"

description:
    - This module computes the SHA-512 hash of a given password.
    - The user can specify the encoding to use for the input string and choose the output format as a string or byte array.

options:
    password:
        description:
            - The input password to be hashed.
        required: true
        type: str
    encoding:
        description:
            - The encoding to use when converting the input password into bytes.
        required: true
        type: str
    output_format:
        description:
            - The output format of the hash value, either as a hexadecimal string or as raw bytes.
        choices: ['string', 'bytes']
        default: 'string'
        type: str
author:
    - Your Name (@yourhandle)
'''

EXAMPLES = r'''
# Hash a password using UTF-8 encoding and get the result as a string
- name: Hash password with SHA-512
  sha512_hash:
    password: "mysecretpassword"
    encoding: "utf-8"
    output_format: "string"

# Hash a password using ASCII encoding and get the result as bytes
- name: Hash password and return as bytes
  sha512_hash:
    password: "anotherpassword"
    encoding: "ascii"
    output_format: "bytes"
'''

RETURN = r'''
hash:
    description: The computed SHA-512 hash of the input password.
    returned: always
    type: str or bytes
    sample: "e0c9035898dd52fc65c41454cec9c4d2611bfb37b04d5f75e2d8b98a5e884c24"
'''

from ansible.module_utils.basic import AnsibleModule
import hashlib
import traceback

def sha512(input, encoding, output_format):
    if input is None:
        return None

    hash_value = hashlib.sha512(input.encode(encoding)).digest()
    
    if output_format == "string":
        return ''.join([f"{x:02x}" for x in hash_value])
    else:
        return hash_value

def main():
    module_args = dict(
        password = dict(type = "str", required = True, no_log = True),
        encoding = dict(type = "str", required = True),
        output_format = dict(type = "str", choices = ["string", "bytes"], default = "string")
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    password = module.params["password"]
    encoding = module.params["encoding"]
    output_format = module.params["output_format"]

    try:
        hash_result = sha512(password, encoding, output_format)
        module.exit_json(changed = False, hash = hash_result)
    except Exception as e:
        module.fail_json(msg = str(e), traceback = traceback.format_exc())

if __name__ == '__main__':
    main()
