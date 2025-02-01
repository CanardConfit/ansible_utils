#!/usr/bin/python

# Copyright: (c) 2025, Tom Andrivet (CanardConfit) <canardconfit.development@gmail.com>
# Mozilla Public License 2.0 (see https://www.mozilla.org/MPL/2.0/)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pbkdf2_hmac_module

short_description: This module hashes a password using PBKDF2-HMAC.

version_added: "2.17.5"

description:
    - This module takes a password and optional salt and returns a hashed password using PBKDF2-HMAC with a specified hash algorithm.
    - Supports SHA-512 and allows customization of iterations, salt length, and output format.

options:
    password:
        description: The password to be hashed.
        required: true
        type: str
    salt:
        description: A base64 encoded salt to use for hashing. If not provided, a random salt will be generated.
        required: false
        type: str
    salt_length:
        description: The length of the salt to generate if none is provided.
        required: false
        type: int
        default: 16
    iterations:
        description: The number of iterations for the PBKDF2 function.
        required: false
        type: int
        default: 10000
    dklen:
        description: The length of the derived key in bytes.
        required: false
        type: int
        default: 32
    output_format:
        description: The format of the output hash, either base64 or a list of bytes.
        required: false
        type: str
        choices: ["base64", "byte_list"]
        default: 'base64'

author:
    - Tom Andrivet (@CanardConfit)
'''

EXAMPLES = r'''
# Hash a password with default settings
- name: Hash password with default settings
  pbkdf2_hmac_module:
    password: "my_secret_password"

# Hash a password with a provided salt
- name: Hash password with provided salt
  pbkdf2_hmac_module:
    password: "my_secret_password"
    salt: "OYK0b4KQDGgE3Pbxzj3psg=="

# Hash a password with a specified number of iterations and output as a byte list
- name: Hash password with custom iterations and byte list output
  pbkdf2_hmac_module:
    password: "my_secret_password"
    iterations: 20000
    output_format: "byte_list"
'''

RETURN = r'''
hash:
    description: The hashed password in the specified format.
    type: str or list
    returned: always
    sample: '8a55c8fe7f18d2a05a5423d93378d67c40e79712b0406be7c7021b4a5f380783'

salt:
    description: The salt used for hashing, base64 encoded.
    type: str
    returned: always
    sample: 'OYK0b4KQDGgE3Pbxzj3psg=='
'''

from ansible.module_utils.basic import AnsibleModule
import hashlib
import binascii
import base64
import os
import traceback

def pbkdf2_hmac(password, salt, salt_length, iterations, dklen, hash_algorithm, output_format):
    if salt is None:
        salt = os.urandom(salt_length)
    else:
        try:
            salt = base64.b64decode(salt)
        except binascii.Error:
            raise ValueError("The provided salt is not properly formatted in base64.")

    key = hashlib.pbkdf2_hmac(hash_algorithm, password.encode('utf-8'), salt, iterations, dklen)

    if output_format == "base64":
        result = base64.b64encode(key).decode('utf-8')
    elif output_format == "byte_list":
        result = list(key)
    else:
        raise ValueError("Unsupported output format. Use 'base64' or 'byte_list'.")

    return result, base64.b64encode(salt).decode('utf-8')

def main():
    module_args = dict(
        password = dict(type = "str", required = True, no_log = True),
        salt = dict(type = "str", required = False, default = None),
        salt_length = dict(type = "int", required = False, default = 16),
        iterations = dict(type = "int", required = False, default = 10000),
        dklen = dict(type = "int", required = False, default = 32),
        hash_algorithm = dict(type = "str", choices = ["sha256", "sha512"], default = "sha512"),
        output_format = dict(type = "str", choices = ["base64", "byte_list"], default = "base64")
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    password = module.params["password"]
    salt = module.params["salt"]
    salt_length = module.params["salt_length"]
    iterations = module.params["iterations"]
    dklen = module.params["dklen"]
    hash_algorithm = module.params["hash_algorithm"]
    output_format = module.params["output_format"]

    try:
        hash_result, salt_used = pbkdf2_hmac(password, salt, salt_length, iterations, dklen, hash_algorithm, output_format)
        module.exit_json(changed = False, hash = hash_result, salt = salt_used)
    except Exception as e:
        module.fail_json(msg = str(e), traceback = traceback.format_exc())

if __name__ == '__main__':
    main()
