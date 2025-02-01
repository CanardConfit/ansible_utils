# Ansible Collection - canardconfit.ansible-utils

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [ToDo](#todo)
- [Module `gpg_apt_key`](#module-gpg_apt_key)
  - [Usage Example](#usage-example)
  - [Module Options](#module-options)
    - [Required Parameters](#required-parameters)
    - [Optional Parameters](#optional-parameters)
- [Module `pbkdf2_hmac`](#module-pbkdf2_hmac)
  - [Usage Example](#usage-example-1)
  - [Module Options](#module-options-1)
    - [Required Parameters](#required-parameters-1)
    - [Optional Parameters](#optional-parameters-1)
- [Module `sha512_hash`](#module-sha512_hash)
  - [Usage Example](#usage-example-2)
  - [Module Options](#module-options-2)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

## Overview

The `canardconfit.ansible-utils` collection provides several modules for various automation tasks with Ansible. In short, everything I needed that hasn't already been done by the community is here.

## ToDo

Ensure that the tests can be executed from the devcontainer, and finish them. Ensure that there is a workflow that runs the tests, ...

## Module `gpg_apt_key`

This module is my version of the [`ansible.builtin.apt_key`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/apt_key_module.html) module, but follows good Linux practice by no longer using the "`apt_key`" method, which **was deprecated in 2022** (I don't know why there's still no replacement for the `apt_key` module in builtin..., anyway).

This deprecation is for all Linux systems, for security reasons. The idea is to put less trust in repository keys by storing them in some folder and signing only the desired repository with that key. For more details, see https://opensource.com/article/22/9/deprecated-linux-apt-key.

This module also implements the new way of registering a repo ([informations here](https://wiki.debian.org/DebianRepository/Format#Debian_Repository_Format)), with `"Release" file` instead of the usual `Flat Repository Format`.

### Usage Example

Below is an example demonstrating how to add and remove APT repository (and its GPG key) using this module. Additional examples can be found in the [module documentation](plugins/modules/gpg_apt_key.py) or on [Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/canardconfit/ansible_utils/content/module/gpg_apt_key/).

```yaml
- name: Add an APT repository and GPG key
  canardconfit.gpg_apt_key:
    repo_name: "example"
    repo_url: "https://example.com/apt"
    gpg_key_url: "https://example.com/apt/gpg"
    distribution: "bookworm"
    components: "main"
    architectures: "amd64"

- name: Remove the APT repository and its GPG key
  canardconfit.gpg_apt_key:
    repo_name: "example"
    repo_url: "https://example.com/apt"
    state: absent
```

### Module Options

#### Required Parameters

- **`repo_name`** (*str*): The name of the repository (used for naming the key and source file).
- **`repo_url`** (*str*): The base URL of the repository.

#### Optional Parameters

- **`gpg_key_url`** (*str*): The URL to the GPG key file. Defaults to `repo_url/gpg` if not provided.
- **`distribution`** (*str*): The distribution name (e.g., `bookworm`, `noble`).
- **`architectures`** (*str*): The target architectures for the repository (e.g., `amd64`, `arm64`).
- **`components`** (*str*, default=`main`): The repository components (e.g., `main`, `non-free`).
- **`keyring_dir`** (*str*, default=`/etc/apt/keyrings`): The directory where GPG keys are stored.
- **`keyring_dir_mode`** (*str*, default=`0755`): Permissions to apply to the keyring directory.
- **`key_mode`** (*str*, default=`0644`): Permissions to apply to the GPG key file.
- **`key_owner`** (*str*, default=`root`): The owner of the GPG key file.
- **`key_group`** (*str*, default=`root`): The group of the GPG key file.
- **`force_dearmor`** (*bool*, default=`false`): Forces the key to be dearmored even if already in binary format.
- **`key_tmp_file`** (*str*): Path to the temporary file for downloading the GPG key.
- **`sources_file`** (*str*): Path to the APT sources file.
- **`repo_content`** (*str*): Custom content template for the repository source file.
- **`apt_update`** (*bool*, default=`true`): If set to `true`, runs `apt update` after changes.
- **`state`** (*str*, default=`present`, choices=`present`, `absent`): Defines whether the repository should be present or absent.

## Module `pbkdf2_hmac`

This module leverages Python's [hashlib library](https://docs.python.org/3/library/hashlib.html) to compute the hash of a password using PBKDF2-HMAC with a specified algorithm.

### Usage Example

Here is a basic usage example that demonstrates how to use the PBKDF2-HMAC hashing module:

```yaml
- name: Hash password with PBKDF2-HMAC
  hosts: localhost
  tasks:
    - name: Hash a password using the canardconfit.hashlib collection
      canardconfit.hashlib.pbkdf2_hmac_module:
        password: "my_secret_password"
        iterations: 20000
        output_format: "base64"
      register: hashed_password

    - name: Display hashed password
      debug:
        msg: "Hashed Password: {{ hashed_password.hash }}"
```

### Module Options

#### Required Parameters

- **`password`** (*str*, required): The password to be hashed.

#### Optional Parameters

- **`salt`** (*str*): A base64 encoded salt. If not provided, a random salt will be generated.
- **`salt_length`** (*int*, default=`16`): The length of the salt to generate if none is provided.
- **`iterations`** (*int*, default=`10000`): The number of iterations for the PBKDF2 function.
- **`dklen`** (*int*, default=`32`): The length of the derived key in bytes.
- **`output_format`** (*str*, default=`base64`, choices=`base64`, `byte_list`): The format of the output hash.

## Module `sha512_hash`

This module leverages Python's [hashlib library](https://docs.python.org/3/library/hashlib.html) to compute the SHA-512 hash of a given password.

### Usage Example

```yaml
- name: Hash password with SHA-512
  sha512_hash:
    password: "mysecretpassword"
    encoding: "utf-8"
    output_format: "string"
```

### Module Options

- **`password`** (*str*, required): The input password to be hashed.
- **`encoding`** (*str*, required): The encoding to use when converting the input password into bytes.
- **`output_format`** (*str*, default=`string`, choices=`string`, `bytes`): The output format of the hash.

## Contributing

We welcome contributions to improve this collection! Please submit a pull request or open [an issue](https://github.com/CanardConfit/ansible_utils/issues) if you have ideas for new features or find bugs.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE) for more details.

## Author

Developed by [**Tom Andrivet** (@CanardConfit)](https://github.com/CanardConfit).

