#!/usr/bin/python

# Copyright: (c) 2025, Tom Andrivet (CanardConfit) <canardconfit.development@gmail.com>
# Mozilla Public License 2.0 (see https://www.mozilla.org/MPL/2.0/)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: gpg_apt_key

short_description: Manages APT repository GPG keys and sources on Linux-based systems.

version_added: "2.17.5"

description:
    - This module handles the management of APT repository GPG keys and source files.
    - It supports adding, updating, and removing GPG keys, as well as configuring APT sources.
    - The module ensures idempotency by checking if the key already exists before applying changes.
    - It can also make an APT update after changes, if required.
    - Unlike C(ansible.builtin.apt_key), which has been deprecated due to security concerns with key management,
      this module follows the modern approach of storing keys in /etc/apt/keyrings and using signed sources lists.
    - This ensures compliance with best practices for APT key management and provides a safer, more maintainable method
      for handling repository authentication.

options:
    repo_name:
        description:
            - The name of the repository (used for naming the key and source file).
        required: true
        type: str

    repo_url:
        description:
            - The base URL of the repository.
        required: true
        type: str

    gpg_key_url:
        description:
            - The URL to the GPG key file.
            - If not provided, defaults to C(repo_url/gpg).
        required: false
        type: str

    distribution:
        description:
            - The distribution name (e.g., C(bookworm), C(noble)).
            - Required if C(state=present).
        required: false
        type: str

    architectures:
        description:
            - The target architectures for the repository (e.g., C(amd64), C(arm64)).
            - Required if C(state=present).
        required: false
        type: str

    components:
        description:
            - The repository components (e.g., C(main), C(sid), C(non-free)).
        required: false
        type: str
        default: "main"

    keyring_dir:
        description:
            - The directory where the GPG keys are stored.
        required: false
        type: str
        default: "/etc/apt/keyrings"

    keyring_dir_mode:
        description:
            - Permissions to apply to the keyring directory.
        required: false
        type: str
        default: "0755"

    key_mode:
        description:
            - Permissions to apply to the GPG key file.
        required: false
        type: str
        default: "0644"

    key_owner:
        description:
            - The owner of the GPG key file.
        required: false
        type: str
        default: "root"

    key_group:
        description:
            - The group of the GPG key file.
        required: false
        type: str
        default: "root"

    force_dearmor:
        description:
            - Forces the key to be dearmored even if it is already in binary format.
        required: false
        type: bool
        default: false

    key_tmp_file:
        description:
            - Path to the temporary file for downloading the GPG key.
        required: false
        type: str

    sources_file:
        description:
            - Path to the APT sources file.
        required: false
        type: str

    repo_content:
        description:
            - Custom content template for the repository source file.
            - Supports placeholders like C({repo_url}), C({distribution}), C({components}), C({architectures}), and C({keyring_file}).
        required: false
        type: str

    apt_update:
        description:
            - If set to true, runs C(apt update) after changes.
        required: false
        type: bool
        default: true

    state:
        description:
            - Defines whether the repository should be present or absent.
        choices: ["present", "absent"]
        required: false
        type: str
        default: "present"

author:
    - Tom Andrivet (@CanardConfit)
'''

EXAMPLES = r'''
# Add a new repository and GPG key
- name: Add example repository
  canardconfit.gpg_apt_key.gpg_apt_key:
    repo_name: "example"
    repo_url: "https://example.com/apt"
    gpg_key_url: "https://example.com/apt/gpg"
    distribution: "bookworm"
    components: "main"
    architectures: "amd64"

# Remove the repository and its GPG key
- name: Remove example repository
  canardconfit.gpg_apt_key.gpg_apt_key:
    repo_name: "example"
    repo_url: "https://example.com/apt"
    state: absent

# Add a repository with a custom keyring directory and permissions
- name: Add repository with custom keyring settings
  canardconfit.gpg_apt_key.gpg_apt_key:
    repo_name: "custom_repo"
    repo_url: "https://example.com/apt"
    keyring_dir: "/etc/apt/custom-keyrings"
    keyring_dir_mode: "0700"
    key_mode: "0600"
    key_owner: "root"
    key_group: "root"

# Disable automatic apt update
- name: Add repository without running apt update
  canardconfit.gpg_apt_key.gpg_apt_key:
    repo_name: "myrepo"
    repo_url: "https://example.com/apt"
    apt_update: false

# Use a custom repository source file
- name: Add repository with a custom sources file
  canardconfit.gpg_apt_key.gpg_apt_key:
    repo_name: "custom_repo"
    repo_url: "https://example.com/apt"
    sources_file: "/etc/apt/sources.list.d/custom_repo.list"

# Override the repository content
- name: Add repository with custom repo content
  canardconfit.gpg_apt_key.gpg_apt_key:
    repo_name: "custom_repo"
    repo_url: "https://example.com/apt"
    repo_content: |
      Types: deb
      URIs: {repo_url}
      Suites: {distribution}
      Components: {components}
      Architectures: {architectures}
      Signed-By: {keyring_file}
'''

RETURN = r'''
changed:
    description: Indicates whether changes were made.
    returned: always
    type: bool
    sample: true

msg:
    description: A summary message describing the action performed.
    returned: always
    type: str
    sample: "GPG key and repository configured successfully"

keyring_file:
    description: The path where the GPG key was stored.
    returned: when state=present
    type: str
    sample: "/etc/apt/keyrings/example.gpg"

sources_file:
    description: The path where the repository source file was stored.
    returned: when state=present
    type: str
    sample: "/etc/apt/sources.list.d/example.sources"
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
import os
import shutil
import pwd
import grp
import hashlib


def download_file(module, url, dest_path):
    """Downloads a file using Ansible's fetch_url() utility"""
    response, info = fetch_url(module, url, timeout=10)
    if info["status"] != 200:
        module.fail_json(msg=f"Failed to download {url}: {info['msg']}")
        return
    
    with open(dest_path, "wb") as f:
        f.write(response.read())


def is_ascii_gpg(file_path):
    """Checks if the downloaded GPG key is ASCII-armored (.asc)"""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(100)
            decoded_chunk = chunk.decode(errors="ignore")
            return "BEGIN PGP PUBLIC KEY BLOCK" in decoded_chunk
    except Exception:
        return False


def is_binary_gpg(file_path: str) -> bool:
    """Checks if the downloaded file is a valid binary GPG key"""
    try:
        with open(file_path, "rb") as f:
            head = f.read(6)

        if not head:
            return False

        first = head[0]

        if (first & 0x80) == 0:
            return False

        if (first & 0x40):
            tag = first & 0x3F
        else:
            tag = (first >> 2) & 0x0F

        return tag in (5, 6, 7, 14)
    except Exception:
        return False


def get_architecture(ansible_arch):
    """Returns 'amd64' or 'arm64' based on ansible_architecture"""
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(ansible_arch, ansible_arch)


def file_hash(file_path):
    """Calculates SHA256 hash of a file"""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except FileNotFoundError:
        return None


def run_command(module, command):
    """Executes a shell command and returns its output"""
    rc, stdout, stderr = module.run_command(command, check_rc=True)
    return stdout.strip()


def main():
    module_args = dict(
        repo_name=dict(type='str', required=True),
        repo_url=dict(type='str', required=True),
        gpg_key_url=dict(type='str', required=False),
        distribution=dict(type='str', required=False),
        architectures=dict(type='str', required=False),
        components=dict(type='str', required=False, default="main"),
        keyring_dir=dict(type='str', required=False, default="/etc/apt/keyrings"),
        keyring_dir_mode=dict(type='str', required=False, default="0755"),
        key_mode=dict(type='str', required=False, default="0644"),
        key_owner=dict(type='str', required=False, default="root"),
        key_group=dict(type='str', required=False, default="root"),
        force_dearmor=dict(type='bool', required=False, default=False),
        key_tmp_file=dict(type='str', required=False),
        sources_file=dict(type='str', required=False),
        repo_content=dict(type='str', required=False),
        apt_update=dict(type='bool', required=False, default=True),
        state=dict(type='str', required=False, choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_if=[
            ("state", "present", ["distribution", "architectures"])
        ], supports_check_mode=True
    )

    repo_name = module.params['repo_name']
    repo_url = module.params['repo_url']
    gpg_key_url = module.params['gpg_key_url'] or f"{repo_url}/gpg"
    distribution = module.params['distribution']
    architectures = get_architecture(module.params['architectures'])
    components = module.params['components']
    keyring_dir = module.params['keyring_dir']
    keyring_dir_mode = int(module.params['keyring_dir_mode'], 8)
    key_mode = int(module.params['key_mode'], 8)
    key_owner = module.params['key_owner']
    key_group = module.params['key_group']
    force_dearmor = module.params['force_dearmor']
    key_tmp_file = module.params['key_tmp_file'] or f"/tmp/{repo_name}.gpg"
    sources_file = module.params['sources_file'] or f"/etc/apt/sources.list.d/{repo_name}.sources"
    apt_update = module.params['apt_update']
    state = module.params['state']

    keyring_file = f"{keyring_dir}/{repo_name}.gpg"

    changes = False

    # Remove key and repo
    if state == "absent":
        if os.path.exists(keyring_file):
            os.remove(keyring_file)
            changes = True
        if os.path.exists(sources_file):
            os.remove(sources_file)
            changes = True
        if apt_update and changes:
            run_command(module, "apt update")
        module.exit_json(changed=changes, msg="GPG key and repository removed successfully")

    # Ensure keyring directory exists
    if not os.path.exists(keyring_dir):
        os.makedirs(keyring_dir, mode=keyring_dir_mode)
        os.chown(keyring_dir, pwd.getpwnam(key_owner).pw_uid, grp.getgrnam(key_group).gr_gid)
        changes = True

    # Download new GPG key
    download_file(module, gpg_key_url, key_tmp_file)

    # Compare with existing key
    if os.path.exists(keyring_file) and file_hash(key_tmp_file) == file_hash(keyring_file):
        os.remove(key_tmp_file)
    else:
        # Process the GPG key
        if is_ascii_gpg(key_tmp_file) or force_dearmor:
            run_command(module, f"gpg --dearmor --yes -o {keyring_file} {key_tmp_file}")
        elif is_binary_gpg(key_tmp_file):
            shutil.move(key_tmp_file, keyring_file)
        else:
            os.remove(key_tmp_file)
            module.fail_json(msg=f"Downloaded file from {gpg_key_url} is not a valid GPG key!")

        os.chmod(keyring_file, key_mode)
        os.chown(keyring_file, pwd.getpwnam(key_owner).pw_uid, grp.getgrnam(key_group).gr_gid)
        changes = True

    # Create repository source file
    default_repo_content = """\
Types: deb
URIs: {repo_url}
Suites: {distribution}
Components: {components}
Architectures: {architectures}
Signed-By: {keyring_file}
"""
    repo_content = module.params['repo_content'] or default_repo_content

    # Replace placeholders of repo_content
    repo_content = repo_content.format(
        repo_url=repo_url,
        distribution=distribution,
        components=components,
        architectures=architectures,
        keyring_file=keyring_file
    )

    if not os.path.exists(sources_file) or open(sources_file).read() != repo_content:
        with open(sources_file, "w") as f:
            f.write(repo_content)
        changes = True

    if apt_update and changes:
        run_command(module, "apt update")

    module.exit_json(changed=changes, msg="GPG key and repository configured successfully", keyring_file=keyring_file, sources_file=sources_file)


if __name__ == '__main__':
    main()
