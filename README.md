# KeePass Ansible Module

## Overview
The `keepass` module is an Ansible module for managing KeePass databases. It can create, read, and modify entries and groups in a `.kdbx` file.

## Requirements
- Python package `pykeepass` must be installed on the host running the module.
```
pip install pykeepass==4.0.6
```

## Parameters
- `db_file`: Path of the KeePass database file (.kdbx). (Required)
- `db_password`: Password of the database. (Required)
- `which`: Specifies the element type (group or entry) to operate on. (Optional)
- `state`: Specifies the action to perform (create, touch, find, delete). (Optional)
- `group_name`: Name of the group for group-related operations. (Optional)
- `entry_title`: Title of the entry for entry-related operations. (Optional)
- `username`: Username to set for an entry. (Optional)
- `password`: Password to set for an entry. (Optional)
- `url`: URL to set for an entry. (Optional)
- `notes`: Notes to set for a group or entry. (Optional)
- `tags`: Tags to set for an entry. (Optional)
- `uuid`: UUID to find/set for a group or entry. (Optional)
- `path`: Path to set/find for a group or entry. (Optional)
- `first`: When finding, get only the first matching element. (Optional, default: true)
- `recursive`: When finding, search recursively in groups. (Optional, default: true)
- `always_create`: When creating an entry, always create the group if it doesn't exist. (Optional, default: false)
- `listed_groups`: Enable/disable the listing of groups. (Optional, default: true)
- `listed_entries`: Enable/disable the listing of entries. (Optional, default: true)
- `regex`: Use regex for finding elements. (Optional, default: false)
- `hide_password`: Hide password in the result output. (Optional, default: false)

## Examples

```yaml
# Create a KeePass database
- name: Create database
  keepass:
    db_file: '/tmp/test.kdbx'
    db_password: 'password'
    state: 'create'

# Create a group in the database
- name: Create group
  keepass:
    db_file: '/tmp/test.kdbx'
    db_password: 'password'
    which: 'group'
    state: 'touch'
    group_name: 'email'

# Create an entry in the database
- name: Create entry
  keepass:
    db_file: '/tmp/test.kdbx'
    db_password: 'password'
    which: 'entry'
    state: 'touch'
    group_name: 'email'
    entry_title: 'gmail'
    username: 'username'
    password: 'password'
```

## Return Values

- `groups`: List of groups in the database. (Returned always)
- `entries`: List of entries in the database. (Returned always)
- `find`: List of found/modified elements based on the operation. (Returned sometimes)

Author: LighTender (@LighTend3r)


