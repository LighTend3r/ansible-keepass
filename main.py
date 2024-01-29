#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: keepass

short_description: Write/Read in keepass

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: Write and read in keepass (.kdbs). Based on https://pypi.org/project/pykeepass/

options:
    db_file:
        description: Path of the database (.kdbs).
        required: true
        type: str
    db_password:
        description: Password of the databse
        required: true
        type: str
    which:
        description: Which element to find/set/create/delete. Value : (group, entrie)
        required: false
        type: str
    state:
        description: Action on the database. Value : (create, touch, find, delete)
        required: false
        type: str
    entry_title:
        description: Find/Set title on an entrie
        required: false
        type: str
    username:
        description: Find/Set username on an entrie
        required: false
        type: str
    password:
        description: Find/Set password on an entrie
        required: false
        type: str
    url:
        description: Find/Set url on an entrie
        required: false
        type: str
    notes:
        description: Find/Set notes on an entrie/group
        required: false
        type: str
    tags:
        description: Find/Set tags on an entrie
        required: false
        type: str
    uuid:
        description: Find/Set uuid on an entrie/group
        required: false
        type: str
    path:
        description: Find/Set path on an entrie/group
        required: false
        type: str
    first:
        description: when find, get the first element
        required: false
        type: bool
        default: true
    recursive:
        description: when find, search recursively in the groups
        required: false
        type: bool
        default: true
    group_name:
        description: when create/search, specify the group name
        required: false
        type: str
    always_create:
        description: when create entrie, always create the group
        required: false
        type: bool
        default: false
    listed_groups:
        description: disable the list of groups
        required: false
        type: bool
        default: true
    listed_entries:
        description: disable the list of entries
        required: false
        type: bool
        default: true
    regex:
        description: use regex
        required: false
        type: bool
        default: false
    hide_password:
        description: hide password in the result
        required: false
        type: bool
        default: false




# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
# extends_documentation_fragment:
#     - my_namespace.my_collection.my_doc_fragment_name

author:
    - LighTender (@LighTend3r)
'''

EXAMPLES = r'''
# Create database
- name: Create database
  keepass:
    db_file: '/tmp/test.kdbx'
    db_password: 'password'
    state: 'create'

# Create group
- name: Create group
  keepass:
    db_file: '/tmp/test.kdbx'
    db_password: 'password'
    which: 'group'
    state: 'touch'
    group_name: 'email'

# Create entrie
- name: Create entrie
  keepass:
    db_file: '/tmp/test.kdbx'
    db_password: 'password'
    which: 'entrie'
    state: 'touch'
    group_name: 'email'
    username: 'gmail'
    password: 'password'
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
groups:
    description: List of groups.
    type: List
    returned: always
entries:
    description: List of entries.
    type: List
    returned: always
find:
    description: List of any find/modified.
    type: List
    returned: sometimes
'''

from ansible.module_utils.basic import AnsibleModule

from pykeepass import PyKeePass, create_database
from collections.abc import Iterable
import re

def est_iterable(objet):
    return isinstance(objet, Iterable)

def build_keyword(module_params, keys):
    return {k: module_params[k] for k in keys if module_params[k] is not None}

def action_groups(module, kp, result):
    if module.params['group_name'] is None:
            module.fail_json(msg='Error, group_name is required', **result)

    if module.params['state'] == 'touch':
        if module.params['group_name'] not in [group.name for group in kp.groups]:

            keys = ['notes', 'uuid']
            keyword = build_keyword(module.params, keys)

            group = kp.add_group(kp.root_group, module.params['group_name'], **keyword)

            result['find'] = [group]
            result['changed'] = True
    elif module.params['state'] == 'find':

        keys = ['notes', 'uuid', 'path']
        keyword = build_keyword(module.params, keys)

        groups = kp.find_groups(name=module.params['group_name'], first=module.params['first'], regex=module.params['regex'], recursive=module.params['recursive'], **keyword)

        if module.params['first'] == True:
            if groups is None:
                module.fail_json(msg='Error, group doesn\'t exist', **result)
            result['find'] = [groups]
        else:
            if len(groups) == 0:
                module.fail_json(msg='Error, group doesn\'t exist', **result)
            result['find'] = groups
    elif module.params['state'] == 'delete':
        if module.params['group_name'] in [group.name for group in kp.groups]:
            try:

                keys = ['notes', 'uuid', 'path']
                keyword = build_keyword(module.params, keys)

                kp.delete_group(kp.find_groups(name=module.params['group_name'], first=True, regex=module.params['regex'], recursive=module.params['recursive'], **keyword))
                result['changed'] = True
            except Exception as e:
                module.fail_json(msg='Error on delete group', **result)
    else:
        module.fail_json(msg='Error, state does\'t exist for groups', **result)

def action_entries(module, kp, result):

    if module.params['state'] == 'touch':

        find = None

        if module.params['group_name'] is None:
            group = kp.root_group
        else:
            groups = kp.find_groups(name=module.params['group_name'])
            if module.params['group_name'] not in [group.name for group in groups]:
                if module.params['always_create']:
                    group = kp.add_group(kp.root_group, module.params['group_name'])
                    result['changed'] = True
                    find = [group]
                else:
                    module.fail_json(msg='Error, group doesn\'t exist', **result)
            else:
                group = kp.find_groups(name=module.params['group_name'], first=True, regex=module.params['regex'], recursive=module.params['recursive'])

        if group is None:
            group = kp.root_group

        if module.params['username'] is None or module.params['password'] is None:
            module.fail_json(msg='Error, username and password are required', **result)

        if module.params['entry_title'] is None:
            module.fail_json(msg='Error, entry_title is required', **result)

        keys = ['url', 'notes', 'uuid', 'tags']
        keyword = build_keyword(module.params, keys)

        if module.params['entry_title'] not in [entry.title for entry in group.entries]:
            entrie = kp.add_entry(group, module.params['entry_title'], module.params['username'], module.params['password'], **keyword)
            result['changed'] = True
            if find is None:
                result['find'] = [entrie]
            else:
                result['find'].append(entrie)


    elif module.params['state'] == 'find':
        group = None
        if module.params['group_name'] in result['groups']:
            group = kp.find_groups(name=module.params['group_name'], first=True, regex=module.params['regex'], recursive=module.params['recursive'])
            if group is None:
                module.fail_json(msg='Error, group doesn\'t exist', **result)

        if module.params['entry_title'] is not None:

            keys = ['url', 'notes', 'tags', 'uuid', 'path']
            keyword = build_keyword(module.params, keys)

            entries = kp.find_entries(title=module.params['entry_title'], group=group, first=module.params['first'], regex=module.params['regex'], recursive=module.params['recursive'], **keyword)
            if module.params['first'] == True:
                if entries is None:
                    module.fail_json(msg='Error, entrie doesn\'t exist', **result)
                result['find'] = [entries]
            else:
                if len(entries) == 0:
                    module.fail_json(msg='Error, entrie doesn\'t exist', **result)
                result['find'] = entries



    elif module.params['state'] == 'delete':
        group = None
        if module.params['group_name'] in result['groups']:
            group = kp.find_groups(name=module.params['group_name'], first=True, regex=module.params['regex'], recursive=module.params['recursive'])
            if group is None:
                module.fail_json(msg='Error, group doesn\'t exist', **result)

        if module.params['entry_title'] is not None:
            try:
                keys = ['url', 'notes', 'tags', 'uuid', 'path']
                keyword = build_keyword(module.params, keys)

                kp.delete_entry(kp.find_entries(title=module.params['entry_title'], group=group, first=True, regex=module.params['regex'], recursive=module.params['recursive'], **keyword))
                result['changed'] = True
            except Exception as e:
                module.fail_json(msg='Error on delete entrie', **result)
    else:
        module.fail_json(msg='Error, state does\'t exist for groups', **result)

def listed(module, kp, result):
    if module.params['listed_groups'] == True:
        result['groups'] = [
        {
            'name': group.name,
            'path': group.path,
            'notes': group.notes,
            'entries': [entry.title for entry in group.entries]
        } for group in kp.groups]
    else:
        result['groups'] = []

    if module.params['listed_entries'] == True:
        result['entries'] = [
        {
            'title': entry.title,
            'username': entry.username,
            **({'password': entry.password} if not module.params['hide_password'] else {}),
            'url': entry.url,
            'notes': entry.notes,
            'tags': entry.tags,
            'expires': entry.expires,
            'history': entry.history,
            'icon': entry.icon,
            'uuid': str(entry.uuid),
            'parent_group': entry.parentgroup.path,
        } for entry in kp.entries]


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        db_file=dict(type='str', required=True),
        db_password=dict(type='str', required=True, no_log=True),
        which=dict(type='str', required=False),
        state=dict(type='str', required=False),
        username=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True),
        first=dict(type='bool', required=False, default=True),
        group_name=dict(type='str', required=False),
        always_create=dict(type='bool', required=False, default=False),
        entry_title=dict(type='str', required=False),
        listed_groups=dict(type='bool', required=False, default=True),
        listed_entries=dict(type='bool', required=False, default=True),
        regex=dict(type='bool', required=False, default=False),
        hide_password=dict(type='bool', required=False, default=False),
        notes=dict(type='str', required=False),
        url=dict(type='str', required=False),
        tags=dict(type='str', required=False),
        uuid=dict(type='str', required=False),
        recursive=dict(type='bool', required=False, default=True),
        path=dict(type='str', required=False),

    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        groups=[],
        entries=[],
        find=None
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications

    # Update the list



    if module.params['state'] == 'create':
        try: # Try to open the database
            kp = PyKeePass(module.params['db_file'], password=module.params['db_password'])
        except Exception as e:
            kp = create_database(module.params['db_file'], password=module.params['db_password'], keyfile=None, transformed_key=None)
            result['changed'] = True

        kp.save()
        module.exit_json(**result)
    else:
        try:
            kp = PyKeePass(module.params['db_file'], password=module.params['db_password'])
        except Exception as e:
            module.fail_json(msg='Error on open database', **result)

    listed(module, kp, result)

    # Target the good action
    if module.params['which'] == 'group':
        action_groups(module, kp, result)
    elif module.params['which'] == 'entrie':
        action_entries(module, kp, result)

    # Update the list
    listed(module, kp, result)

    # If the module is in check mode, we do not want to make any changes to the environment
    if module.check_mode:
        module.exit_json(**result)

    kp.save()
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
