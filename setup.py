#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

from setuptools import setup


def abs_path(rel_path):
    return os.path.join(os.path.dirname(__file__), rel_path)


with open(abs_path('README.md'), mode='rb') as fd:
    long_description = fd.read().decode('utf-8')


setup(
    name='pypsexec',
    version='0.2.0',
    packages=['pypsexec'],
    install_requires=[
        'smbprotocol',
        'six',
    ],
    include_package_data=True,
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/pypsexec',
    description='Run commands on a remote Windows host using SMB/RPC',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='windows psexec paexec remote python',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
