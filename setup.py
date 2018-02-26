#!/usr/bin/env python
# coding: utf-8

from setuptools import setup
from pypsexec import __version__

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''


setup(
    name='pypsexec',
    version=__version__,
    packages=['pypsexec'],
    install_requires=[
        'smbprotocol>=0.0.1.dev6',
        'six'
    ],
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/pypsexec',
    description='Run commands on a remote Windows host using SMB/RPC',
    long_description=long_description,
    keywords='windows psexec paexec remote python',
    license='MIT',
    classifiers=[
        'Development Status :: 1 - Planning',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
