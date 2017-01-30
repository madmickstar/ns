#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages
from codecs import open
import sys
import os
import re
import ns

def get_version(path):
    with open(path, encoding='utf-8') as f:
        version_file = f.read()
    regex = r"^__version__ = ['\"]([^'\"]*)['\"]"
    version_match = re.search(regex, version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string in %s.', version_file)

with open('LICENSE', encoding='utf-8') as f:
    license = f.read()

    
setup(
    name='ns',
    version=get_version('ns/_version.py'),
    description='ns tool is an improved nslookup tool',
    author='Mick Shine',
    author_email='madmixtar@gmail.com',
    url='https://github.com/madmickstar/ns',
    license=license,
    packages=find_packages(exclude=('tests', 'docs')),
    install_requires=['dnspython >= 1.15.0'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Utilities',
    ],
)