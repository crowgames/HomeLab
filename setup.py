from distutils.core import setup

from setuptools import find_packages

with open('README.md') as f:
    long_description = f.read()

setup(
    # Application name:
    name="HomeLab",

    # Version number (initial):
    version="0.1.33",
    scripts=['homelab/homelab'],

    # Application author details:
    author="Nils Wenzler",
    author_email="nils.wenzler@crowgames.de",

    # Packages
    packages=["homelab","homelab.webserver","homelab.static","homelab.analysis", "homelab.test", "homelab.websocket", "homelab.control"],

    package_data={
        # If any package contains *.txt files, include them:
        '': ['*.html', '*.js', '*.json'],
    },

    # Include additional files into the package
    include_package_data=True,
    zip_safe=False,

    # Details
    url="http://pypi.python.org/pypi/HomeLab/",

    #
    license="GPL-v3.0",
    description="Smart Home Security Platform",
    long_description=long_description,
    long_description_content_type='text/markdown',  # This is important!

    # long_description=open("README.md").read(),

    # Dependent packages (distributions)
    install_requires=[
        "websockets", "pympler", "scapy", "requests", "netifaces", "appdirs"
    ],
)
