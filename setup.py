from setuptools import setup

DESCRIPTION = "A pure python implementation of the AES encryption algorithm"

setup(
    name="micro_aes",
    version="2021.4",
    license="GNU General Public License Version 3.0",
    author="Z-40",
    description=DESCRIPTION,
    url="https://github.com/Z-40/MicroAES",
    install_requires=[],
    keywords=["AES", "cryptography"],
    packages=["micro_aes"],
    license_file="MicroAES/license.txt"
)