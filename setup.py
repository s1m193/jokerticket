from setuptools import setup, find_packages

setup(
    name="jokerticket",
    version="1.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "jokerticket": ["*"],
        "jokerticket.enumeration": ["*.py"],
        "jokerticket.kerberos": ["*.py"],
        "jokerticket.credential_access": ["*.py"],
        "jokerticket.lateral_movement": ["*.py", "*.ps1"],
        "jokerticket.delegation": ["*.py"],
        "jokerticket.adcs": ["*.py"],
        "jokerticket.ntlm": ["*.py"],
        "jokerticket.password_attacks": ["*.py"],
        "jokerticket.privilege_escalation": ["*.py"],
        "jokerticket.trusts": ["*.py"],
    },
    install_requires=[
        "impacket", "ldap3", "colorama", "pyasn1", "cryptography",
        "asn1crypto", "oscrypto", "dsinternals", "minikerberos",
        "pycryptodome", "certipy-ad", "pypsrp", "gssapi",
    ],
    entry_points={
        "console_scripts": [
            "jokerticket=jokerticket.cli:menu",
        ]
    },
)
