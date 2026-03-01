from setuptools import find_packages, setup

from secret_scanner import __version__

setup(
    name="secret-scanner",
    version=__version__,
    author="Prakashgode",
    description="A lightweight CLI tool that scans codebases for hardcoded secrets",
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "secret-scanner=secret_scanner.cli:main",
        ],
    },
)
