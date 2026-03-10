from setuptools import find_packages, setup

from secret_scanner import __version__

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [
        line.strip() for line in f if line.strip() and not line.startswith("#")
    ]

setup(
    name="secret-scanner",
    version=__version__,
    author="Prakashgode",
    description="A lightweight CLI tool that scans codebases for hardcoded secrets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Prakashgode/secret-scanner",
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.8",
    install_requires=[r for r in requirements if "pytest" not in r],
    extras_require={
        "dev": ["pytest>=7.0"],
    },
    entry_points={
        "console_scripts": [
            "secret-scanner=secret_scanner.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
