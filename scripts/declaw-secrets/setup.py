#!/usr/bin/env python3
"""
Setup script for DeClaw Secrets Manager
"""

from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="declaw-secrets",
    version="1.0.0",
    author="Tom Stetson",
    author_email="tom@stetson.dev",
    description="Secure secrets management for OpenClaw AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tomstetson/declaw-patterns",
    scripts=["declaw-secrets"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    keywords="security secrets openclaw ai-agents",
    project_urls={
        "Bug Reports": "https://github.com/tomstetson/declaw-patterns/issues",
        "Source": "https://github.com/tomstetson/declaw-patterns",
        "Documentation": "https://github.com/tomstetson/declaw-patterns/blob/main/scripts/declaw-secrets/README.md",
    },
)
