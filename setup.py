from setuptools import setup, find_namespace_packages, find_packages


with open("requirements.txt") as f:
    install_reqs = f.read().strip().split("\n")

# Filter out comments/hashes
reqs = []
for req in install_reqs:
    if req.startswith("#") or req.startswith("    --hash="):
        continue
    reqs.append(str(req).rstrip(" \\"))


with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name="bitcoin_qrreader",
    version="0.2.3",
    author="Andreas Griffin",
    author_email="andreasgriffin@proton.me",
    description="Bitcoin qr reader",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/andreasgriffin/bitcoin-qrreader",
    packages=find_packages(),
    install_requires=reqs,
    classifiers=[
        "Development Status :: 3 - Alpha",  # Replace with the appropriate development status
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.7,<4.0",
)
