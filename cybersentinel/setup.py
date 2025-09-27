from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cybersentinel",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive vulnerability scanner with a modern GUI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cybersentinel",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "PyQt5>=5.15.9",
        "python-nmap>=0.7.1",
        "requests>=2.31.0",
        "reportlab>=4.1.0",
        "cryptography>=41.0.0",
        "pyOpenSSL>=24.0.0",
        "beautifulsoup4>=4.12.2",
        "lxml>=4.9.3",
        "tqdm>=4.65.0",
        "packaging>=23.1",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-qt>=4.2.0",
            "black>=23.7.0",
            "isort>=5.12.0",
            "mypy>=1.4.1",
        ],
        "pdf": ["weasyprint>=60.1"],
        "cve": ["cvss>=2.6"],
        "web": [
            "selenium>=4.11.2",
            "webdriver-manager>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cybersentinel=cybersentinel.gui_main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "cybersentinel": ["resources/*.ui", "resources/*.qss", "resources/*.png"],
    },
)
