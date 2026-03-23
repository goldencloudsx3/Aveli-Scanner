from setuptools import setup, find_packages

setup(
    name="aveli-scanner",
    version="1.0.0",
    description="Real-time internet-wide website vulnerability scanner",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "aiofiles>=23.0.0",
        "rich>=13.7.0",
        "pyyaml>=6.0.1",
        "tldextract>=5.1.0",
        "regex>=2023.12.25",
        "httpx>=0.26.0",
        "click>=8.1.7",
        "colorama>=0.4.6",
        "certifi>=2024.2.2",
        "python-dotenv>=1.0.0",
        "websockets>=12.0",
        "ujson>=5.9.0",
        "cachetools>=5.3.0",
    ],
    entry_points={
        "console_scripts": [
            "aveli=aveli.__main__:main",
        ],
    },
)
