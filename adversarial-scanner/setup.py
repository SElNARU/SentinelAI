from setuptools import setup, find_packages

setup(
    name="sentinel-ai",
    version="0.1.0",
    description="Automated AI Red-Teaming Tool for LLM Endpoints",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "requests",
        "openai",
        "google-generativeai",
        "anthropic",
        "fpdf2",
        "fastapi",
        "uvicorn[standard]",
    ],
    entry_points={
        "console_scripts": [
            "sentinel-audit=core.cli:main", 
        ],
    },
)

