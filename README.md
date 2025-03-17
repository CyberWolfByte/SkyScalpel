![SkyScalpel](Images/SkyScalpel_Banner.png "SkyScalpel Logo")

# SkyScalpel
"SkyScalpel is an open-source framework for JSON policy parsing, obfuscation, deobfuscation, and detection in cloud environments. It provides flexible and highly configurable mechanisms to handle JSON-level obfuscation, IAM policy transformations, and the detection of evasive obfuscation techniques in cloud security contexts.

Built on a custom C# JSON tokenizer and syntax tree parser, SkyScalpel offers unique insights into how obfuscated cloud policies (e.g. IAM policies) can evade detection and empowers defenders to surgically detect and neutralize these obfuscation techniques. The framework also integrates a PowerShell wrapper to enhance usability through pipeline capabilities and command chaining."

## SkyScalpel Docker 
This repo provides a Docker containerized version of SkyScalpel running on:
- Microsoft PowerShell (Ubuntu 20.04) official image
- PowerShell 7.2.1 & .NET 6.0 for full compatibility
- Automatically imports & runs SkyScalpel at startup
- Runs as a non-root user by default

## Acknowledgments
This project is a fork of [SkyScalpel](https://github.com/Permiso-io-tools/SkyScalpel), developed by **Daniel Bohannon (DBO)** and **Abian Morina (Abi)**. We appreciate their contributions to the cloud security community.

## Requirements
- Docker (v20.10+)
- Compatible with Linux, macOS, and Windows.

## Installation
  ```bash
  # Pull the prebuilt docker image
  docker pull cyberwolfbyte/skyscalpel

  # Run the container
  docker run --rm -it cyberwolfbyte/skyscalpel
  
  # Optional: Syntax to mount a local directory if you need to share files between the host machine and container
  docker run -it --rm -v /path/to/host/folder:/path/in/container cyberwolfbyte/skyscalpel

  # Optional: Build the SkyScalpel docker image manually with Dockerfile
  git clone https://github.com/CyberWolfByte/SkyScalpel.git
  cd SkyScalpel/
  docker build -t cyberwolfbyte/skyscalpel .
  ```

## Usage

https://github.com/Permiso-io-tools/SkyScalpel/blob/main/README.md#usage
