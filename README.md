# SubHunt

A very powerful and effective tool for subdomain enumeration.

<p align="center">
  <img src="subhunttt.jpg" width="100%" alt="SubHunt Banner">
</p>

## Overview

SubHunt is a **purely passive** subdomain discovery tool built to return **clean, real, DNS-resolvable results**.
It aggregates multiple large public datasets and filters everything through live DNS resolution, eliminating historical junk, stale records, and wildcard noise.

Cross-platform (Linux, macOS, Windows). No API keys required.

## Requirements

* Python 3.8+
* requests
* python-docx (optional, only for DOCX output)

```bash
pip install requests python-docx
```

## Installation

```bash
git clone https://github.com/5u5urrus/SubHunt.git
cd SubHunt
chmod +x subhunt.py
```

## Usage

Basic (fast, default passive source):

```bash
python subhunt.py example.com
```

Full passive enumeration (all sources):

```bash
python subhunt.py example.com --full
```

Save results to a DOCX report:

```bash
python subhunt.py example.com results.docx --full
```

## Output Example

```
api.example.com
mail.example.com
dev.example.com
```

Only subdomains that **actually resolve in DNS** are printed.

## Why SubHunt

SubHunt focuses on **signal over volume**.
The tool works cleaner and more reliable than many (if not most) other subdomain enumeration tools. Instead of flooding you with historical or speculative entries, it aims to return results that actually exist. 

## License

MIT

## Author

Vahe Demirkhanyan

