# SSH Threat Detector

A Python CLI tool that analyses SSH authentication logs for repeated failed login attempts and flags suspicious brute-force activity.

## Overview

This project explores how failed SSH authentication events can be detected and summarised using log analysis. It scans Linux authentication logs, groups repeated failed login attempts by IP address, and reports suspicious activity once a configurable threshold is reached.

## Features

- Detection of repeated failed SSH login attempts  
- Identification of suspicious source IP addresses  
- Configurable alert threshold  
- Clear terminal output with status indicators  
- Text and JSON results output  
- Append-by-default logging with an optional overwrite flag (`--clear`)  
- Dry-run mode for previewing detections without writing files  

## Usage

This tool is intended to be run in a Python 3 environment using SSH authentication logs from a Linux system.

Run the detector:

```bash
python Main.py
```
