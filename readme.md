# Failed Login Detector

## Overview
A Python-based Blue Team tool that detects potential SSH brute-force attacks by parsing authentication logs and flagging IP addresses with excessive failed login attempts.

## Features
- Parses SSH authentication logs
- Extracts IP addresses using regular expressions
- Counts failed login attempts per IP
- Flags suspicious behavior based on configurable thresholds
- Clean, SOC-style alert output

## Technologies Used
- Python
- Regular Expressions (re)
- Log Analysis
- collections.Counter
- pathlib

## Example Use Case
This tool simulates how SIEM systems detect brute-force attacks by analyzing authentication logs and triggering alerts when thresholds are exceeded.

## How to Run
```bash
python detector.py