# Laravel Dependency & CVE Scanner

A graphical user interface (GUI) application built with Python and Tkinter for scanning Laravel projects for security vulnerabilities in their dependencies. It integrates with Composer Audit and Snyk to provide comprehensive vulnerability detection.

## Features

- **Composer Integration**: Supports both online (`composer audit`) and offline (using `security-checker`) vulnerability scanning
- **Snyk Integration**: Optional Snyk scanning for additional vulnerability data (requires internet)
- **HTML Reports**: Automatically generates styled HTML reports with vulnerability summaries
- **User-Friendly GUI**: Intuitive interface for selecting projects, configuring scans, and viewing results
- **Cross-Platform**: Works on Windows, macOS, and Linux (requires Python and Tkinter)

## Prerequisites

Before running the scanner, ensure you have the following installed:

- **Python 3.x** (with Tkinter support)
- **Composer** installed globally
- **Git** (for cloning repositories if needed)

### Optional Prerequisites

- **For Offline Scanning**:
  ```bash
  composer global require enlightn/security-checker
  git clone https://github.com/FriendsOfPHP/security-advisories ~/.composer/security-advisories
  ```

- **For Snyk Scanning**:
  ```bash
  npm install -g snyk
  snyk auth
  ```

## Installation

1. Download or clone this repository
2. Ensure Python 3.x is installed on your system
3. Install the prerequisites listed above
4. (Optional) Install dependencies: `pip install -r requirements.txt` (currently empty, as only standard library is used)

## Usage

1. **Launch the Application**:
   ```bash
   python laravel_vuln_scanner.py
   ```

2. **Select Project Directory**:
   - Click "Browse" and choose your Laravel project directory
   - The directory must contain a `composer.lock` file

3. **Configure Scan Options**:
   - Check "Composer Audit" to scan using Composer
   - Check "Snyk Scan" to include Snyk results (requires internet)
   - Choose "Online" for full CVE database access or "Offline" for local DB only

4. **Run the Scan**:
   - Click "Run Scan" to start the vulnerability detection
   - View results in the table below

5. **Export Results**:
   - Click "Export HTML Report" to generate and open a styled HTML report
   - The report includes vulnerability counts, details, and links

6. **Additional Features**:
   - Double-click CVE entries to open the CVE details in your browser
   - Use "Clear" to reset the results table

## Requirements

See `requirements.txt` for Python dependencies (currently none required beyond standard library).

## Screenshots

(The application provides a clean, professional GUI with project selection, scan configuration, and results display.)

## Contributing

Feel free to submit issues or pull requests for improvements.

## License

This project is open-source. Please check the license file if included.

## Disclaimer

This tool helps identify potential vulnerabilities but should not be the sole source of security assessment. Always verify findings and follow security best practices.