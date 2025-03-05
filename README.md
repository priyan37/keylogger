# Keylogger Scanner

This project is a **Keylogger Detection Tool** for Linux. It scans `.deb` package files before installation to detect potential keyloggers.

## Features
- Scans `.deb` package files for malicious keylogger scripts.
- Works on Linux-based systems.
- Uses AI-based anomaly detection for improved accuracy.
- Runs efficiently with a 30-second scan timeout.

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/keylogger-scanner.git
cd keylogger-scanner
```

### 2. Set Up a Virtual Environment (Recommended)
```bash
python3 -m venv keylogger-env
source keylogger-env/bin/activate
```

### 3. Install Dependencies
Install required Python packages:
```bash
pip install -r requirements.txt
```

Ensure `ar` and `tar` commands are installed:
```bash
sudo apt install binutils tar
```

### 4. Download & Compile YARA
```bash
sudo apt install yara
```

## Usage
To scan a `.deb` file:
```bash
python3 keylogger_scanner.py /path/to/deb-file.deb
```

## Contributing
If you’d like to contribute, feel free to fork the repo and submit a pull request.

## License
This project is licensed under [MIT License](LICENSE).

