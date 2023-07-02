# Haly: Hardening Analyzer
Haly is a framework that can automatically detect the usage of hardening techniques (RASP) in Android and iOS apps using static and dynamic analysis. It is developed as part of a master thesis at the [University of Twente](https://www.utwente.nl/).

## Implemented checks
An overview on the checks we implemented to detect hardening techniques can be found in [CHECKS.md](CHECKS.md).

## Dataset
The dataset we used for our research can be found in [DATASET.md](DATASET.md).

## Results
The results of our analysis can be found in the [Releases](https://github.com/utwente-scs/haly-hardening-analyzer/releases/tag/publication).

## Installation
### Prerequisites
You will need the following packages to run the analyzer:
- [Python >= 3.10](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [venv](https://docs.python.org/3/library/venv.html)

Furthermore, the following packages are needed for tools the analyzer uses:
- [Java](https://www.oracle.com/java/technologies/downloads/)
- [re2](https://github.com/google/re2)
- [codesearch](https://github.com/google/codesearch)
- [Radare2](https://rada.re/n/radare2.html)
- [adb](https://developer.android.com/tools/adb)
- [Wireshark and tshark](https://www.wireshark.org/)
- [pcapfix](https://f00l.de/pcapfix/)
- [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
- A C++ compiler

You should be able to install all these tools using the following commands on Ubuntu:
```bash
sudo apt install python3 python3-venv python3-pip default-jre libre2-dev codesearch adb wireshark tshark pcapfix pkg-config g++

git clone https://github.com/radareorg/radare2
cd radare2 ; sys/install.sh
```

If you want to make changes to the frida typescript code, you will also need [Node.js and npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).

### Install dependencies
Note: we encountered some issues when running `tcpdump` within a virtual environment, so we recommend not using a venv, if possible.
```bash
pip install -r requirements.txt
```

If you want to make changes to the Frida TypeScript code, you will also need to install the npm dependencies:
```bash
npm install
```

## Usage
### Run the analyzer
You can view the help menu of the analyzer to view all available options:
```bash
python3 main.py --help
```

To run the analyzer, you will need to provide a config file. For this, you can copy `config.example.yaml` and adjust the options to your needs. Please refer to the comments in the config file for more information on the options.

The analyzer has the following workflow:
1. Download: Download apk files or ipa files of the apps listed in the configuration file from the Play Store or the App Store.
2. Prepare: Decompile the apk files or extract and decrypt the ipa files, and index these files using codesearch.
3. Static analysis: Run static analysis tools on the decompiled code to find hardening techniques.
4. Dynamic analysis: Run dynamic analysis tools on the apps using Frida to find hardening techniques.
5. Report: Start a webserver with a HTML report of the results.

### Recompile the Frida TypeScript code after making changes
```bash
npm run build
```

### Credits
This project contains tools from the following projects:
- [Apktool](https://ibotpeaches.github.io/Apktool/) by Connor Tumbleson
- [gplay-downloader](https://github.com/ikolomiko/gplay-downloader) by İlker Avcı
- [ipatool](https://github.com/majd/ipatool) by Majd Alfhaily

Furthermore, inspiration was taken from:
- RaspScan by Jan Seredynski
- [app-tls-pinning](https://github.com/NEU-SNS/app-tls-pinning/) by Amogh Pradeep et al. ([Paper](https://dspace.networks.imdea.org/handle/20.500.12761/1623))
- cross-platform-pps by Magdalena Steinböck et al.