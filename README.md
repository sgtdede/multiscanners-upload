# multiscanners-upload
Asynchronous multiscanner (VirusTotal, Hybrid-Analysis, Cape, MalShare) uploader

## Installation
#### *Note*:
This script requires python3

### Check out the source code
```
git clone https://github.com/sgtdede/multiscanners-upload.git
cd multiscanners-upload
```
### Install the python dependencies
```
pip install -r requirements.txt
```

## Help
```
python3 uploader.py -h
usage: uploader.py [-h] [-v] [-s] [filename [filename ...]]

Multi Scanner uploaded

positional arguments:
  filename

optional arguments:
  -h, --help          show this help message and exit
  -v                  verbose mode
  -s, --skip-waiting  just upload the file and quit, do not poll and wait for analysis result
```
