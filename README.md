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

* * *
## Scanners API Keys
You need to register to the free Public API of the following scanners in order to leverage this tool
When you got the keys, insert them into the conf.yml file and enjoy

### Virustotal

1. Create an account here [https://www.virustotal.com/#/join-us](https://www.virustotal.com/#/join-us)
2. Check `Profile > API key` for your public API key

### Hybrid Analysis

1. Create an account here [https://www.hybrid-analysis.com/signup](https://www.hybrid-analysis.com/signup)
2. After login, go to [`Profile > API key`](https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab)

### MalShare

1. Register here [https://malshare.com/register.php](https://malshare.com/register.php)
2. API key is automatically sent by email

### Cape Sandbox

1. Create an account here [https://www.capesandbox.com/accounts/signup/](https://www.capesandbox.com/accounts/signup/)
2. Generate your API Key (token) using the following request
```
curl -d "username=<USER>&password=<PASSWD>" https://capesandbox.com/apiv2/api-token-auth/
```
