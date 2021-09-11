import argparse
import yaml
import logging
import asyncio
import aiohttp

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',)
logger = logging.getLogger(__name__)

from ipdb import set_trace

parser = argparse.ArgumentParser(description='Multi Scanner uploaded')
parser.add_argument(dest='filenames',metavar='filename', nargs='*')
parser.add_argument('-v', dest='verbose', action='store_true', help='verbose mode')
parser.add_argument('-s', '--skip-waiting', dest='skip', action='store_true', help='just upload the file and quit, do not poll and wait for analysis result')
args = parser.parse_args()

if args.verbose:
    logger.setLevel(logging.DEBUG)

try:
    stream = open("myconf.yml", 'r')
except FileNotFoundError:
    stream = open("conf.yml", 'r')
config = yaml.load(stream, Loader=yaml.FullLoader)

VIRUSTOTAL_URL = config.get("api").get("virustotal").get("url")
VIRUSTOTAL_KEY = config.get("api").get("virustotal").get("key")
HYBRID_ANALYSIS_URL = config.get("api").get("hybrid_analysis").get("url")
HYBRID_ANALYSIS_KEY = config.get("api").get("hybrid_analysis").get("key")
CAPE_URL = config.get("api").get("cape").get("url")
CAPE_KEY = config.get("api").get("cape").get("key")
MALSHARE_URL = config.get("api").get("malshare").get("url")
MALSHARE_KEY = config.get("api").get("malshare").get("key")
SYNC_DELAY = 30

async def main():
    for filename in args.filenames:
        L = await asyncio.gather(
            upload_virustotal(filename),
            upload_cape(filename),
            upload_hybrid_analysis(filename),
            upload_malshare(filename)
        )
    print(L)

async def upload_virustotal(filename):
    try:
        logger.info("Uploading to Virustotal")
        if not VIRUSTOTAL_KEY:
            logger.warning("Virustotal API key not found, please fill it in conf.yml file")
            return
        headers = {'x-apikey': VIRUSTOTAL_KEY}
        url = f"{VIRUSTOTAL_URL}/files"
        files = {'file': open(filename, 'rb')}

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=files) as resp:
                text = await resp.json()
                resp.status
                if not(resp.status == 200):
                    logger.error(f"Virustotal: cannot upload {filename}, error code: {resp.status}, reason: {text}")
                    return
                else:
                    id = text.get('data').get('id')
                    logger.info(f"Virustotal: {filename} uploaded, id: {id}")
                    if not args.skip:
                        await monitor_virustotal_task(id)

    except asyncio.TimeoutError:
        logger.error("Virustotal upload, TimeoutError")


async def monitor_virustotal_task(task_id):
    headers = {'x-apikey': VIRUSTOTAL_KEY}
    url = f"{VIRUSTOTAL_URL}/analyses/{task_id}"
    status = "queued"
    while status in ("queued", "in-progress"):
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                text = await resp.json()
                resp.status
                if not(resp.status == 200):
                    logger.error(f"Virustotal: cannot monitor {url}, error code: {resp.status}, reason: {text}")
                    return
                else:
                    status = text.get("data").get("attributes").get("status")
                    if status in ("queued", "in-progress"):
                        logger.debug(f"Virustotal: time before next sync: {SYNC_DELAY}")
                        await asyncio.sleep(SYNC_DELAY)
                    else:
                        logger.info(f"Virustotal: task {task_id} finished with status {status}")
                        logger.info(f"Virustotal: analysis available at {text.get('data').get('links').get('item')}")
                        return


async def monitor_cape_task(task_id):
    headers = {'Authorization': f"Token {CAPE_KEY}"}
    url = f"{CAPE_URL}/tasks/view/{task_id}"
    status = "pending"
    while status in ("pending", "running"):
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                text = await resp.json()
                if not(resp.status == 200 and text.get("error") == False):
                    logger.error(f"Cape: cannot monitor {url}, error code: {resp.status}, reason: {text}")
                    return
                else:
                    status = text.get("data").get("status")
                    if status in ("pending", "running"):
                        logger.debug(f"Cape: time before next sync: {SYNC_DELAY}")
                        await asyncio.sleep(SYNC_DELAY)
                    else:
                        set_trace()
                        logger.info(f"Cape: task {task_id} finished with status {status}")
                        return



async def upload_cape(filename):
    try:
        logger.info("Uploading to cape")
        if not CAPE_KEY:
            logger.warning("Cape: API key not found, please fill it in conf.yml file")
            return

        headers = {'Authorization': f"Token {CAPE_KEY}"}
        url = f"{CAPE_URL}/tasks/create/file/"
        files = {'file': open(filename, 'rb')}

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=files) as resp:
                text = await resp.json()
                resp.status
                if not(resp.status == 200 and text.get("error") == False):
                    logger.error(f"Cape: cannot upload {filename}, error code: {resp.status}, reason: {text}")
                    return
                else:
                    task_ids = text.get('data').get('task_ids')
                    logger.info(f"Cape: {filename} uploaded, id: {task_ids}")
                    if not args.skip:
                        for task_id in task_ids:
                            await monitor_cape_task(task_id)
    
    except asyncio.TimeoutError:
        logger.error("Cape upload, TimeoutError")


# Environment ID.
# 300: 'Linux (Ubuntu 16.04, 64 bit)', 
# 200: 'Android Static Analysis', 
# 120: 'Windows 7 64 bit', 
# 110: 'Windows 7 32 bit (HWP Support)', 
# 100: 'Windows 7 32 bit'
async def upload_hybrid_analysis(filename, environment_id='120', experimental_anti_evasion='true'):
    try:
        logger.info("Uploading to hybrid analysis")
        if not HYBRID_ANALYSIS_KEY:
            logger.warning("Hybrid Analysis API key not found, please fill it in conf.yml file")
            return
        
        headers = {
            'api-key': HYBRID_ANALYSIS_KEY,
            'user-agent': 'Falcon Sandbox'
        }
        url = f"{HYBRID_ANALYSIS_URL}/submit/file"
        form_data = aiohttp.FormData()
        form_data.add_field('file', open(filename, 'rb'), filename=filename)
        form_data.add_field('environment_id', environment_id)
        form_data.add_field('experimental_anti_evasion', experimental_anti_evasion)
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=form_data) as resp:
                text = await resp.json()
                resp.status
                if resp.status not in (200, 201):
                    logger.error(f"Hybrid Analysis: cannot upload {filename}, error code: {resp.status}, reason: {text}")
                    return
                else:
                    job_id = text.get('job_id')
                    sha256 = text.get('sha256')
                    logger.info(f"Hybrid Analysis: {filename} uploaded, job_id: {job_id}")
                    if not args.skip:
                        await monitor_hybrid_task(job_id)
                        logger.info(f"Hybrid Analysis: report available at https://www.hybrid-analysis.com/sample/{sha256}?environmentId={environment_id}")

    except asyncio.TimeoutError:
        logger.error("Hybrid Analysis upload, TimeoutError")


async def monitor_hybrid_task(task_id):
    headers = {
        'api-key': HYBRID_ANALYSIS_KEY,
        'user-agent': 'Falcon Sandbox'
    }
    url = f"{HYBRID_ANALYSIS_URL}/report/{task_id}/state"

    status = "IN_QUEUE"
    while status in ("IN_QUEUE", "IN_PROGRESS"):
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                text = await resp.json()
                resp.status
                if not(resp.status == 200):
                    logger.error(f"Hybrid Analysis: cannot monitor {url}, error code: {resp.status}, reason: {text}")
                    return
                else:
                    status = text.get("state")
                    if status in ("IN_QUEUE", "IN_PROGRESS"):
                        logger.debug(f"Hybrid Analysis: time before next sync: {SYNC_DELAY}")
                        await asyncio.sleep(SYNC_DELAY)
                    else:
                        logger.info(f"Hybrid Analysis: task {url} finished with status {status}")
                        return


async def upload_malshare(filename):
    try:
        logger.info("Uploading to malshare")
        if not MALSHARE_KEY:
            logger.warning("Malshare API key not found, please fill it in conf.yml file")
            return

        url = f"{MALSHARE_URL}?api_key={MALSHARE_KEY}&action=upload"
        form_data = aiohttp.FormData()
        form_data.add_field('upload', open(filename, 'rb'), filename=filename)

        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=form_data) as resp:
                text = await resp.text()
                resp.status
                if not(resp.status == 200):
                    logger.error(f"Malshare: cannot upload {filename}, error code: {resp.status}, reason: {text}")
                    return
                else:
                    logger.info(f"Malshare: {filename} uploaded, {text}")

    except asyncio.TimeoutError:
        logger.error("Malshare upload, TimeoutError")


if __name__ == "__main__":
    asyncio.run(main())