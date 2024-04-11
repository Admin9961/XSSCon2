import asyncio
import aiohttp
import logging
import backoff
from urllib.parse import urlparse, parse_qs
import pyppeteer
from bs4 import BeautifulSoup
import re
import sys
import os

COMMON_PARAMS = ['id', 'ref', 'page', 'lang', 'callback', 'redirect', 'action']
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

def setup_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='w')
    fileHandler.setFormatter(formatter)

    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)
    
log_file = "dom_xss.txt"
setup_logger(__name__, log_file)

async def analyze_dom_changes(browser, url, payload):
    page = await browser.newPage()
    dialog_triggered = False

    def handle_dialog(dialog):
        nonlocal dialog_triggered
        dialog_triggered = True
        logger.warning(f"Potential DOM-based XSS triggered at {url}: {dialog.message}")
        asyncio.create_task(dialog.dismiss())
    page.on('dialog', handle_dialog)

    try:
        await page.goto(url, timeout=30000)
    except pyppeteer.errors.TimeoutError:
        logger.error(f"Timeout occurred while loading {url}")
        await page.close()
        return

    body_html = await page.evaluate('document.body.innerHTML')
    if payload.strip('<>').lower() in body_html.lower():
        logger.info(f"Detected potential XSS via exact payload presence in HTML at {url}")
    else:
        script_tags = await page.evaluate('''() => {
            const scripts = [...document.querySelectorAll('script')];
            return scripts.map(script => script.innerHTML);
        }''')
        payload_found_in_script = any(payload.strip('<>').lower() in script.lower() for script in script_tags)
        if payload_found_in_script:
            logger.warning(f"Detected potential XSS with the payload in <script> tag at {url}")
        else:
            logger.info(f"No obvious signs of DOM-based XSS found at {url}")
    if dialog_triggered:
        logger.warning(f"Dialog triggered, indicating a potential DOM-based XSS at {url}")
    else:
        logger.info(f"After further analysis, no obvious signs of DOM-based XSS found at {url}")
    await page.close()

async def find_valid_parameters(session, url):
    valid_params = set()
    try:
        async with session.get(url, ssl=False) as response:
            if response.status == 200:
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                inputs = soup.find_all('input')
                valid_params.update(input.get('name') for input in inputs if input.get('name'))
                links = soup.find_all('a')
                for link in links:
                    query = urlparse(link.get('href', '')).query
                    params = parse_qs(query)
                    valid_params.update(params.keys())
                valid_params.update(COMMON_PARAMS)
                
    except Exception as e:
        logger.error(f"Error while searching for valid parameters in {url}: {e}")
    
    return list(valid_params)

async def find_links(session, url, retries=3):
    attempt = 0
    while attempt < retries:
        try:
            async with session.get(url, ssl=False) as response:
                text = await response.text()
                soup = BeautifulSoup(text, 'lxml')
                links = [link.get('href') for link in soup.find_all('a')]
                links = [link for link in links if link and link.startswith('http')]
                return list(set(links))
        except Exception as e:
            attempt += 1
            await asyncio.sleep(2)
    return []

def give_up(e):
    return e.status in [404, 403, 429]

@backoff.on_exception(backoff.expo,
                      aiohttp.ClientError,
                      max_tries=5,
                      giveup=lambda e: isinstance(e, aiohttp.ClientResponseError) and give_up(e))

async def test_dom_xss(browser, session, base_url, payload, valid_params):
    for param in valid_params:
        injected_url = f"{base_url}?{param}={payload}"
        try:
            async with session.get(injected_url, ssl=False) as response:
                response_text = await response.text()
                if payload.strip('<>').lower() in response_text.lower():
                    logger.warning(f"Potential XSS detected in response from {injected_url}")
                    logger.info(f"{injected_url} - IS_VULNERABLE")
                else:
                    logger.info(f"{injected_url} - NOT VULNERABLE")
                await analyze_dom_changes(browser, injected_url, payload)
                logger.info(f"Testing {injected_url} [Status code: {response.status}]")
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error {e.status} at {injected_url} [Reason: {e.message}]")
            await analyze_dom_changes(browser, injected_url, payload)
            logger.info(f"{injected_url} - NOT VULNERABLE")
        except aiohttp.ClientError as e:
            logger.error(f"Error testing {injected_url}: {str(e)}")
            logger.info(f"{injected_url} - NOT VULNERABLE")

async def main(base_url, payload):
    browser = await pyppeteer.launch()
    try:
        async with aiohttp.ClientSession() as session:
            if isinstance(base_url, list):
                base_url = base_url[0]
            valid_params = await find_valid_parameters(session, base_url)
            found_links = await find_links(session, base_url)
            tasks = [asyncio.create_task(test_dom_xss(browser, session, url, payload, valid_params)) for url in found_links]
            tasks.append(asyncio.create_task(test_dom_xss(browser, session, base_url, payload, valid_params)))
            await asyncio.gather(*tasks)
    finally:
        await browser.close()
