<p align="center">
 <img src="images/logo.png" height="200"><br/>
A powerful XSS scanner revisited by NC (DOM XSS based support added, changes in xsscon.py, crawler.py, Log.py, core.py) <br/>


## Installing

Requirements: <br/>

<li>asyncio
aiohttp
pyppeteer
beautifulsoup4
lxml
requests
colorama
</li>

<li> python 3.12 </li>
<br/>
Commands:

```bash
git clone https://github.com/Admin9961/XSSCon2
chmod 755 -R XSSCon
cd XSSCon
python3 xsscon.py --help 
```
## Usage
Basic usage:

```bash
python3 xsscon.py -u http://testphp.vulnweb.com
```
<br/>
Advanced usage:

```bash
python3 xsscon.py --help
(added DOM XSS based support! Syntax 'python xsscon.py -u https://www.example.com --dom')
```

## Main features

* crawling all links on a website ( crawler engine )
* POST and GET forms are supported
* many settings that can be customized
* Advanced error handling
* Multiprocessing support.✔️
* XSS DOM based support via headless browser added by NC ✔️

* Sorry for my bad english 
* if you run xsscon on the win10 terminal you will get an untidy output
* now it doesn't support DOM

