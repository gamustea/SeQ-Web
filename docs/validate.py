from playwright.sync_api import sync_playwright
import os

errors = []
resources_loaded = []

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()

    page.on("console", lambda msg: errors.append(f"Console {msg.type}: {msg.text}") if msg.type == "error" else None)

    def on_response(response):
        if response.status >= 400:
            errors.append(f"404 Error: {response.url} - Status {response.status}")
        else:
            resources_loaded.append(response.url)

    page.on("response", on_response)

    file_path = f"file://{os.getcwd()}/index.html"
    page.goto(file_path, wait_until="networkidle")

    video = page.query_selector("video")
    if video:
        print("Video element found")

    title = page.title()
    print(f"Page title: {title}")

    hero = page.query_selector(".hero")
    if hero:
        print("Hero section found")

    browser.close()

if errors:
    print("\nErrors found:")
    for e in errors:
        print(f"  - {e}")
else:
    print("\nNo errors - Page validated successfully!")

print(f"Resources loaded: {len(resources_loaded)}")
