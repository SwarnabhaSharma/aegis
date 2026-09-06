"""Take screenshots of all Aegis console pages."""

import asyncio

from playwright.async_api import async_playwright

BASE = "http://127.0.0.1:8099"
OUT = "D:/Resume/Aegis/screenshots"

PAGES = [
    ("dashboard", "/dashboard"),
    ("incidents", "/"),
    ("operations", "/console/operations"),
    ("controls", "/console/controls"),
    ("audit", "/console/audit"),
    ("api-docs", "/docs"),
]


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1280, "height": 800})

        for name, path in PAGES:
            print(f"Capturing {name}...")
            await page.goto(f"{BASE}{path}", wait_until="networkidle")
            await page.wait_for_timeout(500)
            await page.screenshot(path=f"{OUT}/{name}.png", full_page=True)
            print(f"  -> {OUT}/{name}.png")

        await browser.close()
        print("Done.")


asyncio.run(main())
