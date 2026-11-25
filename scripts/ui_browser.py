#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The browser half of scripts/live_ui.py. Runs INSIDE Playwright's image, never on the host.

Drives headless Chromium through the demo's own pages as a person would and
checks the status of each page response and the text on it. Reads UI_DEMO,
UI_STS, UI_ALLOWED_USER, UI_DENIED_USER, UI_ALLOWED_PASSWORD,
UI_DENIED_PASSWORD (never printed) and UI_OUT (screenshots). Prints one JSON
summary as its last line and exits 1 on any mismatch.
"""

import json
import os
import re
import sys
import time
import urllib.parse

from playwright.sync_api import sync_playwright

DEMO = os.environ["UI_DEMO"].rstrip("/")
STS = os.environ["UI_STS"].rstrip("/")
OUT = os.environ.get("UI_OUT") or "/out"
PEOPLE = {
    "allowed": (os.environ["UI_ALLOWED_USER"], os.environ["UI_ALLOWED_PASSWORD"]),
    "denied": (os.environ["UI_DENIED_USER"], os.environ["UI_DENIED_PASSWORD"]),
}

checks = []
problems = []
shots = []


def where(url):
    """A label for a URL, never the URL itself (they carry handles and state)."""
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(url))
    path = urllib.parse.urlsplit(url).path
    return ("demo " if origin == DEMO else "iya-sts " if origin == STS else "elsewhere ") + path


def shot(page, name):
    path = os.path.join(OUT, f"{len(shots) + 1:02d}-{name}.png")
    page.screenshot(path=path, full_page=True)
    shots.append(os.path.basename(path))


def expect(name, ok, detail):
    checks.append({"check": name, "ok": bool(ok), **detail})
    if not ok:
        problems.append(name)
    print(("ok   " if ok else "FAIL ") + name + " " + json.dumps(detail), flush=True)


def main_text(page):
    return page.inner_text("main")


def signed_in_as(page):
    if not page.url.startswith(DEMO) or page.locator("details.acct-menu").count() == 0:
        return None
    return page.inner_text("details.acct-menu summary .menu-name").strip()


def complete_sign_in(page, who, trail):
    """From wherever the click left the browser to the demo's signed-in page:
    iya-sts's sign-in page (type the username and password, press Sign in),
    its account chooser (use another account), an optional step (skip)."""
    username, password = PEOPLE[who]
    deadline = time.time() + 90
    while time.time() < deadline:
        page.wait_for_load_state("load")
        name = signed_in_as(page)
        if name is not None:
            return name
        if page.url.startswith(STS):
            if page.locator("#username").is_visible():
                trail.append("iya-sts sign-in page")
                shot(page, f"{who}-iya-sts-sign-in")
                page.fill("#username", username)
                if page.locator("#password").is_visible():
                    page.fill("#password", password)
                page.click("#kc-login")
                page.wait_for_timeout(500)
                continue
            if page.locator("#password").is_visible():
                trail.append("iya-sts password page")
                page.fill("#password", password)
                page.click("#kc-login")
                page.wait_for_timeout(500)
                continue
            if page.locator("#account-another").is_visible():
                trail.append("iya-sts account chooser: another account")
                shot(page, f"{who}-iya-sts-accounts")
                page.click("#account-another")
                page.wait_for_timeout(500)
                continue
            skip = page.locator("button[name=action][value=skip]")
            if skip.count() and skip.first.is_visible():
                trail.append("iya-sts optional step: skip")
                skip.first.click()
                page.wait_for_timeout(500)
                continue
            post = page.locator("form input[name=SAMLResponse]")
            if post.count():
                # The POST binding's form; it submits itself. Press its button
                # only if it is still here, as a person without scripts would.
                page.wait_for_timeout(1500)
                if page.url.startswith(STS) and post.count():
                    trail.append("iya-sts POST binding form: continue")
                    page.locator("form:has(input[name=SAMLResponse]) [type=submit]").first.click()
                continue
        page.wait_for_timeout(300)
    shot(page, f"{who}-sign-in-stuck")
    raise RuntimeError(f"the sign-in as {who} did not reach the demo; last at {where(page.url)}")


def sign_in(page, who, acs, start):
    """Click a sign-in control on the demo and finish at iya-sts."""
    trail = []
    acs.clear()
    start()
    name = complete_sign_in(page, who, trail)
    return name, trail


def visit(page, path, label, by_link):
    if by_link:
        with page.expect_navigation() as navigation:
            page.click(f'nav.site-nav a[href="{path}"]')
        response = navigation.value
    else:
        response = page.goto(DEMO + path)
    page.wait_for_load_state("load")
    shot(page, label)
    return response.status, main_text(page)


def run(playwright):
    browser = playwright.chromium.launch()
    # The loopback iya-sts live_ui.py just started presents its own CA's
    # certificate; the browser is not given that CA, so it does not verify it.
    context = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
    page = context.new_page()
    acs = []
    page.on("response", lambda r: acs.append({"method": r.request.method, "status": r.status})
            if r.url.startswith(DEMO + "/saml/acs") else None)

    # The allowed user: open the demo and click Sign in.
    first = page.goto(DEMO + "/")
    shot(page, "home-signed-out")
    expect("home page signed out", first.status == 200 and "Sign in with SAML 2.0" in main_text(page), {"status": first.status})
    name, trail = sign_in(page, "allowed", acs, lambda: page.click('main a.button.primary[href="/login"]'))
    shot(page, "allowed-signed-in")
    expect("allowed user signed in through the POST binding", name == PEOPLE["allowed"][0] and any(a["method"] == "POST" and a["status"] == 303 for a in acs),
           {"user": name, "acs": list(acs), "via": trail})
    expect("allowed user's home page names them", f"Signed in as {PEOPLE['allowed'][0]}" in main_text(page), {})
    for by_link in (False, True):
        how = "top-bar link" if by_link else "address"
        status, text = visit(page, "/attribute-protected", f"allowed-attribute-protected-{'link' if by_link else 'goto'}", by_link)
        expect(f"allowed GET /attribute-protected by {how}", status == 200 and "Allowed" in text and "The PEP permitted it" in text,
               {"status": status, "want": 200})
        status, text = visit(page, "/orders/42", f"allowed-order-42-{'link' if by_link else 'goto'}", by_link)
        expect(f"allowed GET /orders/42 by {how}", status == 200 and "Order 42" in text and "The PEP permitted read" in text,
               {"status": status, "want": 200})

    # Sign out from the user menu.
    page.click("details.acct-menu summary")
    shot(page, "allowed-user-menu")
    with page.expect_navigation():
        page.click("details.acct-menu form[action='/logout'] button")
    page.wait_for_load_state("load")
    shot(page, "signed-out")
    expect("signed out from the user menu", page.locator("details.acct-menu").count() == 0 and "Sign in with SAML 2.0" in main_text(page), {})
    after = page.goto(DEMO + "/attribute-protected")
    expect("signed out GET /attribute-protected", after.status == 401, {"status": after.status, "want": 401})
    page.goto(DEMO + "/")

    # The denied user. Sign in first; if iya-sts's session for the allowed user
    # lingers and signs them straight back in, "Sign in with another account"
    # (ForceAuthn) from the user menu.
    name, trail = sign_in(page, "denied", acs, lambda: page.click('main a.button.primary[href="/login"]'))
    path = ["Sign in"] + trail
    if name != PEOPLE["denied"][0]:
        shot(page, "lingering-session")
        path.append(f"signed straight back in as {name}: Sign in with another account")

        def another():
            page.click("details.acct-menu summary")
            page.click('details.acct-menu a[href="/login?force=1"]')

        name, trail = sign_in(page, "denied", acs, another)
        path += trail
    shot(page, "denied-signed-in")
    expect("denied user signed in through the POST binding", name == PEOPLE["denied"][0] and any(a["method"] == "POST" and a["status"] == 303 for a in acs),
           {"user": name, "acs": list(acs), "via": path})
    for by_link in (False, True):
        how = "top-bar link" if by_link else "address"
        status, text = visit(page, "/attribute-protected", f"denied-attribute-protected-{'link' if by_link else 'goto'}", by_link)
        expect(f"denied GET /attribute-protected by {how}", status == 403 and "Not allowed" in text and "The PEP denied it" in text,
               {"status": status, "want": 403})
        status, text = visit(page, "/orders/42", f"denied-order-42-{'link' if by_link else 'goto'}", by_link)
        expect(f"denied GET /orders/42 by {how}", status == 200 and "Order 42" in text, {"status": status, "want": 200})
    # page.request shares the context's cookie jar, but on plain http it leaves out a
    # Secure cookie (the demo's sid is Secure; the browser itself sends it, loopback
    # being a secure context), and context.cookies(url) filters it the same way. So
    # the cookies the browser holds for the demo's host and path go in the Cookie
    # header, as the browser would send them (a cookie is not scoped to a port).
    host = urllib.parse.urlsplit(DEMO).hostname
    held = [c for c in context.cookies() if c["domain"].lstrip(".") == host and "/orders/42".startswith(c["path"])]
    jar = "; ".join(f"{c['name']}={c['value']}" for c in held)
    posted = page.request.post(DEMO + "/orders/42", headers={"accept": "text/html", "cookie": jar})
    body = posted.text()
    expect("denied POST /orders/42 by page.request with the browser's cookies", posted.status == 403 and "The PEP denied <code>write</code> on order 42" in body,
           {"status": posted.status, "want": 403, "cookies": sorted(c["name"] for c in held)})
    # And the same POST from the page, which the browser sends with its own cookies.
    in_page = page.evaluate("fetch('/orders/42', {method: 'POST', credentials: 'same-origin'}).then(r => r.status)")
    expect("denied POST /orders/42 by fetch() from the page", in_page == 403, {"status": in_page, "want": 403})
    browser.close()


def main():
    error = None
    try:
        with sync_playwright() as playwright:
            run(playwright)
    except Exception as err:  # the summary says what stopped it
        # No URL in the output: they carry handles and state.
        error = re.sub(r"https?://\S+", "<url>", str(err).splitlines()[0])[:400]
        problems.append("stopped")
    summary = {"ok": not problems and error is None, "checks": len(checks), "passed": sum(1 for c in checks if c["ok"]),
               "failed": problems, "error": error, "results": checks, "screenshots": shots}
    print(json.dumps(summary))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
