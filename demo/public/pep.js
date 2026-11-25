// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The Policy enforcement tab. Every two seconds it fetches the server-drawn
// fragment again (GET /pep-status.html), so the counters and the times stay
// current. A pane the person closed stays closed across the redraw: each pane
// is a <details> with a stable id. The server escapes everything in the
// fragment. A hidden page does not poll, and a 401 means the session is gone,
// so the browser goes back to the sign-in page.
// Its own scope: every page script shares one global scope, and two
// top-level declarations of one name (app.js and pep.js both had `panel`)
// make the second script fail to load at all.
(() => {
const pane = document.getElementById('pep-panel');
const EVERY_MS = 2000;

async function redraw() {
  if (!pane || document.hidden) return;
  try {
    const answer = await fetch('/pep-status.html', { credentials: 'same-origin', cache: 'no-store' });
    if (answer.status === 401) {
      window.location.assign('/');
      return;
    }
    if (!answer.ok) return;
    const closed = [...pane.querySelectorAll('details[id]')].filter((d) => !d.open).map((d) => d.id);
    pane.innerHTML = await answer.text();
    closed.forEach((id) => {
      const again = document.getElementById(id);
      if (again) again.open = false;
    });
    // The Collapse all / Expand all toggle reads the panes again.
    document.dispatchEvent(new Event('panes-redrawn'));
  } catch (err) {
    // The demo restarting: keep what is shown, and try on the next tick.
  }
}

if (pane) {
  setInterval(redraw, EVERY_MS);
  document.addEventListener('visibilitychange', redraw);
}
})();
