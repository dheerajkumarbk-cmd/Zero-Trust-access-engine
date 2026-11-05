# Layer 6 part H: the analyst console

*Notes for the integration session. Code: `src/main/resources/console/` (everything except `modules/admin|lab|guide`).
Tests: `ConsoleSourceTest`, `ConsoleShellTest` (and the server tests of part G, `docs/layer-6/part-g.md`).*

## 1. What it is

Plain HTML, CSS and ES modules served by the console server. No npm, no framework, no CDN, no build step, no font or
image from elsewhere. One custom element per view; one file, `api.js`, is the only code that talks to the server.

| File | Job |
|---|---|
| `index.html` | One `<dw-app>` element and one module script. No inline script, style or handler |
| `shell.js` (`dw-app`) | Login or app; navigation from `/console/api/modules`; hash router; live feed; keyboard; step-up dialog; module loader |
| `api.js` | Every call (`fetch`, `EventSource`); keeps the anti-forgery token in memory only; `X-Dwarpal-Background` for refreshes that must not extend a session |
| `dom.js` | `h()` builds elements: text via text nodes, attributes from an allow-list, links only to `#/...` routes, events with `addEventListener` |
| `view.js`, `table.js`, `parts.js`, `format.js`, `prefs.js` | View base class (a failed load shows "Unavailable", never an empty list), dense table with a j/k cursor, shared pieces (priority badge, entity and evidence links, case-detail cache), time formatting, the only `localStorage` use (theme and saved queries, in try/catch) |
| `views/*.js` | `dw-login`, `dw-statusbar`, `dw-overview`, `dw-queue`, `dw-cases`, `dw-case`, `dw-hunt`, `dw-entity`, `dw-response`, `dw-audit`, `dw-attack` |
| `style.css` | Dark by default, light through `prefers-color-scheme` (and a Theme button: auto, dark, light); no inline styles needed anywhere |

### Views (plan section 5)

| View | What it shows | Source |
|---|---|---|
| Overview | Open P1/P2/P3-4, SLA breached, unassigned, isolations and overdue acknowledgements, awaiting second analyst; the P1/P2 cases to open next; risk leaders; **sources reporting or SILENT in the last 24 hours** (from a `count by dataset`); the daily report for leads | `soc/metrics`, `queue`, `risk/top`, `counts`, `reports/daily` |
| Alert queue | P1 to P4 with entity, score, state, SLA (with a **BREACHED** word), assignee, alert count and **why this rank** (the ranker's reasons; loaded for the first 15 rows and the selected row) | `soc/queue`, `soc/cases/{id}` |
| Cases | The same table for all cases including closed | `soc/cases` |
| Case workspace | Summary, SLA, assignment (to me / to another analyst), every alert with its entities, techniques, **evidence as links to audit sequence numbers**, ranker's reasons, whether the SOC may act; decide buttons that sign a verdict with a confirm dialog and, when needed, the **step-up** dialog; the answer shows result, mode, isolated devices and **who signed with which key** and the "lab's analyst key" notice; timeline; notes with an add form | `soc/cases/{id}`, `.../timeline`, notes, assignment, verdicts |
| Hunt | Query box (`/` jumps here), window and limit, examples, syntax help, results table with evidence class and audit numbers, **`count by` as a table with bars**, saved queries (kept in this browser only) | `soc/search`, `soc/counts` |
| Entity page | Risk score and level, **contributions** (source, current weight with a bar, when, reason, evidence links), cases about it, recent events | `soc/risk/{kind}/{id}`, `soc/cases`, `soc/search` |
| Response | Isolated devices, whether the sensor acknowledged (OVERDUE in words), counters of held-back actions and refused verdicts, playbook version | `soc/isolations`, `soc/metrics` |
| Audit explorer | Newest records, filter by type, one record with payload, previous MAC, neighbours; **"Verify the whole chain"** with the anchor result | `audit/*` |
| ATT&CK | Technique grid by tactic from the alerts of the (up to 80) highest-priority open cases, shade and an "xN" count | `soc/queue`, `soc/cases/{id}` |
| Status bar | Feed (live / reconnecting), scenario state and speed, **scenario time**, alerts raised, a loud banner if the console cannot write its audit records, step-up freshness, idle end of the session | `stream`, `lab`, `me` |

Keyboard: `j` / `k` move in the table, `Enter` opens, `/` goes to Hunt with the query box focused, `?` shows the list, `Esc`
closes dialogs. Priority is a word and a shape (`▲ P1 critical`, `◆ P2 high`, `● P3 medium`, `○ P4 low`) as well as a
colour; SLA breach, "needs 2nd analyst", "SILENT", "OVERDUE" are words too.

### Shell contract for other parts' modules

`console/modules/<id>/index.js` has `export default { id, title, requires, view }`; `view(root, shell)` fills `root` and may
return a cleanup function. `shell.api.get(path[, {background}])`, `shell.api.post(path, object)` are scoped to
`/console/api/<id>/` (the module cannot reach any other route), add the CSRF header, resolve to JSON or reject with an
`Error` carrying the server's short public message and `.status`. `shell.needStepUp()` resolves after a fresh second factor.
`shell.me`, `shell.lab`, `shell.events` (a `live` event for stream events) and `shell.navigate(hash)` are available.

## 2. Standards lines for the front end, and their tests

| Standards line (section 3, "Output and input", "Secrets", "Static files") | How | Test |
|---|---|---|
| No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, string `setTimeout`, inline handlers | Not present; `dom.js` is the only way elements are made | `ConsoleSourceTest.noScriptCanTurnText...` (19 patterns, comments stripped), `noPageHasInlineScriptStyleOrHandlers`, and `theGateCatchesWhatItIsMeantToCatch` proves each pattern matches its attack |
| Strict CSP with Trusted Types works | No inline script/style, no `.style` writes, no `javascript:` URLs, no foreign addresses | `ConsoleSourceTest` (the same patterns) |
| One place talks to the server | `api.js` | `ConsoleSourceTest.onlyApiJsTalksToTheServer` |
| Only a harmless preference in `localStorage`, guarded | `prefs.js` | `ConsoleSourceTest.storageIsOnlyInThePreferencesFile...` |
| Nothing secret in the page | The session cookie is HttpOnly; the CSRF token is in a JS variable only; passwords are cleared from the form after use | `ConsoleSourceTest` (no `sessionStorage`, `indexedDB`, `document.cookie`) |
| Every file the page needs is served, every import resolves | | `ConsoleShellTest` |
| Fail closed: an error is shown as "Unavailable", never as an empty list | `DwView.fail`, `unavailable()`; the ATT&CK view says "Incomplete" when cases could not be read | exercised in the live run below |

### What was and was not checked in a browser (honest account)

The built-in browser refuses the lab's own certificate authority (`ERR_CERT_AUTHORITY_INVALID`), and trusting a CA or turning
certificate checks off is the user's decision, not mine; the owner chose to **skip the browser check**. So **nothing was
looked at with eyes**: layout, colours, dark/light, focus rings, dialogs and the keyboard shortcuts are untested in a real
browser. What was done instead:

* Every script passes `node --check` (syntax).
* A scratch harness (not in the repository) ran the real `api.js` and every view against a **running `ConsoleMain`**
  (`NODE_EXTRA_CA_CERTS` pointed at the lab CA for that Node process only) with a small stand-in DOM, as cleo and as ana, and
  printed what each view rendered: overview, queue, cases, case, entity (landing and one entity), hunt, response, audit
  (list and one record), ATT&CK. All rendered real data from the SOC API with no "Unavailable".
* The same harness added a note containing `<img onerror>`, `<script>` and `<svg onload>` to a case and rendered the case:
  no `img`, `script`, `svg` or `iframe` element appeared in the tree, no `on*` attribute and no non-route `href`; the text
  was in the page as text.
* Server side, everything the views call is covered by part G's tests.

The owner should open `https://localhost:8443/` once (`ConsoleMain` prints the logins) and look.

## 3. Red-team notes for part H

| ID | Attack | Result |
|---|---|---|
| H1 | Stored XSS in a note, an alert text, a host name, a user agent: markup in every free-text field the SOC API returns | Failed. All text enters through `h()` text nodes; the harness above proved it for a note; the source test fails the build on any markup sink |
| H2 | A link in data that goes elsewhere (`javascript:`, another origin) | Failed. `h()` writes an `href` only if it matches `#/...`; a test pattern in `ConsoleSourceTest` also forbids `javascript:` in any file |
| H3 | A query in the hunt box that breaks the page when echoed (`"` and `\` in an entity id) | Failed. The entity page escapes only for the query language and inserts everything else as text; the hunt link goes through `encodeURIComponent` and the route allow-list for hrefs |
| H4 | Another module (parts I, J) with `innerHTML` or a script from a CDN | Would fail the build: the scan includes `modules/**` |
| **H5** | `encodeURIComponent` leaves `! ' ( ) *` unescaped, and the first version of the href allow-list did not accept them, so a hunt link for a query containing them silently lost its `href` (found while reading the code, not an attack) | Fixed in `dom.js` (the characters are allowed in the fragment); every link goes through the same function |
| H6 | The page keeps a session alive by polling | Refreshes triggered by the live feed or timers send `X-Dwarpal-Background: 1`, which the server does not count as activity (tested server side) |

Open points: no browser check (above); the ATT&CK view shows detections only because the SOC API does not expose rule
coverage; the entity page cannot show half-lives because the risk JSON gives the current (decayed) weight only.

## 4. Requests to the integration session

1. **Risk JSON:** please add `halfLifeSeconds` and `initialWeight` to each contribution in `SocJson.risk` so the entity page
   can show "weight 2.1 of 4.0, halves every 3 d" (plan section 5).
2. **Coverage for ATT&CK:** an endpoint (or a field on `soc/metrics`) with the techniques the rules could detect
   (`MitreCoverage`), then the grid can colour what is covered but quiet.
3. **Sensor heartbeats** (your 0b item 2): when they land, the overview's "Sources" panel should read them instead of the
   24-hour event count.
4. A one-line `LabSession` swap in `ConsoleMain` (see `docs/layer-6/part-g.md`, section 6).

## 5. Differences from an enterprise console

| Enterprise SOC console | This console |
|---|---|
| A framework front end, a design system, tested in several browsers, accessibility audited | Plain modules, one author, not yet seen in any browser (see section 2) |
| Case management with attachments, templates, ticket sync, collaboration | Notes, assignment, verdicts |
| Saved searches, dashboards and alerts shared across a team | Saved queries in this browser only |
| ATT&CK Navigator layers, coverage from detection engineering | A detection grid only |
| Verdicts and response actions signed by the analyst's key | Signed by the console server's lab key after a fresh step-up, said on screen |
