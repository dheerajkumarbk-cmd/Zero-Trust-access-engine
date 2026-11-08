// Scenario lab: launch attacks, control the scenario clock, write rules and playbooks, export a run.
import { el, clear, button, stylesheet, table } from './dom.js';

const KIND = { ATTACK: 'Attack', LOOK_ALIKE: 'Harmless look-alike', BASELINE: 'Baseline' };

function view(root, shell) {
  stylesheet('/console/modules/lab/lab.css');
  const api = shell.api;
  let timer = null;
  let lastLaunch = null;

  const status = el('div', { class: 'lab-status', role: 'status', 'aria-live': 'polite' });
  const message = el('p', { class: 'lab-message', role: 'status', 'aria-live': 'polite' });
  const scenarios = el('div', { class: 'lab-cards' });
  const result = el('div', { class: 'lab-result' });
  const journal = el('div', { class: 'lab-journal' });
  const sandbox = el('div', { class: 'lab-sandbox' });
  const exportBox = el('div', { class: 'lab-export' });

  function say(text, bad) {
    message.textContent = text;
    message.className = bad ? 'lab-message lab-bad' : 'lab-message';
  }

  async function act(promise, done) {
    try {
      const r = await promise;
      if (done) done(r);
      return r;
    } catch (e) {
      say(e && e.message ? e.message : 'The lab could not do that.', true);
      return null;
    }
  }

  // ---- clock ------------------------------------------------------------------------------------------
  function drawStatus(s) {
    clear(status);
    const parts = [
      ['Clock', s.state],
      ['Scenario time', s.now],
      ['Speed', s.speed + 'x'],
      ['Open P1', s.openByPriority.P1],
      ['Open P2', s.openByPriority.P2],
      ['Open P3', s.openByPriority.P3],
      ['Open P4', s.openByPriority.P4],
      ['Alerts raised', s.alertsRaised],
    ];
    for (const [k, v] of parts) {
      status.append(el('span', { class: 'lab-stat' }, el('b', {}, k + ': '), String(v)));
    }
    if (s.problem) status.append(el('span', { class: 'lab-bad' }, s.problem));
  }

  async function refreshStatus() {
    await act(api.get('status'), drawStatus);
  }

  function controls() {
    const speed = el('input', { id: 'lab-speed', type: 'number', min: 1, max: 3600, value: 60 });
    const minutes = el('select', { 'aria-label': 'fast-forward' },
      [10, 30, 60, 120, 360].map((m) => el('option', { value: m }, m >= 60 ? m / 60 + ' h' : m + ' min')));
    const roles = shell.me.person.roles;
    if (!roles.includes('LEAD') && !roles.includes('ADMIN')) {
      return el('p', {}, 'The clock runs by itself. Pause, speed and fast-forward are for SOC leads.');
    }
    return el('div', { class: 'lab-controls' },
      button('Pause', () => act(api.post('control/pause', {}), drawStatus)),
      button('Resume', () => act(api.post('control/resume', {}), drawStatus)),
      el('label', { for: 'lab-speed' }, 'Speed (simulated seconds per second)'),
      speed,
      button('Set speed', () => act(api.post('control/speed', { speed: Number(speed.value) }), (s) => {
        drawStatus(s);
        say('Speed changed.');
      })),
      minutes,
      button('Fast-forward', async () => {
        say('Fast-forwarding...');
        await act(api.post('control/fastforward', { minutes: Number(minutes.value) }), (s) => {
          drawStatus(s);
          say('Time moved on.');
          if (lastLaunch) showReport(lastLaunch);
        });
      }),
      !roles.includes('ADMIN') ? null : button('Reset to day zero', async () => {
        if (!window.confirm('Reset the lab? All cases, risk and launched scenarios are forgotten.')) return;
        const ok = await act(shell.needStepUp());
        if (ok === null) return;
        say('Resetting; this takes a few seconds...');
        await act(api.post('control/reset', {}), (s) => {
          drawStatus(s);
          lastLaunch = null;
          clear(result);
          say('The lab is back at day zero.');
          loadJournal();
        });
      }, { class: 'lab-danger' }));
  }

  // ---- scenarios --------------------------------------------------------------------------------------
  function card(s) {
    return el('article', { class: 'lab-card' },
      el('h3', {}, s.id + '  ' + s.title),
      el('p', { class: 'lab-kind' }, KIND[s.kind] || s.kind),
      el('h4', {}, 'What the attacker does'),
      el('p', {}, s.attacker),
      el('h4', {}, 'What the defender should see'),
      el('p', {}, s.defender),
      s.techniques.length ? el('p', { class: 'lab-tech' }, 'MITRE: ' + s.techniques.join('; ')) : null,
      button('Launch ' + s.id, () => launch(s.id)));
  }

  async function launch(id) {
    say('Launching ' + id + '...');
    await act(api.post('launch/' + id, {}), (r) => {
      lastLaunch = r.launch.number;
      say(r.note);
      clear(result);
      result.append(el('h3', {}, 'Launched ' + r.launch.scenario),
        el('p', {}, r.launch.person ? 'About ' + r.launch.person + (r.launch.devices.length ? ' (' + r.launch.devices.join(', ') + ')' : '')
          : 'About everyone with no earlier suspicion.'),
        el('p', {}, 'Plays between ' + r.launch.startsAt + ' and ' + r.launch.endsAt + ' (scenario time).'),
        el('div', { class: 'lab-report' }));
      loadJournal();
      showReport(r.launch.number);
    });
  }

  async function showReport(n) {
    await act(api.get('launches/' + n), (r) => {
      let box = result.querySelector('.lab-report');
      if (!box) {
        box = el('div', { class: 'lab-report' });
        result.append(box);
      }
      clear(box);
      box.append(el('h4', {}, 'What the lab has produced so far'));
      box.append(r.decisions.length
        ? table(['Request', 'Engine decision', 'Policy', 'Chance of attack', 'Signals'],
          r.decisions.map((d) => [d.requestId, d.outcome, d.policy, d.pAttack, d.signals || '-']))
        : el('p', {}, 'No engine decision yet (this scenario has none, or time has not reached it).'));
      box.append(r.alerts.length
        ? table(['Priority', 'Rule', 'Engine', 'May act', 'Why'],
          r.alerts.map((a) => [a.priority, a.rule, a.engine, a.actionable ? 'yes' : 'no', a.reasons.join('; ')]))
        : el('p', {}, 'No alert about this scenario yet.'));
    });
  }

  async function loadJournal() {
    await act(api.get('launches'), (r) => {
      clear(journal);
      journal.append(el('h3', {}, 'Launched so far'));
      journal.append(r.launches.length
        ? table(['#', 'Scenario', 'By', 'About', 'Starts', ''], r.launches.slice().reverse().map((l) => [
          String(l.number), l.scenario, l.by, l.person || '-', l.startsAt,
          button('Results', () => {
            lastLaunch = l.number;
            showReport(l.number);
          })]))
        : el('p', {}, 'Nothing yet.'));
    });
  }

  // ---- sandbox ----------------------------------------------------------------------------------------
  function drawFindings(box, r) {
    box.append(el('p', { class: r.accepted ? 'lab-good' : 'lab-bad' },
      (r.accepted ? 'Accepted. ' : 'Refused. ') + (r.note || '')));
    if (r.findings.length) {
      box.append(table(['Level', 'Where', 'Message'], r.findings.map((f) => [f.level, f.where, f.message])));
    }
  }

  function sandboxView(examples) {
    const rule = el('textarea', { rows: 14, cols: 80, spellcheck: false, 'aria-label': 'correlation rule (YAML)' });
    const play = el('textarea', { rows: 10, cols: 80, spellcheck: false, 'aria-label': 'playbook (YAML)' });
    const ruleOut = el('div', { class: 'lab-out' });
    const playOut = el('div', { class: 'lab-out' });
    const pick = (kind, area) => {
      const s = el('select', { 'aria-label': 'example ' + kind },
        el('option', { value: '' }, 'Load an example...'),
        examples.filter((x) => x.kind === kind).map((x) => el('option', { value: x.id }, x.title + ' (' + x.expect + ')')));
      s.addEventListener('change', () => {
        const x = examples.find((e) => e.id === s.value);
        if (x) {
          area.value = x.yaml;
          say(x.teaches);
        }
      });
      return s;
    };
    const runRule = (run) => act(api.post('sandbox/rule', { yaml: rule.value, run }), (r) => {
      clear(ruleOut);
      drawFindings(ruleOut, r);
      if (r.ran) {
        ruleOut.append(el('p', {}, 'Read ' + r.eventsRead + ' recorded events; the rule would have raised ' + r.alerts + ' alerts.'));
        ruleOut.append(table(['Rule', 'Matched', 'Fired', 'Suppressed'], r.stats.map((s) => [s.rule, s.matched, s.fired, s.suppressed])));
        if (r.sample.length) {
          ruleOut.append(table(['Rule', 'Severity', 'At', 'About', 'Summary'],
            r.sample.map((s) => [s.rule, s.severity, s.at, s.entities.join(', '), s.summary])));
        }
        if (r.silent.length) ruleOut.append(el('p', {}, 'Matched nothing: ' + r.silent.join(', ')));
      }
    });
    const runPlay = () => act(api.post('sandbox/playbook', { yaml: play.value }), (r) => {
      clear(playOut);
      drawFindings(playOut, r);
      if (r.plans.length) {
        playOut.append(table(['Rule', 'What it would do'], r.plans.map((p) => [p.rule, p.steps.join('; ') || 'nothing (people decide)'])));
      }
    });
    return el('div', {},
      el('p', {}, 'Nothing here touches the live lab. A rule runs on a private copy of the recorded events; a playbook is only checked, never installed.'),
      el('h3', {}, 'Correlation rule'), pick('rule', rule), rule,
      el('div', { class: 'lab-row' }, button('Check', () => runRule(false)), button('Check and run on recorded events', () => runRule(true))), ruleOut,
      el('h3', {}, 'Playbook'), pick('playbook', play), play,
      el('div', { class: 'lab-row' }, button('Check', runPlay)), playOut);
  }

  // ---- export -----------------------------------------------------------------------------------------
  function exportView() {
    return el('div', {}, el('p', {}, 'A sanitised JSON replay of this run: pseudonyms for people, devices and addresses, no keys, no host names.'),
      button('Export this run', async () => {
        const doc = await act(api.get('export'));
        if (doc === null) return;
        const text = JSON.stringify(doc, null, 2);
        const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
        const a = el('a', { href: url, download: 'dwarpal-run.json' }, 'Download dwarpal-run.json');
        clear(exportBox);
        exportBox.append(a);
        say('The export is ready.');
      }), exportBox);
  }

  // ---- page -------------------------------------------------------------------------------------------
  root.append(el('h2', {}, 'Scenario lab'),
    el('p', {}, 'Launch an attack on the simulated company, then follow it through the analyst console. Everyone in it is made up.'),
    status, controls(), message,
    el('h3', {}, 'Scenarios'), scenarios, result, journal,
    el('h3', {}, 'Write your own rule or playbook'), sandbox,
    el('h3', {}, 'Export'), exportView());

  (async () => {
    await act(api.get('scenarios'), (r) => r.scenarios.forEach((s) => scenarios.append(card(s))));
    await act(api.get('sandbox/examples'), (r) => sandbox.append(sandboxView(r.examples)));
    await refreshStatus();
    await loadJournal();
  })();
  timer = setInterval(() => {
    refreshStatus();
    if (lastLaunch) showReport(lastLaunch);
  }, 5000);
  return () => clearInterval(timer);
}

export default { id: 'lab', title: 'Scenario lab', requires: 'ANALYST', view };
