// De schermen van Unbreakable. Navigeren gebeurt met het deel na # in de URL.

import { api, currentUser, setUser } from './api.js';
import { encrypt, decrypt, computeMac, verifyMac } from './crypto.js';

const app = document.getElementById('app');

function escapeHtml(text) {
    return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function formatDate(value) {
    return new Date(value).toLocaleString('nl-BE', {
        day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'
    });
}

function showWho() {
    const user = currentUser();
    document.getElementById('who').innerHTML = user
        ? `Je bent <strong>${escapeHtml(user)}</strong> (<a href="#/">wisselen</a>)`
        : '';
}

// ------------------------------------------------------------------ naam kiezen

function renderLogin() {
    const user = currentUser();
    app.innerHTML = `
        <div class="text-center mb-5">
            <h1 class="display-4">Unbreakable</h1>
            <p class="lead">Berichten die niemand anders kan lezen. Dat is toch de bedoeling.</p>
        </div>
        <div class="row justify-content-center">
            <div class="col-md-5">
                ${user ? `<p>Je gebruikt Unbreakable als <strong>${escapeHtml(user)}</strong>.
                          <a href="#/inbox">Naar je inbox</a></p>
                          <p>Iemand anders? Vul hieronder een andere naam in.</p>` : ''}
                <form id="login">
                    <div class="form-group">
                        <label for="name">Wie ben je?</label>
                        <input id="name" class="form-control" placeholder="bijvoorbeeld Anna"
                               required minlength="2" maxlength="40" />
                    </div>
                    <button type="submit" class="btn btn-primary">Verder</button>
                </form>
            </div>
        </div>`;

    document.getElementById('login').addEventListener('submit', (event) => {
        event.preventDefault();
        setUser(document.getElementById('name').value.trim());
        location.hash = '#/inbox';
    });
}

// ------------------------------------------------------------------ inbox

async function renderInbox(params) {
    const user = currentUser();
    const from = params.get('from') || '';

    const all = await api.inbox();
    const senders = [...new Set(all.map(m => m.sender))].sort();
    const messages = all.filter(m => !from || m.sender === from);

    app.innerHTML = `
        <h1>Inbox van ${escapeHtml(user)}</h1>
        <p>
            <a href="#/nieuw" class="btn btn-primary">Nieuw bericht</a>
            <button id="export" class="btn btn-outline-secondary">Exporteer als JSON</button>
        </p>
        <form id="filter" class="mb-3">
            <div class="form-row align-items-end">
                <div class="col-auto">
                    <label for="from">Van</label>
                    <select id="from" class="form-control">
                        <option value="">Iedereen</option>
                        ${senders.map(s => `<option value="${escapeHtml(s)}" ${s === from ? 'selected' : ''}>${escapeHtml(s)}</option>`).join('')}
                    </select>
                </div>
                <div class="col-auto">
                    <button type="submit" class="btn btn-secondary">Filter</button>
                </div>
            </div>
        </form>
        <div id="list"></div>`;

    const rows = messages.map(m => `
        <tr>
            <td>${escapeHtml(m.sender)}</td>
            <td><a href="#/bericht/${m.id}"><code>${escapeHtml(m.ciphertext)}</code></a></td>
            <td>${escapeHtml(m.keyLine)}</td>
            <td>${formatDate(m.sentAt)}</td>
        </tr>`).join('');

    document.getElementById('list').innerHTML = messages.length
        ? `<table class="table">
               <thead><tr><th>Van</th><th>Ciphertext</th><th>Regel</th><th>Verzonden</th></tr></thead>
               <tbody>${rows}</tbody>
           </table>`
        : '<p class="text-muted">Geen berichten.</p>';

    document.getElementById('filter').addEventListener('submit', (event) => {
        event.preventDefault();
        const next = new URLSearchParams();
        const newFrom = document.getElementById('from').value;
        if (newFrom) next.set('from', newFrom);
        location.hash = '#/inbox' + (next.toString() ? '?' + next.toString() : '');
    });

    document.getElementById('export').addEventListener('click', async () => {
        const data = await api.exportJson();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'inbox.json';
        link.click();
        URL.revokeObjectURL(link.href);
    });
}

// ------------------------------------------------------------------ bericht lezen

async function renderMessage(id) {
    const m = await api.message(id);

    app.innerHTML = `
        <h1>Bericht lezen</h1>
        <dl class="row">
            <dt class="col-sm-2">Van</dt><dd class="col-sm-10">${escapeHtml(m.sender)}</dd>
            <dt class="col-sm-2">Aan</dt><dd class="col-sm-10">${escapeHtml(m.recipient)}</dd>
            <dt class="col-sm-2">Verzonden</dt><dd class="col-sm-10">${formatDate(m.sentAt)}</dd>
            <dt class="col-sm-2">Regel in codeboek</dt><dd class="col-sm-10">${escapeHtml(m.keyLine)}</dd>
            <dt class="col-sm-2">Ciphertext</dt><dd class="col-sm-10"><code>${escapeHtml(m.ciphertext)}</code></dd>
            <dt class="col-sm-2">MAC</dt><dd class="col-sm-10"><code>${escapeHtml(m.mac)}</code></dd>
        </dl>
        <div class="row">
            <div class="col-md-8">
                <form id="decrypt" autocomplete="off">
                    <div class="form-group">
                        <label for="key">Sleutel (regel ${escapeHtml(m.keyLine)} uit je codeboek)</label>
                        <input id="key" class="form-control" required autocomplete="off" />
                    </div>
                    <div class="form-group">
                        <label for="hmac-key">HMAC-sleutel</label>
                        <input id="hmac-key" class="form-control" required autocomplete="off" />
                    </div>
                    <button type="submit" class="btn btn-primary">Controleren en ontsleutelen</button>
                </form>
            </div>
        </div>
        <div id="result" class="message-body my-3"></div>
        <p>
            <button id="delete" class="btn btn-outline-danger">Verwijderen</button>
            <a href="#/inbox" class="btn btn-link">Terug naar je inbox</a>
        </p>`;

    document.getElementById('decrypt').addEventListener('submit', async (event) => {
        event.preventDefault();
        const result = document.getElementById('result');
        const key = document.getElementById('key').value;
        const hmacKey = document.getElementById('hmac-key').value;

        // De sleutels blijven niet in het formulier staan.
        event.target.reset();

        try {
            // Eerst de MAC controleren: een gewijzigd bericht ontsleutelen we niet.
            const valid = await verifyMac(hmacKey, m.keyLine, m.ciphertext, m.mac);
            if (!valid) {
                result.className = 'alert alert-danger message-body my-3';
                result.textContent = 'MAC ongeldig: het bericht of het regelnummer is gewijzigd, ' +
                    'of de HMAC-sleutel is fout. Het bericht is niet ontsleuteld.';
                return;
            }

            result.className = 'alert alert-success message-body my-3';
            result.textContent = 'MAC geldig. Bericht: ' + decrypt(m.ciphertext, key);
        } catch (error) {
            result.className = 'alert alert-danger message-body my-3';
            result.textContent = error.message;
        }
    });

    document.getElementById('delete').addEventListener('click', async () => {
        if (confirm('Ben je zeker dat je dit bericht wil verwijderen?')) {
            await api.remove(id);
            location.hash = '#/inbox';
        }
    });
}

// ------------------------------------------------------------------ bericht versturen

async function renderNew() {
    const users = await api.users();

    app.innerHTML = `
        <h1>Nieuw bericht</h1>
        <p class="text-muted">Van: ${escapeHtml(currentUser())}</p>
        <div class="row">
            <div class="col-md-8">
                <form id="compose" autocomplete="off">
                    <div class="form-group">
                        <label for="recipient">Aan</label>
                        <input id="recipient" class="form-control" list="known-users" autocomplete="off"
                               required minlength="2" maxlength="40" />
                        <datalist id="known-users">
                            ${users.map(u => `<option value="${escapeHtml(u)}"></option>`).join('')}
                        </datalist>
                    </div>
                    <div class="form-group">
                        <label for="text">Bericht</label>
                        <input id="text" class="form-control" required maxlength="2000" autocomplete="off" />
                        <small class="form-text text-muted">Enkel letters, cijfers en spaties. Niet langer dan je sleutel.</small>
                    </div>
                    <div class="form-group">
                        <label for="key-line">Regelnummer in het codeboek</label>
                        <input id="key-line" class="form-control" type="number" min="1" required autocomplete="off" />
                        <small class="form-text text-muted">Gebruik elke regel maar één keer.</small>
                    </div>
                    <div class="form-group">
                        <label for="key">Sleutel (de tekst van die regel)</label>
                        <input id="key" class="form-control" required autocomplete="off" />
                    </div>
                    <div class="form-group">
                        <label for="hmac-key">HMAC-sleutel</label>
                        <input id="hmac-key" class="form-control" required autocomplete="off" />
                    </div>
                    <button type="submit" class="btn btn-primary">Versleutelen en versturen</button>
                    <a href="#/inbox" class="btn btn-link">Annuleren</a>
                </form>
                <div id="error" class="alert alert-danger mt-3" hidden></div>
            </div>
        </div>`;

    document.getElementById('compose').addEventListener('submit', async (event) => {
        event.preventDefault();
        const error = document.getElementById('error');
        error.hidden = true;

        try {
            const keyLine = Number(document.getElementById('key-line').value);
            const ciphertext = encrypt(
                document.getElementById('text').value,
                document.getElementById('key').value
            );
            const mac = await computeMac(document.getElementById('hmac-key').value, keyLine, ciphertext);

            // Enkel dit gaat naar de server: geen bericht en geen sleutel.
            await api.send({
                recipient: document.getElementById('recipient').value.trim(),
                ciphertext,
                keyLine,
                mac,
            });
            location.hash = '#/inbox';
        } catch (err) {
            error.textContent = err.message;
            error.hidden = false;
        }
    });
}

// ------------------------------------------------------------------ over

function renderAbout() {
    app.innerHTML = `
        <h1>Over Unbreakable</h1>
        <p>Unbreakable is een berichtenapp. Je stuurt een bericht naar iemand, en enkel die persoon kan het lezen.
           Dat is tenminste het doel.</p>
        <p>Deze versie is de starter app van het vak Cyber Security Advanced aan AP Hogeschool.
           Ze werkt, maar is nog helemaal niet veilig. Doorheen het semester maken jullie ze beter.</p>
        <p>De app bestaat uit twee delen: deze single page app in je browser, en een API op de server.
           Bekijk de developer tools van je browser om te zien wat er over en weer gaat.</p>
        <p>Berichten worden in je browser versleuteld met een sleutel uit een codeboek dat je vooraf met de
           ontvanger uitwisselt. De server krijgt enkel de ciphertext, de MAC en het regelnummer.</p>
        <p class="text-danger">Gebruik deze app enkel in je eigen labomgeving en nooit met echte gegevens.</p>`;
}

// ------------------------------------------------------------------ navigatie

async function route() {
    showWho();

    const [path, query] = (location.hash || '#/').slice(1).split('?');
    const params = new URLSearchParams(query || '');

    try {
        if (path === '/' || path === '') {
            return renderLogin();
        }
        if (path === '/over') {
            return renderAbout();
        }
        if (!currentUser()) {
            location.hash = '#/';
            return;
        }
        if (path === '/inbox') {
            return await renderInbox(params);
        }
        if (path === '/nieuw') {
            return await renderNew();
        }
        const match = path.match(/^\/bericht\/(\d+)$/);
        if (match) {
            return await renderMessage(match[1]);
        }
        app.innerHTML = '<p>Deze pagina bestaat niet.</p>';
    } catch (error) {
        app.innerHTML = `<div class="alert alert-danger">Er liep iets mis: ${escapeHtml(error.message)}</div>`;
    }
}

window.addEventListener('hashchange', route);
route();
