# Genereert docs/architectuur.png en docs/threat-model.png met Graphviz.
# Vereist: het programma "dot" (Graphviz). Uitvoeren vanuit eender welke map:
#   python docs/bron/diagrammen.py
#
# De dreigingen (T-nummers) en flows (F-nummers) komen overeen met docs/threat-model.md.
# Pas je daar iets aan, pas het dan ook hier aan.

import subprocess
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent
FONT = "Segoe UI"

# Status van een dreiging, met de kleur van de badge.
GROEN, ORANJE, ROOD = "#1b7f3b", "#c66a00", "#c62828"
STATUS_TEKST = {
    GROEN: "gemitigeerd",
    ORANJE: "deels of manuele afspraak",
    ROOD: "open (gepland of aanvaard)",
}

# Nummer: (STRIDE, korte omschrijving, status)
DREIGINGEN = {
    1: ("S", "Andere naam in X-User", ROOD),
    2: ("I", "Afluisteren / MitM op het netwerk", GROEN),
    3: ("T", "Ciphertext of regelnummer wijzigen in DB", GROEN),
    4: ("T", "Kwaadaardige code of dependency", GROEN),
    5: ("R", "Beheerder wist logs", ROOD),
    6: ("R", "Verzender ontkent bericht", ROOD),
    7: ("I", "Beheerder leest berichten in DB", GROEN),
    8: ("I", "Geheimen in config en repo", ROOD),
    9: ("D", "HTTP flood", ORANJE),
    10: ("E", "Andermans bericht via id (IDOR)", ROOD),
    11: ("E", "Code op runner via pull request", GROEN),
    12: ("E", "Aanval omzeilt de WAF", ORANJE),
    13: ("E", "App container draait als root", ROOD),
    14: ("I", "Regel uit codeboek hergebruikt", ORANJE),
    15: ("I", "Codeboek gestolen", ORANJE),
    16: ("S", "HMAC-sleutel gelekt", ORANJE),
    17: ("I", "Sleutels met zwakke generator", ORANJE),
    18: ("T", "Server levert aangepaste JavaScript", ROOD),
    19: ("I", "XSS steelt ingetypte sleutels", ORANJE),
    20: ("S", "Afzender in DB vervalst", ROOD),
    21: ("S", "Rij gekopieerd (replay)", ORANJE),
    22: ("D", "Rij verwijderd", ROOD),
    23: ("I", "Metadata en lengte zichtbaar", ROOD),
}


def esc(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def badges(numbers):
    """Een rij gekleurde T-badges als HTML-tabelcellen."""
    cells = "".join(
        f'<TD BGCOLOR="{DREIGINGEN[n][2]}" STYLE="rounded" FIXEDSIZE="TRUE" WIDTH="36" HEIGHT="22">'
        f'<FONT COLOR="white" POINT-SIZE="10"><B>T{n}</B></FONT></TD>'
        for n in numbers
    )
    return f'<TABLE BORDER="0" CELLSPACING="3" CELLPADDING="0"><TR>{cells}</TR></TABLE>'


def label(title, sub="", threats=(), title_color="#1f2933"):
    rows = f'<TR><TD><FONT POINT-SIZE="12" COLOR="{title_color}"><B>{esc(title)}</B></FONT></TD></TR>'
    for line in sub.split("\n") if sub else []:
        rows += f'<TR><TD><FONT POINT-SIZE="9" COLOR="#52606d">{esc(line)}</FONT></TD></TR>'
    if threats:
        rows += f"<TR><TD>{badges(threats)}</TD></TR>"
    return f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="1">{rows}</TABLE>>'


def flow(number, text, threats=(), color="#334e68"):
    rows = f'<TR><TD><FONT POINT-SIZE="9" COLOR="{color}"><B>F{number}</B> {esc(text)}</FONT></TD></TR>'
    if threats:
        rows += f"<TR><TD>{badges(threats)}</TD></TR>"
    return f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="0" BGCOLOR="white">{rows}</TABLE>>'


def render(name, source):
    # De Graphviz-broncode gaat via stdin naar dot, zodat er geen losse .dot-bestanden achterblijven.
    subprocess.run(["dot", "-Tpng", "-Gdpi=150", "-o", str(DOCS / f"{name}.png")],
                   input=source.encode("utf-8"), check=True)
    print(f"{name}.png gemaakt")


HEADER = f"""
  fontname="{FONT}"; bgcolor="white"; pad=0.4;
  node [fontname="{FONT}", margin="0.15,0.08"];
  edge [fontname="{FONT}", color="#627d98", arrowsize=0.7, penwidth=1.3];
"""

# ---------------------------------------------------------------------- architectuur

ARCHITECTUUR = f"""digraph architectuur {{
  {HEADER}
  rankdir=LR; nodesep=0.5; ranksep=0.9; newrank=true; compound=true;
  labelloc=t; label=<<FONT POINT-SIZE="20"><B>Unbreakable: architectuur</B></FONT><BR/><FONT POINT-SIZE="11" COLOR="#52606d">stand na opdracht 3 · berichten worden in de browser versleuteld</FONT>>;
  node [shape=box, style="rounded,filled", fillcolor="white", penwidth=1.4];

  subgraph cluster_users {{
    label=<<B>Gebruikers</B>>; style="rounded,filled"; fillcolor="#eef4fb"; color="#9fb3c8";
    verzender [label={label("Browser verzender", "SPA: app.js, api.js, crypto.js\nmodulo 37 + HMAC SHA256 (Web Crypto)")}, color="#2f6fb0"];
    ontvanger [label={label("Browser ontvanger", "SPA: MAC controleren\nen ontsleutelen")}, color="#2f6fb0"];
  }}

  subgraph cluster_oob {{
    label=<<B>Buiten de app</B>>; style="rounded,filled"; fillcolor="#fff6e0"; color="#e0b04f";
    codeboek [label={label("Codeboek + HMAC-sleutel", "50 regels × 40 tekens (A-Z 0-9 _)\nkopie bij elke partij")}, shape=note, style=filled, color="#b7791f"];
  }}

  subgraph cluster_server {{
    label=<<B>Server</B> · Linux VM (IPv6) · Docker Compose>; style="rounded,filled"; fillcolor="#f2f5f8"; color="#829ab1"; penwidth=1.6;
    bunkerweb [label={label("BunkerWeb 1.6", "WAF + reverse proxy\nTLS (Let's Encrypt), ModSecurity")}, color="#7b3fa0"];
    scheduler [label={label("BunkerWeb scheduler", "configuratie, certificaten")}, color="#7b3fa0"];
    app [label={label("App container", "ASP.NET Core (.NET 10)\nstatische SPA + /api, poort 8080")}, color="#1f7a8c"];
    db [label={label("PostgreSQL 17", "tabel Messages: Sender, Recipient,\nCiphertext, KeyLine, Mac, SentAt")}, shape=cylinder, color="#1f7a8c"];
    runner [label={label("Self-hosted runner", "GitHub Actions, user runner")}, color="#486581"];
    env [label={label(".env", "databankgegevens, SERVER_NAME")}, shape=note, style=filled, color="#486581"];
  }}

  subgraph cluster_github {{
    label=<<B>GitHub</B>>; style="rounded,filled"; fillcolor="#f4f0fa"; color="#a58fc4";
    repo [label={label("Repository", "publiek, branch main")}, shape=cylinder, color="#5b3f8c"];
    actions [label={label("Security pipeline", "Gitleaks · Trivy · Semgrep")}, color="#5b3f8c"];
  }}

  developer [label={label("Developer", "Robbe / Nathan")}, color="#486581"];

  verzender -> bunkerweb [label={flow(2, "HTTPS 443: ciphertext, regel, MAC")}];
  bunkerweb -> ontvanger [label={flow(2, "HTTPS 443: zelfde gegevens")}];
  bunkerweb -> app [label={flow(3, "HTTP 8080 · bw-services")}];
  app -> db [label={flow(4, "SQL 5432 · db-net")}];
  scheduler -> bunkerweb [label={flow(11, "API · bw-universe")}, style=dashed];
  codeboek -> verzender [label={flow(5, "vooraf, buiten de app", color="#9c6500")}, style=dashed, color="#d69e2e"];
  codeboek -> ontvanger [label={flow(5, "vooraf, buiten de app", color="#9c6500")}, style=dashed, color="#d69e2e"];
  env -> app [style=dotted, arrowhead=none];
  developer -> repo [label={flow(6, "git push")}];
  repo -> actions [label={flow(7, "bij push / PR")}];
  actions -> runner [label={flow(8, "deploy-job, enkel push op main")}];
  runner -> app [label={flow(9, "git pull + docker compose up --build")}, style=dashed];
  developer -> scheduler [label={flow(10, "SSH 22 via jumphost, sleutel")}, style=dashed, lhead=cluster_server];

  {{ rank=same; verzender; ontvanger; }}
}}
"""

# ---------------------------------------------------------------------- threat model

def legend():
    rows = '<TR><TD COLSPAN="3" ALIGN="LEFT"><FONT POINT-SIZE="13"><B>Dreigingen</B></FONT></TD></TR>'
    for n, (stride, text, status) in DREIGINGEN.items():
        rows += (
            f'<TR><TD BGCOLOR="{status}" STYLE="rounded" FIXEDSIZE="TRUE" WIDTH="36" HEIGHT="22"><FONT COLOR="white" POINT-SIZE="10"><B>T{n}</B></FONT></TD>'
            f'<TD><FONT POINT-SIZE="10" COLOR="#52606d"><B>{stride}</B></FONT></TD>'
            f'<TD ALIGN="LEFT"><FONT POINT-SIZE="10">{esc(text)}</FONT></TD></TR>'
        )
    rows += '<TR><TD COLSPAN="3"> </TD></TR>'
    for color, text in STATUS_TEKST.items():
        rows += (
            f'<TR><TD BGCOLOR="{color}" STYLE="rounded" FIXEDSIZE="TRUE" WIDTH="36" HEIGHT="22"> </TD>'
            f'<TD COLSPAN="2" ALIGN="LEFT"><FONT POINT-SIZE="10">{text}</FONT></TD></TR>'
        )
    rows += (
        '<TR><TD COLSPAN="3"> </TD></TR>'
        '<TR><TD COLSPAN="3" ALIGN="LEFT"><FONT POINT-SIZE="9" COLOR="#52606d">'
        'S spoofing · T tampering · R repudiation<BR ALIGN="LEFT"/>'
        'I information disclosure · D denial of service<BR ALIGN="LEFT"/>'
        'E elevation of privilege<BR ALIGN="LEFT"/><BR ALIGN="LEFT"/>'
        'rechthoek = externe entiteit · afgerond = proces<BR ALIGN="LEFT"/>'
        'cilinder / notitie = data store<BR ALIGN="LEFT"/>'
        'rode stippellijn = vertrouwensgrens<BR ALIGN="LEFT"/>'
        '</FONT></TD></TR>'
    )
    return f'<<TABLE BORDER="1" CELLBORDER="0" COLOR="#bcccdc" CELLSPACING="3" CELLPADDING="3" STYLE="rounded">{rows}</TABLE>>'


BOUNDARY = 'style="dashed,rounded"; color="#c62828"; penwidth=1.8; fontcolor="#c62828";'
PROCESS = 'shape=box, style="rounded,filled", fillcolor="white", color="#1f7a8c", penwidth=1.4'
ENTITY = 'shape=box, style=filled, fillcolor="#f0f4f8", color="#486581", penwidth=1.4'
STORE = 'shape=cylinder, style=filled, fillcolor="#fffaf0", color="#9c6500", penwidth=1.4'
NOTE = 'shape=note, style=filled, fillcolor="#fffaf0", color="#9c6500", penwidth=1.4'

THREAT_MODEL = f"""digraph threat_model {{
  {HEADER}
  rankdir=LR; nodesep=0.45; ranksep=0.8; newrank=true;
  labelloc=t; label=<<FONT POINT-SIZE="20"><B>Unbreakable: threat model (STRIDE)</B></FONT><BR/><FONT POINT-SIZE="11" COLOR="#52606d">stand na opdracht 3 · T-nummers komen overeen met docs/threat-model.md</FONT>>;

  subgraph cluster_client {{
    label=<<B>Vertrouwensgrens: apparaat van de gebruiker</B>>; {BOUNDARY}
    gebruiker [label={label("Gebruiker", "verzender of ontvanger")}, {ENTITY}];
    spa [label={label("SPA in de browser", "mod 37 versleutelen, HMAC, verify\nbericht en sleutels enkel lokaal", (18, 19))}, {PROCESS}];
  }}

  subgraph cluster_oob {{
    label=<<B>Vertrouwensgrens: buiten de app</B>>; {BOUNDARY}
    codeboek [label={label("Codeboek", "sleutel per regelnummer", (14, 15, 17))}, {NOTE}];
    hmac [label={label("HMAC-sleutel", "gedeeld, herbruikbaar", (16,))}, {NOTE}];
  }}

  subgraph cluster_server {{
    label=<<B>Vertrouwensgrens: server (Linux VM)</B>>; {BOUNDARY}
    subgraph cluster_docker {{
      label=<<B>Vertrouwensgrens: Docker netwerken</B>>; {BOUNDARY}
      waf [label={label("BunkerWeb WAF", "TLS, ModSecurity, rate limiting", (9, 12))}, {PROCESS}];
      api [label={label("App: SPA + API", "levert de JavaScript, bewaart rijen", (1, 6, 10, 13))}, {PROCESS}];
      db [label={label("PostgreSQL", "ciphertext, regel, MAC + metadata", (3, 7, 20, 21, 22, 23))}, {STORE}];
    }}
    config [label={label("Config", ".env en appsettings.json", (8,))}, {NOTE}];
    logs [label={label("Logs", "Docker en BunkerWeb", (5,))}, {NOTE}];
    runner [label={label("Self-hosted runner", "deploy na geslaagde scans", (11,))}, {PROCESS}];
  }}

  subgraph cluster_github {{
    label=<<B>Vertrouwensgrens: GitHub (derde partij)</B>>; {BOUNDARY}
    repo [label={label("Repository", "publiek", (8,))}, {STORE}];
    pipeline [label={label("Security pipeline", "Gitleaks, Trivy, Semgrep", (4,))}, {PROCESS}];
  }}

  developer [label={label("Developer", "")}, {ENTITY}];
  beheerder [label={label("Beheerder / aanvaller", "met toegang tot de server")}, {ENTITY}, color="#c62828"];
  legende [label={legend()}, shape=plain];

  gebruiker -> spa [label={flow(1, "bericht + sleutels, lokaal")}];
  codeboek -> gebruiker [label={flow(5, "vooraf uitwisselen", color="#9c6500")}, style=dashed, color="#d69e2e"];
  hmac -> gebruiker [label={flow(5, "vooraf uitwisselen", color="#9c6500")}, style=dashed, color="#d69e2e"];
  spa -> waf [label={flow(2, "HTTPS 443: ciphertext, regel, MAC, X-User", (2,))}];
  waf -> spa [label={flow(2, "HTTPS 443: JavaScript + berichten", (18,))}];
  waf -> api [label={flow(3, "HTTP 8080, intern")}];
  api -> db [label={flow(4, "SQL 5432, wachtwoord uit .env")}];
  config -> api [style=dotted, arrowhead=none];
  api -> logs [style=dotted, arrowhead=none];
  developer -> repo [label={flow(6, "git push")}];
  repo -> pipeline [label={flow(7, "scans")}];
  pipeline -> runner [label={flow(8, "HTTPS, enkel push op main")}];
  runner -> api [label={flow(9, "docker compose up --build")}, style=dashed];
  beheerder -> db [label={flow(10, "SSH 22, beheerrechten", color="#c62828")}, style=dashed, color="#c62828"];
  beheerder -> api [style=dashed, color="#c62828"];
  beheerder -> logs [style=dashed, color="#c62828"];

  db -> legende [style=invis];
}}
"""

if __name__ == "__main__":
    render("architectuur", ARCHITECTUUR)
    render("threat-model", THREAT_MODEL)
