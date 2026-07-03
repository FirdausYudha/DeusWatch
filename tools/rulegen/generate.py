#!/usr/bin/env python3
"""
DeusWatch rule generator.

Emits DeusWatch-flavoured Sigma rules (the subset understood by
internal/detect/sigma) from curated corpuses. Reproducible: re-running
overwrites the generated folders deterministically (stable uuid5 ids).

Categories (each -> a one-level subfolder under rules/sigma so the loader,
which recurses exactly one level, picks them up):

  rules/sigma/judi/      online-gambling ("judi online") content indicators
  rules/sigma/deface/    web defacement markers + webshell file drops
  rules/sigma/fim/       File Integrity Monitoring on sensitive paths
  rules/sigma/endpoint/  suspicious process / command-line activity
  rules/sigma/agg/       aggregation (SQL-path) rules

Engine facts this generator relies on (see internal/detect/sigma):
  * A keyword selection (a YAML list) is substring-matched, case-insensitively,
    against ALL string fields of the event (event.original, file.path,
    process.command_line, user.name, ...). So a single keyword rule catches a
    gambling term whether it lands in a web access-log line, a FIM file path,
    or a command line.
  * Field selections support |contains |startswith |endswith |re; a value list
    is OR. Multiple selections combine via condition (and/or/not).
  * Single-event vs aggregation is split by the presence of '|' in condition.
"""

import itertools
import os
import re
import shutil
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES = os.path.join(ROOT, "rules", "sigma")
NS = uuid.UUID("0b3d9e2a-6c41-4f8a-9d5b-1e7c2a4f6b80")  # DeusWatch rule namespace

# Clean previously generated output up-front so re-runs are deterministic. The agg/
# folder is shared with hand-written rules, so it is NOT wiped - generated agg files
# are overwritten by name instead.
for _sub in ("judi", "deface", "fim", "endpoint"):
    _d = os.path.join(RULES, _sub)
    if os.path.isdir(_d):
        shutil.rmtree(_d)

REFS = {
    "judi": "https://attack.mitre.org/techniques/T1491/002/",
    "deface": "https://attack.mitre.org/techniques/T1491/",
    "webshell": "https://attack.mitre.org/techniques/T1505/003/",
    "fim": "https://attack.mitre.org/techniques/T1565/001/",
    "endpoint": "https://attack.mitre.org/techniques/T1059/",
}


def slug(s):
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")[:60] or "rule"


def rid(name):
    return str(uuid.uuid5(NS, name))


def yq(s):
    """Quote a scalar for YAML single-quoted style (safe for our values)."""
    return "'" + str(s).replace("'", "''") + "'"


def write_rule(subdir, name, title, desc, level, tags, detection_lines, logsource):
    d = os.path.join(RULES, subdir)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, name + ".yml")
    ls = "\n".join(f"  {k}: {v}" for k, v in logsource.items())
    tg = "\n".join(f"  - {t}" for t in tags)
    body = f"""title: {title}
id: {rid(subdir + '/' + name)}
status: experimental
description: >
  {desc}
references:
  - {REFS.get(subdir, REFS['endpoint'])}
author: DeusWatch (generated)
level: {level}
logsource:
{ls}
detection:
{detection_lines}
tags:
{tg}
"""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    return path


def keyword_detection(keywords):
    if not keywords:
        raise ValueError("keyword_detection: empty keyword list")
    lines = ["  keywords:"]
    for k in keywords:
        lines.append(f"    - {yq(k)}")
    lines.append("  condition: keywords")
    return "\n".join(lines)


def path_detection(patterns, actions, modifier="contains", field="file.path"):
    lines = ["  selection:"]
    lines.append(f"    {field}|{modifier}:")
    for p in patterns:
        lines.append(f"      - {yq(p)}")
    if actions:
        lines.append("  change:")
        lines.append("    event.action:")
        for a in actions:
            lines.append(f"      - {a}")
        lines.append("  condition: selection and change")
    else:
        lines.append("  condition: selection")
    return "\n".join(lines)


def cmd_detection(patterns, field="process.command_line", modifier="contains"):
    lines = ["  selection:"]
    lines.append(f"    {field}|{modifier}:")
    for p in patterns:
        lines.append(f"      - {yq(p)}")
    lines.append("  condition: selection")
    return "\n".join(lines)


# ── leetspeak expansion ───────────────────────────────────────────────────────
LEET = {"a": ["4", "@"], "e": ["3"], "i": ["1", "!"], "o": ["0"],
        "s": ["5", "$"], "g": ["9"], "t": ["7"], "b": ["8"], "l": ["1"]}


def leet_variants(word, limit=40):
    """Generate leetspeak spellings of `word` as the (bounded) cartesian product of
    per-character substitutions, so combined forms like g4c0r / g4c0rr are produced
    (not just single substitutions). Each result also gets a doubled-last-char twin
    (gacor -> gacorr, g4c0r -> g4c0rr), a very common obfuscation."""
    word = word.lower()
    opts = []
    for ch in word:
        o = [ch] + LEET.get(ch, [])
        opts.append(o[:3])  # cap options/char to keep the product bounded
    total = 1
    for o in opts:
        total *= len(o)
    combos = set()
    if total <= 4000:
        for combo in itertools.product(*opts):
            combos.add("".join(combo))
    else:  # fall back to single-substitution family + one aggressive form
        combos.add(word)
        for i, ch in enumerate(word):
            for rep in LEET.get(ch, []):
                combos.add(word[:i] + rep + word[i + 1:])
        combos.add("".join(LEET.get(c, [c])[0] for c in word))
    combos |= {w + w[-1] for w in list(combos) if w}  # doubled trailing char
    combos = {w for w in combos if len(w) >= 4}
    return sorted(combos)[:limit]


files_written = []


def emit(*args, **kw):
    files_written.append(write_rule(*args, **kw))


# ══════════════════════════════════════════════════════════════════════════════
#  1) JUDI ONLINE  (online gambling content indicators)
# ══════════════════════════════════════════════════════════════════════════════
JUDI_LOG = {"category": "web"}
JUDI_TAGS = ["attack.t1491.002", "attack.impact"]


def judi(name, title, desc, keywords, level="medium", tags=None):
    emit("judi", "judi_" + name, title, desc, level, tags or JUDI_TAGS,
         keyword_detection(keywords), JUDI_LOG)


# 1a. Core leetspeak terms - one rule per core term, packed with variants.
CORE_TERMS = [
    "gacor", "slot", "judi", "togel", "maxwin", "jackpot", "scatter",
    "deposit", "bandar", "cuan", "zeus", "olympus", "bonanza", "pragmatic",
    "rungkad", "wede", "withdraw", "jepe", "petir", "hoki", "sultan", "raja",
    "mahjong", "pgsoft", "sabung", "tembak", "parlay", "gampang", "menang",
    "rtp", "pragmaticplay", "starlight", "gatotkaca", "kakek", "zeus", "olympus",
    "spaceman", "aviator", "sweetbonanza", "mahjongways", "koitogel", "hongkong",
    "singapore", "sydney", "pgsoft", "habanero", "microgaming", "casino",
    "baccarat", "roulette", "poker", "domino", "ceme", "capsa", "sbobet",
    "sicbo", "dingdong", "fafafa", "linktogel", "situsslot", "agenslot",
    "dewa", "naga", "garuda", "kilat", "turbo", "anti", "boncos", "wd",
]
for t in sorted(set(CORE_TERMS)):
    if len(t) < 4:  # too short to keyword-match without false positives
        continue
    variants = leet_variants(t)
    if not variants:
        continue
    judi(f"leet_{slug(t)}",
         f"Judi Online - Leetspeak term '{t}' (SEO/content injection)",
         f"Leetspeak/obfuscated spellings of the gambling term '{t}' (e.g. g4c0r, "
         f"g4c0rr). Common in SEO-spam injected into a compromised site's pages, "
         f"file names, or query strings.",
         variants, level="high")

# 1b. Themed keyword corpuses (each rule fires once, packs many related terms).
THEMES = {
    "slot_umum": ("Slot / gacor umum", [
        "slot gacor", "slot online", "slot88", "situs slot", "agen slot", "link slot",
        "slot terpercaya", "slot maxwin", "slot pulsa", "slot dana", "slot deposit",
        "slot resmi", "slot terbaru", "slot hoki", "slot anti rungkad", "slot demo",
        "akun pro", "akun gacor", "pola gacor", "jam gacor", "bocoran slot", "rtp slot",
        "rtp live", "info rtp", "server luar", "server thailand", "slot thailand",
        "slot kamboja", "slot vietnam", "x500", "x1000", "auto maxwin",
    ]),
    "togel": ("Togel / lottery", [
        "togel online", "bandar togel", "agen togel", "toto gelap", "colok bebas",
        "colok jitu", "colok naga", "tebak angka", "prediksi togel", "bocoran togel",
        "angka jitu", "angka main", "shio togel", "4d 3d 2d", "diskon togel",
        "hadiah 2d", "hadiah 3d", "hadiah 4d", "bandar darat", "keluaran togel",
        "pengeluaran togel", "data keluaran", "result togel", "live draw",
    ]),
    "pasaran": ("Togel pasaran (markets)", [
        "togel hongkong", "keluaran hk", "result hk", "togel hkg", "data hk",
        "togel singapore", "keluaran sgp", "result sgp", "data sgp", "togel sgp",
        "togel sydney", "keluaran sdy", "result sdy", "data sdy", "togel sidney",
        "togel cambodia", "keluaran cambodia", "togel china", "togel japan",
        "togel taiwan", "togel macau", "togel bullseye", "togel magnum",
    ]),
    "casino": ("Live casino", [
        "live casino", "casino online", "roulette online", "baccarat online",
        "sicbo online", "dragon tiger", "dragon tiger online", "casino terpercaya",
        "judi casino", "meja casino", "dealer cantik", "agen casino", "wm casino",
        "sexy baccarat", "casino terbesar",
    ]),
    "kartu": ("Judi kartu (card games)", [
        "poker online", "idn poker", "domino qq", "bandar qq", "capsa susun",
        "bandar ceme", "ceme online", "qiu qiu", "gaple online", "dominoqq",
        "pkv games", "sakong online", "aduq online", "bandar poker", "super10",
    ]),
    "sabung": ("Sabung ayam (cockfighting)", [
        "sabung ayam", "sv388", "s128", "adu ayam", "ayam online", "laga ayam",
        "taji ayam", "sabung ayam online", "agen sabung ayam", "digmaan", "wa88",
    ]),
    "tembak_ikan": ("Tembak ikan (fish shooting)", [
        "tembak ikan", "fishing game", "judi tembak ikan", "game ikan online",
        "fish hunter", "royal fishing", "dragon fortune", "fishing war",
    ]),
    "bola": ("Sportsbook / judi bola", [
        "judi bola", "taruhan bola", "agen bola", "sbobet", "mix parlay",
        "over under", "handicap bola", "bola online", "pasang bola", "bandar bola",
        "sportsbook", "taruhan online", "prediksi bola", "parlay bola", "voor bola",
        "maxbet", "cmd368", "ubobet",
    ]),
    "deposit": ("Metode deposit / pembayaran", [
        "deposit pulsa", "deposit dana", "deposit ovo", "deposit gopay",
        "deposit linkaja", "deposit qris", "deposit shopeepay", "tanpa potongan",
        "deposit 5000", "deposit 10rb", "deposit via pulsa", "depo pulsa",
        "depo dana", "e-wallet", "bank 24 jam", "deposit termurah", "min depo",
        "deposit bri", "deposit bca", "deposit bni", "deposit mandiri",
    ]),
    "promo": ("Promo / bonus judi", [
        "bonus new member", "bonus deposit", "bonus rollingan", "cashback slot",
        "bonus referral", "welcome bonus", "bonus harian", "freebet", "freespin",
        "garansi kekalahan", "extra bonus", "turnover", "bonus 100", "bonus 200",
        "bonus cashback", "rollingan", "komisi referral", "event slot",
    ]),
    "istilah": ("Istilah situs judi", [
        "situs judi", "judi online", "agen judi", "bandar judi", "judi terpercaya",
        "link alternatif", "daftar sekarang", "login slot", "daftar slot",
        "situs terpercaya", "situs resmi", "bo terpercaya", "bandar terbesar",
        "situs gacor", "agen resmi", "customer service 24 jam", "livechat 24 jam",
        "wla resmi", "situs anti blokir", "link login", "link daftar",
    ]),
    "gacor_slang": ("Slang / kata sandi gambling", [
        "gacor parah", "gacor terus", "auto jp", "auto wd", "wd besar", "jp paus",
        "scatter hitam", "maxwin sensasional", "banjir scatter", "pecah petir",
        "petir merah", "petir x500", "cuan melimpah", "jackpot terbesar",
        "modal receh", "modal kecil", "sekali spin", "spin gratis",
    ]),
}
for key, (label, kws) in THEMES.items():
    judi(f"theme_{key}",
         f"Judi Online - {label} keywords",
         f"Indonesian online-gambling ({label}) terminology observed in injected "
         f"SEO-spam content, dropped file names, or query strings on a compromised asset.",
         kws, level="medium")

# 1c. Provider / game-title brand indicators (specific, low-FP multiword titles).
BRANDS = [
    "pragmatic play", "pg soft", "pgsoft", "habanero", "microgaming", "spadegaming",
    "playtech", "cq9", "joker gaming", "joker123", "playstar", "top trend gaming",
    "gates of olympus", "starlight princess", "sweet bonanza", "sugar rush",
    "wild west gold", "aztec gems", "koi gate", "mahjong ways", "lucky neko",
    "gates of gatot kaca", "wild bounty showdown", "power of thor", "the dog house",
    "great rhino", "bonanza gold", "fortune tiger", "fortune ox", "fortune rabbit",
    "caishen wins", "lucky twins", "treasures of aztec", "ways of qilin",
    "buffalo king", "gem saviour", "candy bonanza", "wisdom of athena",
    "gorilla mania", "queen of bounty", "mahjong wins", "dreams of macau",
    "rise of apollo", "hip hop panda", "ganesha fortune", "medusa hunter",
    # extended catalogue of well-known slot titles (public game names)
    "gates of olympus 1000", "starlight princess 1000", "sweet bonanza 1000",
    "sweet bonanza xmas", "big bass bonanza", "big bass splash", "bigger bass bonanza",
    "wild west duels", "twilight princess", "cash patrol", "wild wild riches",
    "wolf gold", "john hunter", "tomb of the scarab queen", "eye of cleopatra",
    "5 lions megaways", "5 lions gold", "3 kingdoms", "midas fortune",
    "phoenix rises", "juicy fruits", "release the kraken", "the great chicken escape",
    "chicken drop", "cheeky emperor", "gems bonanza", "santa's great gifts",
    "power of merlin", "raging bull", "pinata wins", "diamond strike",
    "wild gladiators", "spirit of adventure", "aztec bonanza", "wild pixies",
    "hot to burn", "wild hot chilli reels", "888 dragons", "888 gold",
    "triple tigers", "master joker", "vampires vs wolves", "day of dead",
    "peking luck", "great reef", "hercules and pegasus", "colossal cash zone",
    "queen of gods", "book of tut", "book of fallen", "book of the dead",
    "legend of perseus", "clover gold", "leprechaun riches", "dragon hatch",
    "dragon hatch 2", "wild bandito", "wild fireworks", "wild coaster",
    "captain's bounty", "prosperity fortune tree", "cai shen 888", "jungle delight",
    "leprechaun riches", "queen of bounty", "bikini paradise", "fortune gods",
    "muay thai champion", "shaolin soccer", "circus delight", "wild ape",
    "bali vacation", "emoji riches", "phoenix rises", "vampires castle",
    "opera dynasty", "medusa 2", "flirting scholar", "gem saviour sword",
    "gem saviour conquest", "tree of fortune", "santa fortune tiger",
    "mahjong ways 2", "mahjong ways 3", "ways of the qilin", "supermarket spree",
    "garuda gems", "ninja vs samurai", "songkran splash", "raider jane",
    "double fortune", "hood vs wolf", "mermaid riches", "genie's 3 wishes",
    "guardians of ice and fire", "the queen's banquet", "lucky piggy",
    "diner delights", "geisha's revenge", "buffalo win", "fortune dragon",
    "wild card football", "candy burst", "totem wonders", "asgardian rising",
    "dreams of macau", "queen bee", "cocktail nights", "spirited wonders",
]
for b in sorted(set(BRANDS)):
    judi(f"brand_{slug(b)}",
         f"Judi Online - Slot title/provider '{b}'",
         f"Reference to gambling slot title/provider '{b}'. Presence in a legitimate "
         f"asset's content or file names indicates SEO-spam / gambling content injection.",
         [b], level="medium")

# 1d. Site-brand tokens (gambling stem + numeric/vip suffix). These digit-suffixed
# brand tokens are specific enough to be low-FP IOCs and are exactly the kind of
# site names SOC teams block. One rule per distinct token.
STEMS = [
    "slot", "gacor", "hoki", "cuan", "mpo", "dewa", "raja", "king", "zeus",
    "sultan", "naga", "garuda", "jitu", "toto", "bola", "mega", "agen", "bandar",
    "royal", "koi", "panen", "gaspol", "sikat", "mantul", "olympus", "win",
    "jp", "pesona", "luxury", "asia",
]
SUFFIXES = ["88", "77", "99", "777", "303", "138", "168", "4d", "vip",
            "100", "888", "gacor", "vip88", "indo"]
SITE_BRANDS = []
for st in STEMS:
    for sf in SUFFIXES:
        SITE_BRANDS.append(st + sf)
for tok in SITE_BRANDS:
    judi(f"site_{slug(tok)}",
         f"Judi Online - Gambling site brand token '{tok}'",
         f"Gambling site-brand token '{tok}' (gambling stem + numeric suffix). Appearing "
         f"in page content, links, or dropped file names points to gambling-site "
         f"branding injected into a compromised asset.",
         [tok], level="medium")


# ══════════════════════════════════════════════════════════════════════════════
#  2) WEB DEFACE  (defacement markers + webshell file drops)
# ══════════════════════════════════════════════════════════════════════════════
DEFACE_LOG = {"category": "web"}
WEB_FILE_LOG = {"product": "linux", "category": "file_event"}

# 2a. Defacement banner / marker strings (keyword, matches web-log + file path).
DEFACE_MARKERS = [
    "hacked by", "defaced by", "owned by", "pwned by", "0wned by", "h4cked by",
    "your security is low", "your site has been hacked", "system hacked",
    "this site has been hacked", "greetz to", "greetzz", "we are anonymous",
    "we are legion", "expect us", "stamp of", "touched by", "patched by",
    "security breached", "admin sleeping", "no system is safe", "your website is vulnerable",
    "mass deface", "index of hacker", "cyber team", "cyber army", "hacktivist",
    "fuck your system", "get rekt", "rip website", "gg wp admin", "notpwned",
    "tim jancok", "ganteng", "maaf pak admin", "situs anda diretas", "keamanan lemah",
    "sudah diretas", "berhasil diretas", "web anda kena hack", "jebol",
]
for i, m in enumerate(DEFACE_MARKERS):
    emit("deface", f"deface_marker_{slug(m)}_{i}",
         f"Web Defacement Marker - '{m}'",
         f"Classic web-defacement banner text '{m}' found in a page body, response, "
         f"or a modified web file - a strong signal the asset was defaced.",
         "high", ["attack.t1491", "attack.impact"],
         keyword_detection([m]), DEFACE_LOG)

# 2b. Webshell file names (file.path endswith) - drop = T1505.003.
WEBSHELLS = [
    "c99.php", "r57.php", "c100.php", "wso.php", "b374k.php", "b374k.php.php",
    "alfa.php", "alfashell.php", "alfa-rex.php", "indoxploit.php", "idx.php",
    "marijuana.php", "mini.php", "minishell.php", "shell.php", "shell.php5",
    "shell.phtml", "sh3ll.php", "up.php", "upload.php.jpg", "gel4y.php",
    "gecko.php", "priv8.php", "p0wny.php", "p0wny-shell.php", "andela.php",
    "dhanush.php", "byp.php", "bypass.php", "0byt3m1n1.php", "wso2.php",
    "wsoshell.php", "cmd.php", "cmd.aspx", "cmd.jsp", "webadmin.php",
    "adminer.php", "config.php.bak", "1n73ction.php", "x.php", "xx.php",
    "z.php", "zone-h.php", "leaf.php", "leafmailer.php", "madspot.php",
    "smevk.php", "b4rt.php", "obfuscated.php", "eval.php", "assert.php",
    "wp-config.php", "wp-login.php.php", "radmin.php", "sadrazam.php",
    "tesla.php", "pouya.php", "k2ll33d.php", "priv-shell.php", "angel.php",
    "cyberdog.php", "goon.php", "vuln.php", "backdoor.php", "b374k-mini.php",
    "conf.php.suspected", "system.php.suspected",
]
for w in WEBSHELLS:
    emit("deface", f"webshell_file_{slug(w)}",
         f"Webshell File Drop - {w}",
         f"A file matching a known webshell name ('{w}') was created or modified under a "
         f"monitored web root - a backdoor for remote command execution.",
         "high", ["attack.t1505.003", "attack.persistence"],
         path_detection([w], ["file_created", "file_modified"], modifier="endswith"),
         WEB_FILE_LOG)

# 2c. Suspicious dropped-file patterns (double extension / masqueraded uploads).
SUS_EXT = [
    ".php.jpg", ".php.png", ".php.gif", ".php.jpeg", ".phtml.jpg", ".asp;.jpg",
    ".php%00.jpg", ".php.", ".php5.jpg", ".jsp.jpg", ".php.bak", ".php.suspected",
    ".php.rogue", ".pht.jpg", ".phar.jpg", ".shtml.jpg", ".php.txt",
]
for e in SUS_EXT:
    emit("deface", f"webshell_dblext_{slug(e)}",
         f"Suspicious Double-Extension Upload - {e}",
         f"A file whose name contains the masquerading double-extension pattern '{e}', a "
         f"common trick to smuggle executable server code past an upload filter.",
         "high", ["attack.t1036.007", "attack.defense_evasion"],
         path_detection([e], ["file_created", "file_modified"], modifier="contains"),
         WEB_FILE_LOG)


# ══════════════════════════════════════════════════════════════════════════════
#  3) FIM  (File Integrity Monitoring on sensitive paths)
# ══════════════════════════════════════════════════════════════════════════════
FIM_LINUX_LOG = {"product": "linux", "category": "file_event"}
FIM_WIN_LOG = {"product": "windows", "category": "file_event"}

# (path substring, human label, level, [actions])  -- actions omitted => modified/deleted
CHG = ["file_modified", "file_deleted"]
DROP = ["file_created", "file_modified", "file_deleted"]

FIM_LINUX = [
    ("/etc/passwd", "user database", "high", CHG),
    ("/etc/shadow", "password hashes", "critical", CHG),
    ("/etc/gshadow", "group shadow", "high", CHG),
    ("/etc/group", "group database", "medium", CHG),
    ("/etc/sudoers", "sudoers policy", "critical", CHG),
    ("/etc/sudoers.d/", "sudoers drop-in", "critical", DROP),
    ("/etc/ssh/sshd_config", "sshd config", "high", CHG),
    ("/root/.ssh/authorized_keys", "root authorized_keys", "critical", DROP),
    ("/.ssh/authorized_keys", "authorized_keys", "high", DROP),
    ("/etc/ssh/", "ssh host keys/config", "high", CHG),
    ("/etc/crontab", "system crontab", "high", CHG),
    ("/etc/cron.d/", "cron.d job", "high", DROP),
    ("/etc/cron.daily/", "cron.daily job", "high", DROP),
    ("/etc/cron.hourly/", "cron.hourly job", "high", DROP),
    ("/etc/cron.weekly/", "cron.weekly job", "medium", DROP),
    ("/etc/cron.monthly/", "cron.monthly job", "medium", DROP),
    ("/var/spool/cron/", "user crontab spool", "high", DROP),
    ("/etc/at.allow", "at allow", "medium", CHG),
    ("/etc/systemd/system/", "systemd unit", "high", DROP),
    ("/lib/systemd/system/", "systemd lib unit", "high", DROP),
    ("/etc/init.d/", "init.d script", "high", DROP),
    ("/etc/rc.local", "rc.local", "high", CHG),
    ("/etc/ld.so.preload", "ld.so.preload (rootkit vector)", "critical", DROP),
    ("/etc/ld.so.conf", "ld.so.conf", "high", CHG),
    ("/etc/pam.d/", "PAM config", "critical", CHG),
    ("/etc/nsswitch.conf", "nsswitch", "high", CHG),
    ("/etc/hosts", "hosts file", "medium", CHG),
    ("/etc/hosts.allow", "hosts.allow", "medium", CHG),
    ("/etc/hosts.deny", "hosts.deny", "medium", CHG),
    ("/etc/resolv.conf", "DNS resolver", "medium", CHG),
    ("/etc/profile", "login profile", "medium", CHG),
    ("/etc/profile.d/", "profile.d script", "medium", DROP),
    ("/etc/bash.bashrc", "system bashrc", "medium", CHG),
    ("/etc/environment", "environment", "medium", CHG),
    ("/etc/motd", "message of the day", "low", CHG),
    ("/etc/issue", "issue banner", "low", CHG),
    ("/etc/modules", "kernel modules list", "high", CHG),
    ("/etc/modprobe.d/", "modprobe config", "high", DROP),
    ("/boot/", "boot files", "high", CHG),
    ("/etc/fstab", "filesystem table", "medium", CHG),
    ("/etc/selinux/config", "SELinux config", "high", CHG),
    ("/etc/apparmor.d/", "AppArmor profile", "high", CHG),
    ("/etc/audit/", "auditd rules", "high", CHG),
    ("/etc/rsyslog.conf", "rsyslog config", "high", CHG),
    ("/etc/rsyslog.d/", "rsyslog drop-in", "medium", DROP),
    ("/etc/logrotate.conf", "logrotate config", "medium", CHG),
    ("/etc/login.defs", "login.defs", "medium", CHG),
    ("/etc/securetty", "securetty", "medium", CHG),
    ("/etc/shells", "valid shells", "medium", CHG),
    ("/etc/anacrontab", "anacrontab", "medium", CHG),
    ("/etc/xinetd.d/", "xinetd service", "high", DROP),
    ("/etc/network/interfaces", "network interfaces", "medium", CHG),
    ("/etc/netplan/", "netplan config", "medium", CHG),
    ("/etc/iptables/", "iptables rules", "high", CHG),
    ("/etc/nftables.conf", "nftables rules", "high", CHG),
    ("/etc/default/grub", "grub defaults", "medium", CHG),
    ("/etc/ca-certificates.conf", "CA certificates", "high", CHG),
    ("/usr/local/share/ca-certificates/", "local CA store", "high", DROP),
    ("/etc/ssl/certs/", "SSL certs", "high", CHG),
    ("/etc/ssl/private/", "SSL private keys", "critical", CHG),
    ("/etc/kubernetes/", "kubernetes config", "high", CHG),
    ("/root/.kube/config", "kubeconfig", "high", CHG),
    ("/etc/docker/daemon.json", "docker daemon config", "high", CHG),
    ("/var/run/docker.sock", "docker socket", "critical", DROP),
    ("/etc/nginx/nginx.conf", "nginx config", "high", CHG),
    ("/etc/nginx/sites-enabled/", "nginx vhost", "high", DROP),
    ("/etc/apache2/apache2.conf", "apache config", "high", CHG),
    ("/etc/apache2/sites-enabled/", "apache vhost", "high", DROP),
    ("/etc/httpd/conf/httpd.conf", "httpd config", "high", CHG),
    ("/etc/php/", "php config", "medium", CHG),
    ("/etc/php.ini", "php.ini", "medium", CHG),
    ("/etc/mysql/", "mysql config", "medium", CHG),
    ("/etc/postgresql/", "postgresql config", "medium", CHG),
    ("/etc/redis/redis.conf", "redis config", "medium", CHG),
    ("/etc/supervisor/", "supervisor config", "medium", DROP),
    ("/root/.bashrc", "root bashrc", "high", CHG),
    ("/root/.bash_profile", "root bash_profile", "high", CHG),
    ("/root/.profile", "root profile", "high", CHG),
    ("/root/.bash_history", "root bash_history", "medium", CHG),
    ("/etc/passwd-", "passwd backup", "high", CHG),
    ("/etc/shadow-", "shadow backup", "critical", CHG),
    ("/usr/bin/", "system binary dir", "high", CHG),
    ("/usr/sbin/", "system sbin dir", "high", CHG),
    ("/bin/", "core binary dir", "high", CHG),
    ("/sbin/", "core sbin dir", "high", CHG),
    ("/usr/local/bin/", "local binary dir", "medium", DROP),
    ("/etc/update-motd.d/", "dynamic motd script", "high", DROP),
    ("/etc/skel/", "new-user skeleton", "medium", DROP),
    ("/etc/subuid", "subuid map", "medium", CHG),
    ("/etc/subgid", "subgid map", "medium", CHG),
    ("/etc/machine-id", "machine-id", "medium", CHG),
    ("/etc/timezone", "timezone", "low", CHG),
    ("/etc/wpa_supplicant/", "wifi credentials", "high", CHG),
    ("/etc/openvpn/", "openvpn config", "high", CHG),
    ("/etc/wireguard/", "wireguard config", "high", CHG),
    ("/etc/samba/smb.conf", "samba config", "medium", CHG),
    ("/etc/exports", "NFS exports", "high", CHG),
    ("/etc/vsftpd.conf", "vsftpd config", "medium", CHG),
    ("/etc/proftpd/", "proftpd config", "medium", CHG),
    ("/etc/dovecot/", "dovecot config", "medium", CHG),
    ("/etc/postfix/", "postfix config", "medium", CHG),
    ("/etc/fail2ban/", "fail2ban config", "medium", CHG),
    ("/etc/knockd.conf", "port-knock config", "high", CHG),
    ("/etc/polkit-1/", "polkit rules", "high", DROP),
    ("/etc/dbus-1/", "dbus policy", "medium", DROP),
    ("/etc/udev/rules.d/", "udev rules", "high", DROP),
    ("/etc/sysctl.conf", "sysctl config", "medium", CHG),
    ("/etc/sysctl.d/", "sysctl drop-in", "medium", DROP),
]
for path, label, lvl, acts in FIM_LINUX:
    emit("fim", f"fim_lin_{slug(path)}",
         f"FIM - {label} ({path})",
         f"Integrity change on {label} ({path}). Modification/creation/deletion here "
         f"often indicates tampering, backdooring, or track-covering.",
         lvl, ["attack.t1565.001", "attack.impact"],
         path_detection([path], acts, modifier="contains"), FIM_LINUX_LOG)

FIM_WIN = [
    ("\\Windows\\System32\\drivers\\etc\\hosts", "hosts file", "medium", CHG),
    ("\\Windows\\System32\\config\\SAM", "SAM hive", "critical", CHG),
    ("\\Windows\\System32\\config\\SYSTEM", "SYSTEM hive", "high", CHG),
    ("\\Windows\\System32\\config\\SECURITY", "SECURITY hive", "high", CHG),
    ("\\Windows\\System32\\Tasks\\", "scheduled task", "high", DROP),
    ("\\Windows\\Tasks\\", "AT task", "high", DROP),
    ("\\Start Menu\\Programs\\Startup\\", "Startup folder", "high", DROP),
    ("\\Windows\\System32\\GroupPolicy\\", "Group Policy", "high", CHG),
    ("\\Windows\\System32\\drivers\\", "kernel driver", "high", DROP),
    ("\\Windows\\SysWOW64\\", "SysWOW64 binary", "high", DROP),
    ("\\Windows\\System32\\wbem\\", "WMI repository", "high", CHG),
    ("\\Windows\\System32\\lsass.exe", "LSASS binary", "critical", CHG),
    ("\\Windows\\System32\\winlogon.exe", "winlogon binary", "critical", CHG),
    ("\\Windows\\System32\\svchost.exe", "svchost binary", "critical", CHG),
    ("\\Windows\\System32\\cmd.exe", "cmd binary", "high", CHG),
    ("\\Windows\\System32\\sethc.exe", "sticky-keys binary", "high", CHG),
    ("\\Windows\\System32\\utilman.exe", "utilman binary", "high", CHG),
    ("\\Windows\\System32\\Osk.exe", "on-screen keyboard binary", "high", CHG),
    ("\\Windows\\System32\\Magnify.exe", "magnifier binary", "high", CHG),
    ("\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\", "common Startup", "high", DROP),
    ("\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\", "user Startup", "high", DROP),
    ("\\Windows\\System32\\drivers\\etc\\lmhosts", "lmhosts", "medium", CHG),
    ("\\Windows\\win.ini", "win.ini", "medium", CHG),
    ("\\Windows\\system.ini", "system.ini", "medium", CHG),
    ("\\Windows\\System32\\ntdll.dll", "ntdll", "high", CHG),
    ("\\Windows\\System32\\kernel32.dll", "kernel32", "high", CHG),
    ("\\inetpub\\wwwroot\\", "IIS web root", "high", DROP),
    ("\\Windows\\System32\\inetsrv\\", "IIS binaries", "high", CHG),
    ("\\Windows\\System32\\spool\\drivers\\", "print spooler drivers", "high", DROP),
    ("\\Users\\Public\\", "public user folder", "medium", DROP),
]
for path, label, lvl, acts in FIM_WIN:
    emit("fim", f"fim_win_{slug(path)}",
         f"FIM (Windows) - {label}",
         f"Integrity change on a sensitive Windows path ({label}: ...{path}). "
         f"Tampering here is associated with persistence, credential theft, or evasion.",
         lvl, ["attack.t1565.001", "attack.impact"],
         path_detection([path], acts, modifier="contains"), FIM_WIN_LOG)

# 3c. Web-root integrity: core files + PHP dropped into upload dirs.
FIM_WEB = [
    ("/var/www/", "web root", "high", DROP),
    ("/var/www/html/index.php", "index.php", "high", CHG),
    ("/var/www/html/index.html", "index.html", "high", CHG),
    ("/var/www/html/.htaccess", ".htaccess", "high", CHG),
    ("/wp-config.php", "wp-config.php", "high", CHG),
    ("/wp-content/uploads/", "WordPress uploads", "high", DROP),
    ("/wp-content/plugins/", "WordPress plugins", "medium", DROP),
    ("/wp-content/themes/", "WordPress themes", "medium", DROP),
    ("/wp-includes/", "WordPress core includes", "high", DROP),
    ("/administrator/", "Joomla admin", "medium", DROP),
    ("/configuration.php", "Joomla config", "high", CHG),
    ("/sites/default/settings.php", "Drupal settings", "high", CHG),
    ("/app/etc/env.php", "Magento env", "high", CHG),
    ("/robots.txt", "robots.txt", "low", CHG),
    ("/sitemap.xml", "sitemap.xml", "low", CHG),
    ("/.env", "dotenv secrets", "high", CHG),
    ("/vendor/", "composer vendor dir", "medium", DROP),
    ("/public/", "public web dir", "medium", DROP),
    ("/uploads/", "generic upload dir", "high", DROP),
    ("/images/", "images dir (php drop)", "medium", DROP),
]
for path, label, lvl, acts in FIM_WEB:
    emit("fim", f"fim_web_{slug(path)}",
         f"FIM (Web) - {label} ({path})",
         f"Integrity change under the web application tree ({label}: {path}). Watch for "
         f"webshell drops in upload dirs and tampering of core app files.",
         lvl, ["attack.t1565.001", "attack.persistence"],
         path_detection([path], acts, modifier="contains"), FIM_LINUX_LOG)


# ══════════════════════════════════════════════════════════════════════════════
#  4) ENDPOINT  (suspicious process / command-line activity)
# ══════════════════════════════════════════════════════════════════════════════
PROC_LOG_LIN = {"product": "linux", "category": "process_creation"}
PROC_LOG_WIN = {"product": "windows", "category": "process_creation"}


def endpoint(name, title, desc, patterns, level, tags, win=False):
    emit("endpoint", "ep_" + name, title, desc, level, tags,
         cmd_detection(patterns), PROC_LOG_WIN if win else PROC_LOG_LIN)


# 4a. Reverse shells (one rule per technique/interpreter).
REVSHELL = [
    ("bash_devtcp", "bash /dev/tcp reverse shell",
     ["/dev/tcp/", "/dev/udp/"], "attack.t1059.004"),
    ("bash_i", "bash -i interactive shell to socket",
     ["bash -i >& ", "bash -i 2>&1", "sh -i >& "], "attack.t1059.004"),
    ("nc_exec", "netcat reverse shell (-e / -c)",
     ["nc -e ", "nc -c ", "ncat -e ", "nc.traditional -e ", "netcat -e "], "attack.t1059.004"),
    ("nc_mkfifo", "netcat mkfifo reverse shell",
     ["mkfifo /tmp/", "mknod /tmp/backpipe", "|nc ", "| nc "], "attack.t1059.004"),
    ("socat", "socat reverse shell",
     ["socat exec:", "socat tcp-connect:", "socat openssl:"], "attack.t1059.004"),
    ("python_socket", "python reverse shell",
     ["import socket", "socket.socket(socket.af_inet", "pty.spawn", "os.dup2"], "attack.t1059.006"),
    ("perl_socket", "perl reverse shell",
     ["perl -e", "use socket;", "socket(s,pf_inet"], "attack.t1059.004"),
    ("php_socket", "php reverse shell",
     ["php -r", "fsockopen(", "proc_open(", "shell_exec("], "attack.t1059"),
    ("ruby_socket", "ruby reverse shell",
     ["ruby -rsocket", "tcpsocket.open"], "attack.t1059.004"),
    ("lua_socket", "lua reverse shell",
     ["lua -e", "require('socket')"], "attack.t1059"),
    ("awk_socket", "awk reverse shell",
     ["/inet/tcp/0/", "gawk -v"], "attack.t1059.004"),
    ("openssl_revshell", "openssl encrypted reverse shell",
     ["openssl s_client -connect", "openssl s_client -quiet"], "attack.t1059.004"),
    ("telnet_revshell", "telnet reverse shell",
     ["telnet ", "mkfifo backpipe"], "attack.t1059.004"),
    ("powershell_revshell", "powershell reverse shell",
     ["new-object system.net.sockets.tcpclient", "$client.getstream()"], "attack.t1059.001"),
]
for n, title, pats, tech in REVSHELL:
    endpoint(f"revshell_{n}", f"Reverse Shell - {title}",
             f"Command line consistent with a {title}. Reverse shells give an attacker "
             f"interactive remote control of the host.", pats, "high",
             [tech, "attack.execution"], win=("powershell" in n))

# 4b. Download-and-execute / staging.
STAGING = [
    ("curl_pipe_sh", "curl | sh download-and-run",
     ["curl -s http", "curl http", "|sh", "| sh", "|bash", "| bash"], "attack.t1105"),
    ("wget_pipe_sh", "wget | sh download-and-run",
     ["wget -q -o- http", "wget -o- http", "wget http", "wget -qo-"], "attack.t1105"),
    ("base64_decode_pipe", "base64-decoded piped to shell",
     ["base64 -d", "base64 --decode", "|base64 -d|sh", "openssl base64 -d"], "attack.t1140"),
    ("chmod_tmp_exec", "chmod +x on a dropped payload",
     ["chmod +x /tmp/", "chmod 777 /tmp/", "chmod +x /dev/shm/", "chmod +x /var/tmp/"], "attack.t1222"),
    ("tmp_exec", "execution from world-writable dir",
     ["/tmp/./", "/dev/shm/", "/var/tmp/.", "./tmp/"], "attack.t1059"),
    ("python_c_download", "python -c inline download",
     ["python -c", "python3 -c", "urllib.request.urlopen", "urllib.urlretrieve"], "attack.t1059.006"),
    ("nohup_setsid", "detached background execution",
     ["nohup ", "setsid ", "disown", "& disown"], "attack.t1059.004"),
]
for n, title, pats, tech in STAGING:
    endpoint(f"stage_{n}", f"Payload Staging - {title}",
             f"Command line consistent with {title} - typical of malware/tooling "
             f"download and execution.", pats, "high", [tech, "attack.command_and_control"])

# 4c. Windows LOLBins.
LOLBIN_WIN = [
    ("certutil_download", "certutil download / decode",
     ["certutil -urlcache", "certutil -f -urlcache", "certutil -decode", "certutil.exe -urlcache"], "attack.t1105"),
    ("bitsadmin", "bitsadmin transfer",
     ["bitsadmin /transfer", "bitsadmin /create", "bitsadmin /addfile"], "attack.t1197"),
    ("mshta_http", "mshta remote scriptlet",
     ["mshta http", "mshta.exe http", "mshta vbscript:", "mshta javascript:"], "attack.t1218.005"),
    ("regsvr32_scrobj", "regsvr32 squiblydoo",
     ["regsvr32 /s /n /u /i:http", "regsvr32 /i:http", "scrobj.dll"], "attack.t1218.010"),
    ("rundll32_js", "rundll32 abuse",
     ["rundll32 javascript:", "rundll32.exe javascript:", "rundll32 shell32.dll,", "rundll32 url.dll,"], "attack.t1218.011"),
    ("wmic_process_call", "wmic process call create",
     ["wmic process call create", "wmic /node:", "wmic os get"], "attack.t1047"),
    ("powershell_enc", "powershell encoded command",
     ["powershell -enc", "powershell -e ", "-encodedcommand", "powershell -nop -w hidden"], "attack.t1059.001"),
    ("powershell_download", "powershell download cradle",
     ["downloadstring(", "downloadfile(", "invoke-webrequest", "iwr ", "net.webclient", "invoke-expression", "iex("], "attack.t1059.001"),
    ("msbuild_inline", "msbuild inline task",
     ["msbuild ", "msbuild.exe "], "attack.t1127.001"),
    ("installutil", "installutil bypass",
     ["installutil /logfile=", "installutil.exe"], "attack.t1218.004"),
    ("cscript_wscript", "wscript/cscript script exec",
     ["cscript //e:", "wscript ", "cscript.exe", ".vbs", ".js "], "attack.t1059.005"),
    ("esentutl", "esentutl copy (locked file)",
     ["esentutl /y", "esentutl.exe /y", "esentutl /vss"], "attack.t1005"),
    ("vssadmin_delete", "shadow copy deletion",
     ["vssadmin delete shadows", "vssadmin.exe delete", "wmic shadowcopy delete"], "attack.t1490"),
    ("wevtutil_clear", "event log clearing",
     ["wevtutil cl ", "wevtutil.exe cl", "clear-eventlog", "wevtutil el"], "attack.t1070.001"),
    ("bcdedit", "boot config tamper",
     ["bcdedit /set", "bcdedit.exe /set", "recoveryenabled no", "bootstatuspolicy ignoreallfailures"], "attack.t1490"),
    ("schtasks_create", "scheduled task creation",
     ["schtasks /create", "schtasks.exe /create", "/sc onlogon", "/ru system"], "attack.t1053.005"),
    ("sc_create", "service creation",
     ["sc create", "sc.exe create", "sc config", "new-service"], "attack.t1543.003"),
    ("reg_add_run", "registry Run-key persistence",
     ["reg add", "\\currentversion\\run", "\\currentversion\\runonce"], "attack.t1547.001"),
    ("net_user_add", "local account creation",
     ["net user /add", "net localgroup administrators", "net user "], "attack.t1136.001"),
    ("nltest", "domain trust discovery",
     ["nltest /domain_trusts", "nltest /dclist", "nltest.exe"], "attack.t1482"),
    ("whoami_priv", "privilege discovery",
     ["whoami /priv", "whoami /groups", "whoami /all"], "attack.t1033"),
    ("fodhelper_uac", "fodhelper UAC bypass",
     ["fodhelper.exe", "computerdefaults.exe", "\\ms-settings\\shell\\open"], "attack.t1548.002"),
]
for n, title, pats, tech in LOLBIN_WIN:
    endpoint(f"lolbin_{n}", f"Windows LOLBin - {title}",
             f"Command line consistent with {title}, a living-off-the-land technique "
             f"abusing a signed system binary.", pats, "high",
             [tech, "attack.defense_evasion"], win=True)

# 4d. Linux abuse / persistence / evasion.
LOLBIN_LIN = [
    ("crontab_edit", "crontab modification",
     ["crontab -", "crontab -e", "echo * * * *", "(crontab -l"], "attack.t1053.003"),
    ("authorized_keys_append", "authorized_keys injection",
     ["echo ssh-rsa", ">> ~/.ssh/authorized_keys", ">> /root/.ssh/authorized_keys", "authorized_keys"], "attack.t1098.004"),
    ("useradd_backdoor", "backdoor account creation",
     ["useradd ", "adduser ", "usermod -ag sudo", "usermod -ag root"], "attack.t1136.001"),
    ("passwd_change", "password change",
     ["passwd root", "echo root:", "chpasswd", "openssl passwd"], "attack.t1098"),
    ("history_clear", "shell history tampering",
     ["history -c", "unset histfile", "export histfilesize=0", "rm ~/.bash_history", "cat /dev/null > ~/.bash_history"], "attack.t1070.003"),
    ("log_wipe", "log deletion / truncation",
     ["rm -rf /var/log", "> /var/log/", "truncate -s0 /var/log", "shred /var/log"], "attack.t1070.002"),
    ("chattr_immutable", "chattr to hide/lock files",
     ["chattr +i", "chattr -i", "chattr +a"], "attack.t1222.002"),
    ("timestomp", "timestamp tampering",
     ["touch -r ", "touch -t ", "touch -d "], "attack.t1070.006"),
    ("iptables_flush", "firewall flush",
     ["iptables -f", "iptables --flush", "ufw disable", "systemctl stop firewalld"], "attack.t1562.004"),
    ("selinux_disable", "SELinux/AppArmor disable",
     ["setenforce 0", "aa-complain", "systemctl disable apparmor"], "attack.t1562.001"),
    ("preload_rootkit", "ld.so.preload rootkit staging",
     ["/etc/ld.so.preload", "ld_preload=", "export ld_preload"], "attack.t1574.006"),
    ("kmod_load", "kernel module load",
     ["insmod ", "modprobe ", "kldload "], "attack.t1547.006"),
    ("systemd_persist", "systemd service persistence",
     ["systemctl enable", "systemctl daemon-reload", ".service", "systemd-run"], "attack.t1543.002"),
    ("rc_local_persist", "rc.local persistence",
     ["/etc/rc.local", "/etc/init.d/", "update-rc.d"], "attack.t1037.004"),
    ("wget_curl_recon", "tooling fetch",
     ["wget http", "curl -o ", "tftp -g", "scp "], "attack.t1105"),
    ("proc_hide", "process/rootkit hiding",
     ["ld_preload", "libprocesshider", "/proc/", "prctl(pr_set_name"], "attack.t1014"),
    ("miner_flags", "cryptominer indicators",
     ["--donate-level", "stratum+tcp://", "xmrig", "--cpu-priority", "minerd", "nanopool", "cryptonight"], "attack.t1496"),
    ("clear_utmp", "login-record wiping",
     ["> /var/run/utmp", "> /var/log/wtmp", "> /var/log/btmp", "utmpdump"], "attack.t1070"),
]
for n, title, pats, tech in LOLBIN_LIN:
    endpoint(f"linabuse_{n}", f"Linux Abuse - {title}",
             f"Command line consistent with {title} - associated with persistence, "
             f"defense evasion, or impact on Linux hosts.", pats, "high",
             [tech, "attack.defense_evasion"])

# 4e. Credential access.
CREDACCESS = [
    ("read_shadow", "reading /etc/shadow", ["cat /etc/shadow", "cp /etc/shadow", "unshadow"], "attack.t1003.008", "critical", False),
    ("read_passwd", "dumping /etc/passwd", ["cat /etc/passwd", "getent passwd"], "attack.t1003.008", "medium", False),
    ("proc_mem_dump", "reading process memory", ["/proc/self/maps", "gcore ", "dd if=/proc/", "process_vm_readv"], "attack.t1003.007", "high", False),
    ("mimikatz", "mimikatz credential theft", ["sekurlsa::", "mimikatz", "lsadump::", "privilege::debug", "kerberos::"], "attack.t1003.001", "critical", True),
    ("lsass_dump", "LSASS memory dump", ["procdump -ma lsass", "comsvcs.dll, minidump", "rundll32 comsvcs", "-accepteula -ma lsass"], "attack.t1003.001", "critical", True),
    ("reg_save_sam", "SAM/SYSTEM hive export", ["reg save hklm\\sam", "reg save hklm\\system", "reg save hklm\\security"], "attack.t1003.002", "critical", True),
    ("ntds_dump", "NTDS.dit extraction", ["ntdsutil", "ntds.dit", "ac i ntds", "create full"], "attack.t1003.003", "critical", True),
    ("keyring_ssh", "SSH/GPG key harvesting", ["find / -name id_rsa", "cat ~/.ssh/id_rsa", "gpg --export-secret-keys", ".ssh/id_ed25519"], "attack.t1552.004", "high", False),
    ("cloud_creds", "cloud credential file access", ["~/.aws/credentials", ".config/gcloud", "~/.azure/", "kubeconfig"], "attack.t1552.001", "high", False),
    ("browser_creds", "browser credential store access", ["login data", "cookies.sqlite", "logins.json", "key4.db"], "attack.t1555.003", "high", False),
]
for n, title, pats, tech, lvl, win in CREDACCESS:
    endpoint(f"cred_{n}", f"Credential Access - {title}",
             f"Command line consistent with {title}.", pats, lvl,
             [tech, "attack.credential_access"], win=win)

# 4f. Discovery / recon.
DISCOVERY = [
    ("host_enum", "host / OS enumeration", ["uname -a", "hostnamectl", "cat /etc/os-release", "lscpu"], "attack.t1082", "low", False),
    ("user_enum", "account enumeration", ["id ", "whoami", "who ", "w ", "last ", "lastlog"], "attack.t1087.001", "low", False),
    ("net_enum", "network configuration discovery", ["ifconfig -a", "ip addr", "ip a", "netstat -antp", "ss -tulpn", "arp -a"], "attack.t1016", "low", False),
    ("proc_enum", "process discovery", ["ps aux", "ps -ef", "top -b", "tasklist"], "attack.t1057", "low", False),
    ("sudo_enum", "sudo capability discovery", ["sudo -l", "sudo -ll"], "attack.t1033", "medium", False),
    ("scan_nmap", "network scanning tool", ["nmap ", "masscan ", "zmap ", "-p- ", "-sc -sv"], "attack.t1046", "medium", False),
    ("net_view_win", "Windows domain discovery", ["net view", "net group \"domain admins\"", "net accounts", "arp -a"], "attack.t1018", "medium", True),
    ("systeminfo_win", "Windows system discovery", ["systeminfo", "wmic qfe", "driverquery", "set "], "attack.t1082", "low", True),
    ("suid_search", "SUID/privilege-escalation search", ["find / -perm -4000", "find / -perm -u=s", "-perm -2000"], "attack.t1083", "medium", False),
    ("cred_search_fs", "filesystem secret grep", ["grep -r password", "grep -ri passwd", "grep -r api_key", "grep -r secret"], "attack.t1552.001", "medium", False),
]
for n, title, pats, tech, lvl, win in DISCOVERY:
    endpoint(f"disc_{n}", f"Discovery - {title}",
             f"Command line consistent with {title} - typical post-exploitation reconnaissance.",
             pats, lvl, [tech, "attack.discovery"], win=win)

# 4g. Privilege escalation.
PRIVESC = [
    ("pkexec", "pkexec / PwnKit", ["pkexec", "gconv-modules", "cve-2021-4034"], "attack.t1548.001", "high", False),
    ("dirtypipe", "Dirty Pipe / DirtyCow", ["dirtypipe", "dirtycow", "cve-2022-0847", "cve-2016-5195"], "attack.t1068", "high", False),
    ("setuid_bash", "setuid shell staging", ["chmod u+s /bin/bash", "chmod 4755", "cp /bin/bash /tmp"], "attack.t1548.001", "high", False),
    ("sudo_exploit", "sudo baron samedit", ["cve-2021-3156", "sudoedit -s", "baron samedit"], "attack.t1068", "high", False),
    ("polkit_dbus", "polkit dbus abuse", ["dbus-send", "org.freedesktop.policykit", "createuser"], "attack.t1548", "medium", False),
    ("token_priv_win", "Windows token/privilege abuse", ["seimpersonateprivilege", "juicypotato", "printspoofer", "roguepotato"], "attack.t1134.001", "high", True),
    ("uac_bypass_win", "Windows UAC bypass", ["eventvwr.exe", "sdclt.exe", "slui.exe", "\\shell\\open\\command"], "attack.t1548.002", "high", True),
]
for n, title, pats, tech, lvl, win in PRIVESC:
    endpoint(f"privesc_{n}", f"Privilege Escalation - {title}",
             f"Command line consistent with {title}.", pats, lvl,
             [tech, "attack.privilege_escalation"], win=win)

# 4h. Webshell command execution (PHP OS-command sinks in a command line).
endpoint("webshell_php_system", "Webshell - PHP command execution functions",
         "A command line containing PHP command-execution sinks (system/exec/passthru/"
         "shell_exec/popen) - typical of a webshell running OS commands.",
         ["system(", "passthru(", "shell_exec(", "popen(", "proc_open(", "exec(", "assert(", "eval(base64"],
         "high", ["attack.t1505.003", "attack.execution"])


# ══════════════════════════════════════════════════════════════════════════════
#  5) AGGREGATION (SQL-path) rules
# ══════════════════════════════════════════════════════════════════════════════
def agg_rule(name, title, desc, selection_lines, cond, level, tags, logsource, timeframe="5m"):
    d = os.path.join(RULES, "agg")
    os.makedirs(d, exist_ok=True)
    ls = "\n".join(f"  {k}: {v}" for k, v in logsource.items())
    tg = "\n".join(f"  - {t}" for t in tags)
    body = f"""title: {title}
id: {rid('agg/' + name)}
status: experimental
description: >
  {desc}
references:
  - https://attack.mitre.org/techniques/T1110/
author: DeusWatch (generated)
level: {level}
logsource:
{ls}
detection:
{selection_lines}
  timeframe: {timeframe}
  condition: {cond}
tags:
{tg}
"""
    path = os.path.join(d, name + ".yml")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    files_written.append(path)


AGG = [
    ("auth_fail_by_ip", "Authentication Failures Burst by Source IP",
     "Many failed authentications from one source IP in a short window - credential "
     "stuffing / brute force.",
     "  selection:\n    event.category: authentication\n    event.outcome: failure",
     "selection | count() by source.ip > 20", "high",
     ["attack.t1110", "attack.credential_access"], {"category": "authentication"}, "5m"),
    ("auth_fail_by_user", "Authentication Failures Burst by User",
     "Many failed authentications against a single account - targeted password guessing.",
     "  selection:\n    event.category: authentication\n    event.outcome: failure",
     "selection | count() by user.name > 15", "high",
     ["attack.t1110.003", "attack.credential_access"], {"category": "authentication"}, "5m"),
    ("fim_change_burst", "Mass File Integrity Changes by Host",
     "A burst of file changes on one host - ransomware, mass defacement, or a deploy "
     "gone wrong.",
     "  selection:\n    event.category: file",
     "selection | count() by host.name > 100", "high",
     ["attack.t1486", "attack.impact"], {"category": "file_event"}, "5m"),
    ("web_flood_by_ip", "High Request Volume by Source IP (web)",
     "A single source IP generating an unusually high request volume - scanning, "
     "scraping, or a layer-7 flood.",
     "  selection:\n    event.category: web",
     "selection | count() by source.ip > 300", "medium",
     ["attack.t1595", "attack.reconnaissance"], {"category": "web"}, "1m"),
    ("firewall_block_burst", "Firewall Block Burst by Source IP",
     "Many firewall drops from one source IP - port scan / network probe.",
     "  selection:\n    event.action: firewall_block",
     "selection | count() by source.ip > 30", "high",
     ["attack.t1046", "attack.discovery"], {"category": "firewall"}, "1m"),
    ("sudo_fail_by_user", "Sudo Failures by User",
     "Repeated sudo authentication failures for one user - privilege-escalation attempts.",
     "  selection:\n    event.category: authentication\n    event.action: sudo",
     "selection | count() by user.name > 10", "medium",
     ["attack.t1548.003", "attack.privilege_escalation"], {"category": "authentication"}, "10m"),
]
for name, title, desc, sel, cond, lvl, tags, ls, tf in AGG:
    agg_rule(name, title, desc, sel, cond, lvl, tags, ls, tf)


# ── report ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"Generated {len(files_written)} rule files under {RULES}")
    counts = {}
    for p in files_written:
        sub = os.path.basename(os.path.dirname(p))
        counts[sub] = counts.get(sub, 0) + 1
    for k in sorted(counts):
        print(f"  {k:10s} {counts[k]}")
