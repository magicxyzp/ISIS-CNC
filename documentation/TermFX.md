ISIS-C&C — TermFX placeholders

Syntax: `<<$key>>`. Optional spaces are allowed, e.g. `<< $user.username >>`.
The server **changes the working directory** to the folder that contains `assets/config.json` (cwd, next to the binary, or a parent) so banner files load and variables resolve even if you start the exe from elsewhere.

Window title, `spinner.txt`, and `<<$title.*>>` tokens
------------------------------------------------------
The SSH **window title** is built from `assets/banners/{theme}/branding/title.txt` (TermFX).

**Spinner animation** (`<<$title.spinner>>` in `title.txt` only — panels get an empty spinner):
- Edit **`assets/banners/{theme}/branding/spinner.txt`** (falls back to theme `default` if missing).
- **Two or more** non-empty, non-`#` lines → **each line** is one frame (spaces allowed, e.g. `ISIS <3` on one line).
- **Exactly one** such line → frames are **words** split on whitespace (e.g. `I IS ISI ISIS ISIS < ISIS<3`).
- If the file is empty/invalid, default frames are `| / - +` (no `\`).

**Timing (`config.json` → `settings.title`):**
- **`spinner_frame_sleep`** — milliseconds between spinner frames (and title refresh). If **`0`**, **`title_update_sleep`** is used instead.
- **`title_update_sleep`** — used when `spinner_frame_sleep` is `0` (default 500 ms).

In **help / plan / prompt** banners, **`<<$title.time>>`**, **`<<$title.date>>`**, **`<<$title.datetime>>`** work (clock at draw time). **`<<$title.spinner>>`** / **`<<$title.fakebots>>`** render **empty** there on purpose.

**If the title never changes (only “SSH” or a static string):** the SSH **client** must allow the server to set the title. Examples: **PuTTY** → *Terminal → Features* → enable **“Set window title”** / allow remote control of title; **Windows Terminal** usually allows OSC from SSH; web SSH consoles often **ignore** titles entirely.

`title.*` tokens in **`title.txt`** (window title):

<<$title.spinner>>   — current frame from `branding/spinner.txt` (see above)
<<$title.fakebots>> — random integer 1000–1200 (title bar only)
<<$title.time>>     — current clock HH:MM:SS
<<$title.datetime>> — 01/02/2006 15:04:05
<<$title.date>>     — same as <<$date>>

**Alternate syntax (matched only for `title.*` keys):** `$title.spinner`, `$title.time`, or `{title.time}` / `{$title.time}` — useful if `<<`/`>>` were mistyped.

**Common typos fixed automatically:** `<<$title.spiiner>>`, `<<$title.spiner>>`, `title.tim`, etc. map to the correct token.

Save `title.txt` as **UTF-8** or **UTF-16** (Notepad “Unicode”). Fullwidth `＜＜$…＞＞` brackets are normalized to ASCII.

You can use **all** base panel tokens below in `title.txt` as well (e.g. <<$online>>, <<$user.username>>).

FiveM Resolver:

<<$cfx.ip>>
<<$cfx.port>>
<<$cfx.code>>
<<$cfx.country>>
<<$cfx.hosting>>
<<$cfx.org>>
<<$cfx.players.current>>
<<$cfx.players.max>>

IP Lookup:

<<$ip.ip>>
<<$ip.region>>
<<$ip.country>>
<<$ip.continent>>
<<$ip.city>>
<<$ip.zip>>
<<$ip.isp>>
<<$ip.asn>>
<<$ip.org>>
<<$ip.timezone>>

Broadcast Banner:

<<$broadcast.message>>
<<$broadcast.sender>>

Attack Sent Banner:

<<$target.host>>
<<$target.port>>
<<$target.duration>>
<<$target.method>>
<<$target.timesent>>

<<$user.ongoing>>
<<$user.concurrents>>
<<$user.maxtime>>
<<$user.username>>

Base TermFX:

<<$skipline>>
<<$clear>>
<<$general.online>>
<<$general.ongoing>>
<<$general.attackcount>>
<<$online>>
<<$ongoing>>
<<$date>>
<<$time>>
<<$datetime>>
<<$user.username>>
<<$user.ongoing>>
<<$user.concurrents>>
<<$user.maxtime>>
<<$user.vip>>
<<$user.reseller>>
<<$user.mod>>
<<$user.admin>>
<<$user.bp_powersaving>>
<<$user.bp_blacklist>>
<<$user.bp_softmaxtime>>
<<$user.api>>

<<$user.expiry.days>>
<<$user.creation.days>>
<<$user.expiry.formatted>>
<<$user.creation.user>>
<<$user.creation.formatted>>
<<$user.attackcount>>

Colours:

reset: [0m
bright: [1m
dim: [2m
underscore: [4m
blink: [5m
reverse: [7m
hidden: [8m
black: [30m
bright black: [90m
background black: [40m
red: [31m
bright red: [91m
background red: [41m
green: [32m
bright green: [92m
background green: [42m
yellow: [33m
bright yellow: [93m
background yellow: [43m
blue: [34m
bright blue: [94m
background blue: [44m
magenta: [35m
bright magenta: [95m
background magenta: [45m
cyan: [36m
bright cyan: [96m
background cyan: [46m
white: [37m
bright white: [97m
background white: [47m
