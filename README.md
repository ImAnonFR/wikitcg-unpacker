# wikitcg-unpacker

Automatically opens your [WikiTCG](https://wiki-tcg.com) boosters so your reserve never caps out.

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/ImAnonFR/wikitcg-unpacker.git
cd wikitcg-unpacker
```

**With uv**

```bash
uv venv
uv pip install -r requirements.txt
source .venv/bin/activate
```

**With pip**

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then add your credentials:

```bash
cp env.example .env
chmod 600 .env
# edit .env: WIKITCG_EMAIL and WIKITCG_PASSWORD
```

## Usage

```bash
# Check that everything works (login + read your reserve). Opens nothing.
python wikitcg_bot.py --dry-run
OR
uv run wikitcg_bot.py --dry-run

# Open every stored booster once, then exit
python wikitcg_bot.py --once
OR
uv run wikitcg_bot.py --once

# Run forever: open everything, sleep until the reserve refills, repeat
python wikitcg_bot.py 
OR 
uv run wikitcg_bot.py 

# Run forever: open every 15min when a pack is available
python wikitcg_bot.py --target 1
OR
uv run wikitcg_bot.py --target 1
```

| Option | Description |
|---|---|
| `--dry-run` | Log in and read the reserve without opening anything |
| `--once` | Open all stored boosters once and exit |
| `--target N` | Wake up when the reserve reaches `N` boosters (1–10, default `8`) |
| `--specials` | Also open the special boosters you own |
| `-v` | Debug logging |

Every opened booster is logged to `pulls.jsonl`.
