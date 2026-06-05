#!/usr/bin/env python3
"""
process_domains.py
==================
Daily monitor for dropped Estonian (.ee) domains.

PIPELINE
--------
  1. Pull the full .ee zone via AXFR (`dig`).
  2. Parse + clean it to a unique set of second-level .ee domains.
  3. Diff against yesterday's snapshot to find DROPPED domains.
  4. Lexical pre-screen (length / digits / hyphens / consonant runs).
  5. Bulk OpenPageRank lookup (batched, 100 domains per request).
  6. POST domains scoring >= 2.5 to the Google Apps Script webhook.
  7. Persist today's snapshot to `active_domains.txt` for tomorrow's diff.

ENVIRONMENT VARIABLES
---------------------
  OPENPAGERANK_API_KEY  - DomCop OpenPageRank API key (sent as header `API-OPR`)
  APPS_SCRIPT_URL       - Google Apps Script `/exec` webhook URL

RUNTIME REQUIREMENTS
--------------------
  - Linux with `dnsutils` installed (provides the `dig` command).
  - Python 3.10+ with the `requests` library.
"""

import os
import re
import sys
import json
import time
import subprocess
from datetime import datetime, timezone

import requests

# --------------------------------------------------------------------------- #
# Configuration constants
# --------------------------------------------------------------------------- #

STATE_FILE = "active_domains.txt"            # local snapshot of yesterday's domains
ZONE_SERVER = "zone.internet.ee"             # Estonian registry AXFR server
ZONE_NAME = "ee."                            # the zone we transfer
AXFR_TIMEOUT = 600                           # seconds to allow the transfer to run
AXFR_RETRIES = 3                             # how many times to attempt the transfer
AXFR_RETRY_DELAY = 15                        # seconds to wait between attempts

OPR_ENDPOINT = "https://openpagerank.com/api/v1.0/getPageRank"
OPR_BATCH_SIZE = 100                         # OpenPageRank caps each call at 100 domains
OPR_SCORE_THRESHOLD = 2.5                    # only domains >= this become "gems"
HTTP_TIMEOUT = 60                            # per-request network timeout (seconds)

# Sanity floor: a healthy .ee zone has well over 100k domains. If the parsed
# list comes back far smaller than this, the transfer almost certainly failed
# (refused / truncated), and we must NOT overwrite the state file -- otherwise
# tomorrow's diff would report the entire registry as "dropped".
MIN_PLAUSIBLE_ZONE_SIZE = 50_000

# Vowel set for the consonant-run filter. Includes the Estonian vowels and
# treats 'y' as a vowel per the specification. Any character NOT in this set
# (consonants AND digits/symbols) counts toward a consonant run.
VOWELS = set("aeiouõäöüy")


# --------------------------------------------------------------------------- #
# Step 1 + 2: Zone transfer download & cleaning
# --------------------------------------------------------------------------- #

def fetch_zone() -> str:
    """Run a full AXFR zone transfer and return the raw text output.

    The Estonian registry permits anonymous AXFR from `zone.internet.ee`.

    Hardening for cloud CI runners (e.g. GitHub Actions):
      * `-4` forces IPv4. GitHub-hosted runners frequently have broken or
        missing IPv6, and without this `dig` may attempt an IPv6 route and
        stall, returning "no reply from server" (exit code 9).
      * `+time=15 +tries=1` keeps each attempt from hanging too long.
      * We retry a few times, because a single transient drop is common and a
        later attempt often succeeds.

    Returns the raw zone text, or "" if every attempt failed.
    """
    cmd = [
        "dig", "-4", "+time=15", "+tries=1",
        f"@{ZONE_SERVER}", ZONE_NAME, "axfr",
    ]

    for attempt in range(1, AXFR_RETRIES + 1):
        print(f"[zone] AXFR attempt {attempt}/{AXFR_RETRIES}: {' '.join(cmd)}")
        result = None
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=AXFR_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            print(f"[zone] attempt {attempt}: timed out after {AXFR_TIMEOUT}s.")

        # Success = clean exit AND we actually received content.
        if result is not None and result.returncode == 0 and result.stdout.strip():
            print(f"[zone] attempt {attempt}: transfer succeeded.")
            return result.stdout

        if result is not None:
            stderr = result.stderr.strip()
            print(
                f"[zone] attempt {attempt}: dig exited {result.returncode}. "
                f"stderr: {stderr!r}"
            )

        if attempt < AXFR_RETRIES:
            print(f"[zone] retrying in {AXFR_RETRY_DELAY}s...")
            time.sleep(AXFR_RETRY_DELAY)

    print("[zone] ERROR: all AXFR attempts failed.")
    return ""


# Matches a zone-file owner token that is EXACTLY a second-level .ee domain,
# i.e. "<label>.ee." with a single label and no sub-labels.
#   - "example.ee."        -> matches, captures "example.ee"
#   - "ee."                -> no match (no label before .ee)
#   - "ns1.example.ee."    -> no match (two labels -> glue/host record)
# The label class [^.\s;]+ forbids dots, whitespace and comment markers.
_SECOND_LEVEL_RE = re.compile(r"^([^.\s;]+\.ee)\.$", re.IGNORECASE)


def parse_zone(raw: str) -> set[str]:
    """Extract a clean, unique set of second-level .ee domain names.

    Every registered domain appears in the parent zone as the OWNER of its NS
    (and possibly DS) records, e.g.::

        example.ee.   3600  IN  NS  ns1.host.com.

    We read the first whitespace-delimited token of each line (the owner name)
    and keep it only if it is a single-label `<label>.ee.`. This naturally
    discards:
      * the SOA / NS / DNSKEY records of the apex `ee.` zone itself,
      * glue / host records such as `ns1.example.ee.` (multi-label owners),
      * comment lines beginning with ';'.

    NOTE ON IDN DOMAINS: Internationalised .ee domains (containing õ/ä/ö/ü)
    are stored in the zone in their punycode form, which always begins with
    "xn--". Because those names contain hyphens, they will later be removed by
    the lexical hyphen filter (Step 3). That is consistent with the spec's
    intent to drop hyphenated names, but it is worth knowing they never reach
    the API stage.
    """
    domains: set[str] = set()
    for line in raw.splitlines():
        if not line or line[0] in (";",):
            continue
        parts = line.split()
        if not parts:
            continue
        match = _SECOND_LEVEL_RE.match(parts[0])
        if match:
            domains.add(match.group(1).lower())
    return domains


# --------------------------------------------------------------------------- #
# Step 2 (cont.): Local state persistence
# --------------------------------------------------------------------------- #

def read_state() -> set[str]:
    """Read yesterday's domain snapshot. Missing file => empty set (first run)."""
    if not os.path.exists(STATE_FILE):
        print(f"[state] '{STATE_FILE}' not found -- treating as first run.")
        return set()
    with open(STATE_FILE, "r", encoding="utf-8") as fh:
        return {line.strip().lower() for line in fh if line.strip()}


def write_state(domains: set[str]) -> None:
    """Overwrite the state file with today's snapshot (sorted for stable diffs)."""
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        for domain in sorted(domains):
            fh.write(domain + "\n")
    print(f"[state] Wrote {len(domains)} domains to '{STATE_FILE}'.")


# --------------------------------------------------------------------------- #
# Step 3: Rigid lexical filtering (pre-screening)
# --------------------------------------------------------------------------- #

def _has_long_consonant_run(label: str, threshold: int = 5) -> bool:
    """True if `label` contains a run of `threshold`+ consecutive consonants.

    Per the spec, vowels (a,e,i,o,u,õ,ä,ö,ü,y) reset the run and ANYTHING
    else -- consonants, digits, stray symbols -- extends it. In practice
    digit-heavy names are already removed by the digit filters below, so this
    behaves as the intended "random consonant gibberish" filter.
    """
    run = 0
    for ch in label:
        if ch in VOWELS:
            run = 0
        else:
            run += 1
            if run >= threshold:
                return True
    return False


def passes_lexical_filter(domain: str) -> bool:
    """Return True if the domain survives all pre-screen rules.

    A domain is ELIMINATED if its label (the part before ".ee") is:
      * longer than 17 characters,
      * purely numeric,
      * contains more than 3 numeric characters,
      * contains any hyphen / dash,
      * contains a run of 5+ consecutive consonants.
    """
    label = domain[:-3] if domain.endswith(".ee") else domain  # strip ".ee"

    if len(label) > 17:
        return False
    if label.isdigit():
        return False
    if sum(ch.isdigit() for ch in label) > 3:
        return False
    if "-" in label:
        return False
    if _has_long_consonant_run(label):
        return False
    return True


# --------------------------------------------------------------------------- #
# Step 4: Bulk OpenPageRank screening
# --------------------------------------------------------------------------- #

def _chunk(seq: list[str], size: int):
    """Yield successive `size`-length chunks from `seq`."""
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def query_openpagerank(candidates: list[str], api_key: str) -> dict[str, float]:
    """Look up OpenPageRank for each candidate, returning {domain: decimal_score}.

    Requests are batched at 100 domains/call using repeated `domains[]=`
    query parameters. The decimal score (0-10, e.g. 3.45) is preferred over
    the integer score for finer-grained filtering; we fall back to the
    integer if the decimal is absent.
    """
    headers = {"API-OPR": api_key}
    scores: dict[str, float] = {}

    for batch_no, batch in enumerate(_chunk(candidates, OPR_BATCH_SIZE), start=1):
        # A list of tuples makes `requests` emit repeated `domains[]=` params.
        params = [("domains[]", d) for d in batch]
        try:
            resp = requests.get(
                OPR_ENDPOINT,
                headers=headers,
                params=params,
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            print(f"[opr] WARNING: batch {batch_no} request failed: {exc}")
            continue
        except json.JSONDecodeError as exc:
            print(f"[opr] WARNING: batch {batch_no} returned non-JSON: {exc}")
            continue

        for item in data.get("response", []) or []:
            # Items can be plain strings on error in some edge responses; guard.
            if not isinstance(item, dict):
                continue
            domain = (item.get("domain") or "").lower()
            if not domain:
                continue
            decimal = item.get("page_rank_decimal")
            integer = item.get("page_rank_integer")
            try:
                score = float(decimal if decimal not in (None, "") else (integer or 0))
            except (TypeError, ValueError):
                score = 0.0
            scores[domain] = score

        print(f"[opr] Batch {batch_no}: scored {len(batch)} domains.")

    return scores


# --------------------------------------------------------------------------- #
# Step 5: Gem filtration & webhook trigger
# --------------------------------------------------------------------------- #

def send_to_webhook(gems: list[dict], webhook_url: str) -> None:
    """POST the gem payload to the Apps Script web app.

    IMPORTANT (the redirect trap): a POST to a Google Apps Script `/exec`
    URL is processed immediately -- `doPost` runs and consumes the body on
    that first request -- and Google then returns a `302 Found` whose
    Location points at a `script.googleusercontent.com` URL hosting the
    rendered ContentService output. We therefore set allow_redirects=True so
    `requests` follows through to retrieve that final response. The body has
    already been delivered, so the GET that requests issues on the 302 simply
    fetches the result -- no data is lost.
    """
    payload = {"gems": gems}
    try:
        resp = requests.post(
            webhook_url,
            json=payload,
            allow_redirects=True,
            timeout=HTTP_TIMEOUT,
        )
        print(f"[webhook] HTTP {resp.status_code}; body: {resp.text.strip()[:200]}")
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[webhook] ERROR: failed to deliver payload: {exc}")


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def main() -> int:
    api_key = os.environ.get("OPENPAGERANK_API_KEY", "").strip()
    webhook_url = os.environ.get("APPS_SCRIPT_URL", "").strip()

    if not api_key:
        print("[fatal] OPENPAGERANK_API_KEY is not set.")
        return 1
    if not webhook_url:
        print("[fatal] APPS_SCRIPT_URL is not set.")
        return 1

    # --- Step 1 + 2: transfer & parse ------------------------------------- #
    raw_zone = fetch_zone()
    today_domains = parse_zone(raw_zone)
    print(f"[zone] Parsed {len(today_domains)} unique second-level .ee domains.")

    # Guard against a failed/partial transfer wiping the state file.
    if len(today_domains) < MIN_PLAUSIBLE_ZONE_SIZE:
        print(
            f"[fatal] Only {len(today_domains)} domains parsed "
            f"(< {MIN_PLAUSIBLE_ZONE_SIZE}). Assuming a failed transfer. "
            "State file left UNCHANGED."
        )
        return 1

    # --- Step 2: diff to find drops --------------------------------------- #
    yesterday_domains = read_state()
    if not yesterday_domains:
        # First run: no baseline to diff against. Seed the state and stop so
        # we don't flood ourselves with a meaningless "everything dropped" set.
        write_state(today_domains)
        print("[diff] First run complete -- baseline seeded, no diff performed.")
        return 0

    # Dropped = present yesterday, absent today. (The spec calls this a
    # "symmetric difference", but a drop is specifically the asymmetric
    # set difference yesterday - today; newly-registered names are not drops.)
    dropped = yesterday_domains - today_domains
    print(f"[diff] {len(dropped)} domains dropped since last run.")

    # Persist today's snapshot now that we have a trustworthy zone.
    write_state(today_domains)

    if not dropped:
        print("[diff] Empty drop set -- nothing further to do.")
        return 0

    # --- Step 3: lexical pre-screen --------------------------------------- #
    candidates = sorted(d for d in dropped if passes_lexical_filter(d))
    print(f"[lexical] {len(candidates)} of {len(dropped)} drops survived screening.")

    if not candidates:
        print("[lexical] No candidates survived -- nothing to score.")
        return 0

    # --- Step 4: OpenPageRank scoring ------------------------------------- #
    scores = query_openpagerank(candidates, api_key)

    # --- Step 5: gem filtration & delivery -------------------------------- #
    gems = [
        {"domain": domain, "rank": round(score, 2)}
        for domain, score in sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        if score >= OPR_SCORE_THRESHOLD
    ]
    print(f"[gems] {len(gems)} domains scored >= {OPR_SCORE_THRESHOLD}.")

    if gems:
        send_to_webhook(gems, webhook_url)
    else:
        print("[gems] No gems today -- webhook not triggered.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
