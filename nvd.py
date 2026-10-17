"""Look up CVEs for a software name + version using the free NVD API."""
import os, time, requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cache = {}          # query -> (timestamp, results)
_last_call = 0.0
CACHE_SECONDS = 3600


def severity_from_score(score):
    if score is None: return "Unknown"
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"


def _best_score(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            return metrics[key][0]["cvssData"].get("baseScore")
    return None


def lookup(software, version, limit=15):
    global _last_call
    query = f"{software} {version}".strip()
    hit = _cache.get(query.lower())
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]

    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    if not key:  # public limit is about 5 requests / 30 s
        wait = 6.5 - (time.time() - _last_call)
        if wait > 0: time.sleep(wait)
    _last_call = time.time()

    r = requests.get(NVD_URL, headers=headers, timeout=30,
                     params={"keywordSearch": query, "resultsPerPage": 50})
    r.raise_for_status()

    results = []
    for item in r.json().get("vulnerabilities", []):
        cve = item["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        score = _best_score(cve.get("metrics", {}))
        results.append({"id": cve["id"], "description": desc[:300],
                        "score": score, "severity": severity_from_score(score)})
    results.sort(key=lambda x: x["score"] or 0, reverse=True)
    results = results[:limit]
    _cache[query.lower()] = (time.time(), results)
    return results
