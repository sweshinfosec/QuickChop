# -*- coding: utf-8 -*-
"""
WPTChecklistScanner.py - Burp Suite extension (v1)
=====================================================================
A Burp Suite Extender tab that drives the standalone checklist_auto_scan.py
WPT checklist scanner against your CURRENT, authenticated Burp session, and
shows results grouped by category right inside Burp - plus optional
cross-reference against Burp's own Scanner findings.

WHY THIS IS WRITTEN THE WAY IT IS (read this before editing)
---------------------------------------------------------------------
Burp only loads Python extensions via Jython, which is stuck on Python
2.7 language syntax and a limited standard library with none of the
third-party packages (requests, pandas, xlsxwriter, Pillow, ...) that
checklist_auto_scan.py's ~100 checks and its .xlsx writer depend on.
Rewriting all of that in Jython would mean reimplementing and re-testing
logic that already works. Instead, this extension is a thin Jython
shell that:
  1. builds a Swing UI tab inside Burp,
  2. pulls your target list + session cookie from Burp's own Proxy
     history/scope (so it always tests as YOU, authenticated),
  3. shells out to a real CPython 3 interpreter running
     checklist_auto_scan.py with that captured session (that's the
     "I have python installed on my remote machine" part - this
     extension calls that installation, it doesn't replace it), and
  4. reads back the JSON it writes and renders it as a results table.

This keeps the actual scanning logic in one place (checklist_auto_scan.py,
already built/tested/used from the command line and from
Checklist-AutoScan.ps1) instead of forking it into a third, Jython-only
copy that would drift out of sync.

See README_BurpExtension.md (ships alongside this file) for installation,
configuration, and the external-tool integration roadmap (sqlmap/Dalfox/
Turbo Intruder/etc. for the ~300 checklist items this v1 does NOT cover).
"""

from burp import IBurpExtender, ITab, IContextMenuFactory

from javax.swing import (JPanel, JTabbedPane, JButton, JLabel, JTextField, JTextArea,
                          JScrollPane, JTable, JFileChooser, BoxLayout, SwingUtilities,
                          JOptionPane, ListSelectionModel, BorderFactory, JCheckBox, JTextPane,
                          JProgressBar, RowFilter, JList, DefaultListModel, JToggleButton, ButtonGroup,
                          JComboBox, JMenuItem)
from javax.swing.event import ListSelectionListener, DocumentListener, ChangeListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.text import SimpleAttributeSet, StyleConstants
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, Font, Dimension, Cursor
from java.awt.event import MouseAdapter
from java.lang import Object as JObject, Integer as JInteger

import subprocess
import json
import csv
import os
import tempfile
import threading
import time
import re

# Reported directly: "can we name this extention as lowchop? means low
# handing frouit tree to chooping" -> picked "QuickChop" from a short list
# of alternates offered back. This is the extension's DISPLAY name only
# (Burp's Extender tab list, the Suite tab caption, dialog titles, status
# messages). The file stays WPTChecklistScanner.py on disk so the
# existing --script-path/guessed-path logic and README don't need to
# change too - say the word if you'd rather rename the file itself.
EXT_NAME = "QuickChop"
# Reported directly: "after completing the scan it crashed or slow not
# working properly burp freezes" - a hung checklist_auto_scan.py
# subprocess (or a CLI tool it shells out to) used to block
# proc.communicate() forever with no way to recover. This caps a single
# scan run before it's force-killed; see _run_checklist_auto_scan.
SCAN_TIMEOUT_SECONDS = 20 * 60
# Reported directly: "no line by line URL read no 5-10 test perfored and
# captue progreess eaxly how i it was before" - checklist_auto_scan.py's
# add() (this rev onward) prints "QUICKCHOP_ROW|<json>" to stdout for
# every result the instant it's produced. _run_checklist_auto_scan reads
# that stream live (instead of blocking on proc.communicate() until the
# whole run finishes) and hands rows back to the UI in small batches of
# this size, so KPI cards / progress bar / Detailed Results grow
# gradually as the scan runs rather than jumping from 0 to 100% at once.
PROGRESS_FLUSH_EVERY = 8
RESULT_COLORS = {
    "PASS": Color(0xD9, 0xF2, 0xDF), "FAIL": Color(0xFB, 0xDA, 0xD8),
    "MANUAL": Color(0xFD, 0xF1, 0xC7), "INFO": Color(0xD9, 0xEC, 0xFB),
    "ERROR": Color(0xE6, 0xE6, 0xE6),
}
# Same accent colors checklist_auto_scan.py's terminal-style screenshots use
# for their top status bar (_RESULT_COLORS' first/dark element there) - reused
# here so the in-Burp detail popup and the exported evidence screenshots read
# as the same visual system. Reported directly: "no highlate for the findings"
# - the plain black-on-white popup didn't distinguish PASS/FAIL/etc at all.
RESULT_ACCENT_COLORS = {
    "PASS": Color(0x1E, 0x7E, 0x34), "FAIL": Color(0xA4, 0x26, 0x2C),
    "MANUAL": Color(0x8A, 0x6D, 0x00), "INFO": Color(0x1F, 0x4E, 0x78),
    "ERROR": Color(0x3B, 0x3B, 0x3B),
}
# Reported directly: "show colors differentils one line to other who
# critical first then high the n mediam last low" - the Summary tab's
# "Failed vulnerabilities" list (see _refresh_worst_findings) previously
# badged every row identically in FAIL-red regardless of severity, so
# rows were only distinguishable by reading the text. Each severity tier
# now gets its own color, darkest/most alarming for Critical down to a
# calmer blue-gray for Low, on top of the existing Critical-first sort.
SEVERITY_ACCENT_COLORS = {
    "Critical": Color(0x7B, 0x00, 0x00), "High": Color(0xA4, 0x26, 0x2C),
    "Medium": Color(0xB8, 0x56, 0x0F), "Low": Color(0x1F, 0x4E, 0x78),
    # Two spellings intentionally: "Informational" is the WPT checklist's
    # own severity value; Burp Scanner's IScanIssue.getSeverity() instead
    # returns the shorter "Information" for the same tier - both are
    # mapped here so _refresh_worst_findings and _show_burp_issue_detail
    # (which each only ever see ONE of the two vocabularies) both resolve
    # to a real color instead of falling back to plain FAIL-red.
    "Informational": Color(0x66, 0x66, 0x66), "Information": Color(0x66, 0x66, 0x66),
}
RESULT_COLUMNS = ["ID", "Category", "Test", "Severity", "Priority", "Result", "Evidence", "URL", "Source"]

# ---------------------------------------------------------------------
# OWASP Top 10 (2021) grouping for the Categories/Summary "OWASP Top 10"
# toggle. This maps checklist_auto_scan.py's actual category strings
# (the 13 automated categories - see its module docstring/print output)
# onto the 10 OWASP buckets. This is an ILLUSTRATIVE / best-effort
# mapping, not an official one - worth confirming against however
# ReportSystem itself classifies categories before relying on it for a
# real client-facing report. Any category NOT in this map (e.g. a future
# check category, or a MANUAL-only master-checklist category that ends
# up in a result row some other way) falls into the OWASP_OTHER bucket
# below instead of silently disappearing from the OWASP view.
# ---------------------------------------------------------------------
OWASP_GROUPS = [
    ("A01", "A01: Broken Access Control"),
    ("A02", "A02: Cryptographic Failures"),
    ("A03", "A03: Injection"),
    ("A04", "A04: Insecure Design"),
    ("A05", "A05: Security Misconfiguration"),
    ("A06", "A06: Vulnerable & Outdated Components"),
    ("A07", "A07: Identification & Authentication Failures"),
    ("A08", "A08: Software & Data Integrity Failures"),
    ("A09", "A09: Security Logging & Monitoring Failures"),
    ("A10", "A10: Server-Side Request Forgery (SSRF)"),
]
OWASP_OTHER_KEY = "OTHER"
OWASP_OTHER_LABEL = "Uncategorized / Not Yet Mapped"
# key -> human label lookup for OWASP_GROUPS, used by the Checklist
# Reference tab/export to show a real bucket name instead of a bare "A03"/
# "OTHER" key.
OWASP_GROUPS_BY_KEY = dict(OWASP_GROUPS)
OWASP_GROUPS_BY_KEY[OWASP_OTHER_KEY] = OWASP_OTHER_LABEL
OWASP_CATEGORY_MAP = {
    "Access Control": "A01",
    "Authorization Testing": "A01",
    "SSL / TLS": "A02",
    "Client-Side Testing": "A02",
    "HTTP Security Headers": "A05",
    "Configuration Testing": "A05",
    "Clickjacking": "A05",
    "CORS": "A05",
    "Email Security": "A05",
    "Information Gathering": "A06",
    "Session Management Testing": "A07",
    "Information Disclosure": "A09",
    "HTTP Host Header Attacks": "A10",
}
# Reported directly: "no categories listed owasp one fine" - the OWASP
# Top 10 view always lists all 10 fixed buckets (with 0s) even before a
# scan has run. KNOWN_CATEGORIES (redefined further below, once
# MASTER_CHECKLIST exists) gives the "All Categories" view the same
# "always show the full list" behavior.
# ---------------------------------------------------------------------
# Full master checklist (~421 items, "Web App Checklist" sheet from
# MasterChecklistMerged_2.xlsx) - the ~77 automated IDs above are a
# SUBSET of this same list (same WA-* ID scheme; verify with
# AUTOMATED_CHECKLIST_IDS below), the other ~344 are manual-testing-only
# items (SQL Injection, XSS, Business Logic, Race Conditions, etc.) that
# need a human + Repeater/Intruder/sqlmap/etc, never something
# checklist_auto_scan.py can verify unattended.
#
# Reported directly: "when I can confirm the test XSS in repeater or
# proxy or intruder selected output can be moved to quickchop for a
# record vulnerability list so we understand how many findings have
# been covered" - this list is what powers the new "Log finding to
# QuickChop" right-click menu (see IContextMenuFactory.createMenuItems
# below): it's the full searchable ID/name list the log-finding dialog
# picks from, so a MANUALLY confirmed finding from Repeater/Proxy/
# Intruder can be recorded against the correct checklist ID and show up
# in Detailed Results/Summary/Categories/Export right alongside the
# automated rows - one combined coverage picture instead of two.
#
# Tuple layout: (ID, Category, Test Name, Severity, Priority). To
# refresh this from a newer master spreadsheet: re-extract the "Web App
# Checklist" sheet's ID/Category/Test Name/Severity/Priority columns
# (openpyxl) and regenerate this whole list the same way.
# ---------------------------------------------------------------------
MASTER_CHECKLIST = [
    ("WA-SS-001", "SQL Injection", "Classic SQLi \u2014 WHERE clause bypass", "Critical", "P1"),
    ("WA-SS-002", "SQL Injection", "SQLi \u2014 error-based extraction", "Critical", "P1"),
    ("WA-SS-003", "SQL Injection", "SQLi \u2014 UNION-based column count", "Critical", "P1"),
    ("WA-SS-004", "SQL Injection", "SQLi \u2014 UNION retrieve data from other tables", "Critical", "P1"),
    ("WA-SS-005", "SQL Injection", "Blind SQLi \u2014 boolean-based", "Critical", "P1"),
    ("WA-SS-006", "SQL Injection", "Blind SQLi \u2014 time-based (SLEEP/WAITFOR)", "Critical", "P1"),
    ("WA-SS-007", "SQL Injection", "Blind SQLi \u2014 out-of-band DNS exfil", "High", "P1"),
    ("WA-SS-008", "SQL Injection", "SQLi \u2014 second-order (stored) injection", "High", "P1"),
    ("WA-SS-009", "SQL Injection", "SQLi \u2014 filter/WAF bypass (case, encoding)", "High", "P1"),
    ("WA-SS-010", "SQL Injection", "SQLi \u2014 login bypass via OR 1=1", "Critical", "P1"),
    ("WA-SS-011", "SQL Injection", "SQLi \u2014 stacked queries execution", "Critical", "P1"),
    ("WA-SS-012", "SQL Injection", "SQLi \u2014 file read (LOAD_FILE / COPY)", "High", "P1"),
    ("WA-SS-013", "SQL Injection", "SQLi \u2014 file write / webshell drop", "Critical", "P1"),
    ("WA-SS-014", "SQL Injection", "SQLi \u2014 XML/SOAP parameter injection", "High", "P1"),
    ("WA-SS-015", "SQL Injection", "SQLi \u2014 HTTP header injection (User-Agent/X-Forwarded-For)", "High", "P1"),
    ("WA-SS-016", "SQL Injection", "SQLi \u2014 cookie value injection", "High", "P1"),
    ("WA-SS-017", "SQL Injection", "SQLi \u2014 JSON body parameter injection", "High", "P1"),
    ("WA-SS-018", "SQL Injection", "SQLi \u2014 order-by / sort parameter injection", "Medium", "P2"),
    ("WA-SS-019", "Authentication", "Username enumeration via different responses", "High", "P1"),
    ("WA-SS-020", "Authentication", "Username enumeration via subtly different responses", "Medium", "P2"),
    ("WA-SS-021", "Authentication", "Username enumeration via response timing", "Medium", "P2"),
    ("WA-SS-022", "Authentication", "Password brute-force with rate-limit bypass", "High", "P1"),
    ("WA-SS-023", "Authentication", "2FA simple bypass (skip step 2)", "Critical", "P1"),
    ("WA-SS-024", "Authentication", "2FA brute-force (6-digit OTP)", "High", "P1"),
    ("WA-SS-025", "Authentication", "2FA broken logic (account takeover)", "Critical", "P1"),
    ("WA-SS-026", "Authentication", "Password reset \u2014 poisoning via Host header", "High", "P1"),
    ("WA-SS-027", "Authentication", "Password reset \u2014 broken logic / token reuse", "High", "P1"),
    ("WA-SS-028", "Authentication", "Password reset \u2014 link via referrer header leak", "Medium", "P2"),
    ("WA-SS-029", "Authentication", "Offline password cracking (stolen cookie hash)", "High", "P1"),
    ("WA-SS-030", "Authentication", "Stay logged in cookie predict / brute-force", "High", "P1"),
    ("WA-SS-031", "Authentication", "Account lockout \u2014 enumeration via lockout timing", "Medium", "P2"),
    ("WA-SS-032", "Authentication", "HTTP basic auth brute-force", "High", "P1"),
    ("WA-SS-033", "Path Traversal", "Path traversal \u2014 simple ../../etc/passwd", "High", "P1"),
    ("WA-SS-034", "Path Traversal", "Path traversal \u2014 absolute path bypass", "High", "P1"),
    ("WA-SS-035", "Path Traversal", "Path traversal \u2014 stripped non-recursively (....//)", "High", "P1"),
    ("WA-SS-036", "Path Traversal", "Path traversal \u2014 URL-encoded sequences (%2e%2e)", "High", "P1"),
    ("WA-SS-037", "Path Traversal", "Path traversal \u2014 null byte bypass (%00.png)", "High", "P1"),
    ("WA-SS-038", "Path Traversal", "Path traversal \u2014 start of path validation bypass", "High", "P1"),
    ("WA-SS-039", "Command Injection", "OS command injection \u2014 simple case (;whoami)", "Critical", "P1"),
    ("WA-SS-040", "Command Injection", "Blind command injection \u2014 time delay (sleep 10)", "Critical", "P1"),
    ("WA-SS-041", "Command Injection", "Blind command injection \u2014 output redirect to web root", "Critical", "P1"),
    ("WA-SS-042", "Command Injection", "Blind command injection \u2014 out-of-band (DNS/HTTP)", "Critical", "P1"),
    ("WA-SS-043", "Command Injection", "Blind command injection \u2014 shell metachar bypass", "High", "P1"),
    ("WA-SS-044", "Business Logic", "Excessive trust in client-side controls (price manipulation)", "High", "P1"),
    ("WA-SS-045", "Business Logic", "High-level logic vulnerability (order negative qty)", "High", "P1"),
    ("WA-SS-046", "Business Logic", "Low-level logic flaw (integer overflow on price)", "High", "P1"),
    ("WA-SS-047", "Business Logic", "Inconsistent security controls (email domain change)", "High", "P1"),
    ("WA-SS-048", "Business Logic", "Flawed enforcement of business rules (discount stacking)", "Medium", "P2"),
    ("WA-SS-049", "Business Logic", "Infinite money logic flaw (gift card loop)", "High", "P1"),
    ("WA-SS-050", "Business Logic", "Authentication bypass via flawed state machine", "Critical", "P1"),
    ("WA-SS-051", "Business Logic", "Flawed logic \u2014 weak isolation on dual-use endpoint", "High", "P1"),
    ("WA-SS-052", "Business Logic", "Insufficient workflow validation (skip steps)", "High", "P1"),
    ("WA-SS-053", "Business Logic", "Account takeover via password reset poisoning logic", "Critical", "P1"),
    ("WA-SS-054", "Business Logic", "Manipulation of hidden inputs/fields", "Medium", "P2"),
    ("WA-SS-055", "Information Disclosure", "Information disclosure in error messages (stack trace)", "Medium", "P2"),
    ("WA-SS-056", "Information Disclosure", "Info disclosure \u2014 debug page (phpinfo/rails debug)", "High", "P1"),
    ("WA-SS-057", "Information Disclosure", "Info disclosure \u2014 source code via backup files", "High", "P1"),
    ("WA-SS-058", "Information Disclosure", "Info disclosure \u2014 version via response headers", "Low", "P3"),
    ("WA-SS-059", "Information Disclosure", "Info disclosure \u2014 sensitive data in git/svn/.DS_Store", "High", "P1"),
    ("WA-SS-060", "Access Control", "Unprotected admin functionality (robots.txt leak)", "Critical", "P1"),
    ("WA-SS-061", "Access Control", "Unprotected admin \u2014 unpredictable URL via source", "High", "P1"),
    ("WA-SS-062", "Access Control", "Parameter-based access control (admin=true cookie)", "Critical", "P1"),
    ("WA-SS-063", "Access Control", "Broken access \u2014 relying on obscurity (security by header)", "High", "P1"),
    ("WA-SS-064", "Access Control", "URL-based access control bypass (X-Original-URL)", "High", "P1"),
    ("WA-SS-065", "Access Control", "Method-based access control bypass (GET\u2192POST/POST\u2192GET)", "High", "P1"),
    ("WA-SS-066", "Access Control", "IDOR \u2014 direct object reference (change user ID in URL)", "Critical", "P1"),
    ("WA-SS-067", "Access Control", "IDOR \u2014 in non-numeric IDs (GUID/UUID)", "High", "P1"),
    ("WA-SS-068", "Access Control", "IDOR \u2014 via redirect (302 still returns body)", "High", "P1"),
    ("WA-SS-069", "Access Control", "Multi-step process bypass (skip confirmation step)", "High", "P1"),
    ("WA-SS-070", "Access Control", "Referer-based access control bypass", "High", "P1"),
    ("WA-SS-071", "Access Control", "Horizontal privilege escalation (access another user data)", "Critical", "P1"),
    ("WA-SS-072", "Access Control", "Vertical privilege escalation (user \u2192 admin actions)", "Critical", "P1"),
    ("WA-SS-073", "File Upload", "File upload \u2014 unrestricted (webshell upload)", "Critical", "P1"),
    ("WA-SS-074", "File Upload", "File upload \u2014 content-type bypass (image/jpeg \u2192 PHP)", "Critical", "P1"),
    ("WA-SS-075", "File Upload", "File upload \u2014 blacklist bypass (.php5 / .phtml / .phar)", "Critical", "P1"),
    ("WA-SS-076", "File Upload", "File upload \u2014 obfuscated extension (.pHp / .%00.php)", "High", "P1"),
    ("WA-SS-077", "File Upload", "File upload \u2014 flawed validation of file contents", "High", "P1"),
    ("WA-SS-078", "File Upload", "File upload \u2014 polyglot webshell (JPEG + PHP)", "High", "P1"),
    ("WA-SS-079", "File Upload", "File upload \u2014 path traversal in filename", "High", "P1"),
    ("WA-SS-080", "Race Conditions", "Race condition \u2014 limit overrun (redeem coupon multiple times)", "High", "P1"),
    ("WA-SS-081", "Race Conditions", "Race condition \u2014 bypassing rate limits via parallel requests", "High", "P1"),
    ("WA-SS-082", "Race Conditions", "Race condition \u2014 single-endpoint TOCTOU", "High", "P1"),
    ("WA-SS-083", "Race Conditions", "Race condition \u2014 multi-endpoint state clash", "High", "P1"),
    ("WA-SS-084", "Race Conditions", "Race condition \u2014 partial construction attack", "Medium", "P2"),
    ("WA-SS-085", "Race Conditions", "Race condition \u2014 time-sensitive hidden token brute force", "High", "P1"),
    ("WA-SS-086", "SSRF", "SSRF against server itself (127.0.0.1 loopback)", "Critical", "P1"),
    ("WA-SS-087", "SSRF", "SSRF against backend internal systems", "Critical", "P1"),
    ("WA-SS-088", "SSRF", "SSRF bypass \u2014 blacklist filter (127.1 / 2130706433)", "High", "P1"),
    ("WA-SS-089", "SSRF", "SSRF bypass \u2014 whitelist filter via open redirect", "High", "P1"),
    ("WA-SS-090", "SSRF", "Blind SSRF \u2014 out-of-band detection (Referer header)", "High", "P1"),
    ("WA-SS-091", "SSRF", "Blind SSRF \u2014 shellshock exploit via User-Agent", "Critical", "P1"),
    ("WA-SS-092", "SSRF", "SSRF via cloud metadata endpoint (169.254.169.254)", "Critical", "P1"),
    ("WA-SS-093", "XXE Injection", "XXE \u2014 retrieve files via external entity", "Critical", "P1"),
    ("WA-SS-094", "XXE Injection", "XXE \u2014 SSRF via external entity", "Critical", "P1"),
    ("WA-SS-095", "XXE Injection", "Blind XXE \u2014 out-of-band interaction", "High", "P1"),
    ("WA-SS-096", "XXE Injection", "Blind XXE \u2014 out-of-band via XML parameter entity", "High", "P1"),
    ("WA-SS-097", "XXE Injection", "Blind XXE \u2014 data exfiltration via error message", "High", "P1"),
    ("WA-SS-098", "XXE Injection", "Blind XXE \u2014 out-of-band exfil via repurposed local DTD", "High", "P1"),
    ("WA-SS-099", "XXE Injection", "XXE \u2014 via file upload (SVG/Office formats)", "High", "P1"),
    ("WA-SS-100", "XXE Injection", "XXE \u2014 via modified content-type (JSON\u2192XML)", "High", "P1"),
    ("WA-SS-101", "XXE Injection", "XInclude attacks (when full XML doc control not possible)", "High", "P1"),
    ("WA-SS-102", "NoSQL Injection", "NoSQLi \u2014 detect / bypass authentication ($ne operator)", "Critical", "P1"),
    ("WA-SS-103", "NoSQL Injection", "NoSQLi \u2014 extract data via operator injection", "High", "P1"),
    ("WA-SS-104", "NoSQL Injection", "NoSQLi \u2014 timing-based blind injection", "High", "P1"),
    ("WA-SS-105", "NoSQL Injection", "NoSQLi \u2014 JavaScript injection ($where clause)", "High", "P1"),
    ("WA-SS-106", "API Testing", "API recon \u2014 discover hidden endpoints via JS/docs/wordlist", "High", "P1"),
    ("WA-SS-107", "API Testing", "API \u2014 find hidden params via mass assignment", "High", "P1"),
    ("WA-SS-108", "API Testing", "API \u2014 exploiting unused/debug endpoints", "High", "P1"),
    ("WA-SS-109", "API Testing", "API \u2014 HTTP verb tampering on REST endpoints", "Medium", "P2"),
    ("WA-SS-110", "API Testing", "API \u2014 server-side parameter pollution (SSPP)", "High", "P1"),
    ("WA-SS-111", "Web Cache Deception", "Cache deception \u2014 force cache of private data via path suffix", "High", "P1"),
    ("WA-SS-112", "Web Cache Deception", "Cache deception \u2014 delimiter-based (delimiter discrepancy)", "High", "P1"),
    ("WA-SS-113", "Web Cache Deception", "Cache deception \u2014 delimiter decoding discrepancy", "High", "P1"),
    ("WA-SS-114", "Web Cache Deception", "Cache deception \u2014 static extension path confusion", "High", "P1"),
    ("WA-SS-115", "Web Cache Deception", "Cache deception \u2014 normalization discrepancy", "Medium", "P2"),
    ("WA-CS-116", "Cross-Site Scripting (XSS)", "Reflected XSS \u2014 simple HTML context", "High", "P1"),
    ("WA-CS-117", "Cross-Site Scripting (XSS)", "Stored XSS \u2014 simple HTML context", "High", "P1"),
    ("WA-CS-118", "Cross-Site Scripting (XSS)", "DOM-based XSS \u2014 innerHTML sink", "High", "P1"),
    ("WA-CS-119", "Cross-Site Scripting (XSS)", "DOM-based XSS \u2014 document.write sink", "High", "P1"),
    ("WA-CS-120", "Cross-Site Scripting (XSS)", "DOM-based XSS \u2014 location.search AngularJS expression", "High", "P1"),
    ("WA-CS-121", "Cross-Site Scripting (XSS)", "Reflected DOM XSS via JSON injection", "High", "P1"),
    ("WA-CS-122", "Cross-Site Scripting (XSS)", "Stored DOM XSS via innerHTML", "High", "P1"),
    ("WA-CS-123", "Cross-Site Scripting (XSS)", "XSS via HTML attribute encoding bypass", "High", "P1"),
    ("WA-CS-124", "Cross-Site Scripting (XSS)", "XSS via href attribute (javascript:alert)", "High", "P1"),
    ("WA-CS-125", "Cross-Site Scripting (XSS)", "XSS via JS string escape with backslash", "High", "P1"),
    ("WA-CS-126", "Cross-Site Scripting (XSS)", "XSS into JS template literal", "High", "P1"),
    ("WA-CS-127", "Cross-Site Scripting (XSS)", "XSS \u2014 CSP bypass via dangling markup", "High", "P1"),
    ("WA-CS-128", "Cross-Site Scripting (XSS)", "XSS \u2014 bypass CSP via nonce reuse", "High", "P1"),
    ("WA-CS-129", "Cross-Site Scripting (XSS)", "XSS \u2014 bypass CSP via hash mismatch", "High", "P1"),
    ("WA-CS-130", "Cross-Site Scripting (XSS)", "XSS \u2014 SVG tag injection", "High", "P1"),
    ("WA-CS-131", "Cross-Site Scripting (XSS)", "XSS \u2014 polyglot payload", "High", "P1"),
    ("WA-CS-132", "Cross-Site Scripting (XSS)", "XSS \u2014 tag attribute context (event handler injection)", "High", "P1"),
    ("WA-CS-133", "Cross-Site Scripting (XSS)", "XSS \u2014 custom tag injection with autofocus/tabindex", "Medium", "P2"),
    ("WA-CS-134", "Cross-Site Scripting (XSS)", "XSS \u2014 onload iframe injection", "High", "P1"),
    ("WA-CS-135", "Cross-Site Scripting (XSS)", "XSS \u2014 Unicode / HTML entity bypass", "High", "P1"),
    ("WA-CS-136", "Cross-Site Scripting (XSS)", "XSS \u2014 WAF bypass using less-common event handlers", "High", "P1"),
    ("WA-CS-137", "Cross-Site Scripting (XSS)", "Reflected XSS \u2014 cookie extraction PoC", "High", "P1"),
    ("WA-CS-138", "Cross-Site Scripting (XSS)", "Stored XSS \u2014 keylogger injection PoC", "High", "P1"),
    ("WA-CS-139", "Cross-Site Scripting (XSS)", "XSS \u2014 account takeover via password change form", "Critical", "P1"),
    ("WA-CS-140", "Cross-Site Scripting (XSS)", "XSS \u2014 session hijacking via document.cookie exfil", "Critical", "P1"),
    ("WA-CS-141", "Cross-Site Scripting (XSS)", "XSS \u2014 clickjacking + XSS chained attack", "High", "P1"),
    ("WA-CS-142", "Cross-Site Scripting (XSS)", "XSS \u2014 DOM clobbering to bypass purification", "High", "P1"),
    ("WA-CS-143", "Cross-Site Scripting (XSS)", "XSS \u2014 open redirect via location.hash", "Medium", "P2"),
    ("WA-CS-144", "Cross-Site Scripting (XSS)", "DOM XSS \u2014 jQuery selector sink ($())", "High", "P1"),
    ("WA-CS-145", "Cross-Site Scripting (XSS)", "DOM XSS \u2014 jQuery attr() hashchange event", "High", "P1"),
    ("WA-CS-146", "CSRF", "CSRF \u2014 simple GET request no token", "High", "P1"),
    ("WA-CS-147", "CSRF", "CSRF \u2014 token validation depends on request method (GET ok)", "High", "P1"),
    ("WA-CS-148", "CSRF", "CSRF \u2014 token validation depends on token being present", "High", "P1"),
    ("WA-CS-149", "CSRF", "CSRF \u2014 token not tied to user session", "High", "P1"),
    ("WA-CS-150", "CSRF", "CSRF \u2014 token tied to non-session cookie", "High", "P1"),
    ("WA-CS-151", "CSRF", "CSRF \u2014 token duplicated in cookie", "High", "P1"),
    ("WA-CS-152", "CSRF", "CSRF \u2014 Referer-based defense bypass (remove header)", "High", "P1"),
    ("WA-CS-153", "CSRF", "CSRF \u2014 Referer header whitelist bypass", "High", "P1"),
    ("WA-CS-154", "CSRF", "CSRF \u2014 SameSite Lax bypass via GET method override", "High", "P1"),
    ("WA-CS-155", "CSRF", "CSRF \u2014 SameSite Strict bypass via sibling domain redirect", "High", "P1"),
    ("WA-CS-156", "CSRF", "CSRF \u2014 SameSite Lax bypass via cookie refresh", "Medium", "P2"),
    ("WA-CS-157", "CSRF", "CSRF \u2014 bypass via browser cookie injection (CRLF chain)", "High", "P1"),
    ("WA-CS-158", "CORS", "CORS \u2014 misconfig: wildcard/reflected origin trusts attacker", "High", "P1"),
    ("WA-CS-159", "CORS", "CORS \u2014 null origin trusted (sandbox iframe bypass)", "High", "P1"),
    ("WA-CS-160", "CORS", "CORS \u2014 intranet pivot via trusted whitelisted origin", "High", "P1"),
    ("WA-CS-161", "Clickjacking", "Clickjacking \u2014 basic UI redress attack (iframe overlay)", "Medium", "P2"),
    ("WA-CS-162", "Clickjacking", "Clickjacking \u2014 form pre-fill attack", "Medium", "P2"),
    ("WA-CS-163", "Clickjacking", "Clickjacking \u2014 frame-busting script bypass", "Medium", "P2"),
    ("WA-CS-164", "Clickjacking", "Clickjacking \u2014 multistep attack (confirm + click)", "Medium", "P2"),
    ("WA-CS-165", "Clickjacking", "Clickjacking \u2014 drag-and-drop UI attack", "Medium", "P2"),
    ("WA-CS-166", "DOM-based Vulnerabilities", "DOM-based open redirect (location.href taint)", "Medium", "P2"),
    ("WA-CS-167", "DOM-based Vulnerabilities", "DOM-based cookie manipulation", "Medium", "P2"),
    ("WA-CS-168", "DOM-based Vulnerabilities", "DOM-based XSS via web messages", "High", "P1"),
    ("WA-CS-169", "DOM-based Vulnerabilities", "DOM-based open redirect via web messages", "Medium", "P2"),
    ("WA-CS-170", "DOM-based Vulnerabilities", "DOM-based XSS via web messages and JSON.parse", "High", "P1"),
    ("WA-CS-171", "DOM-based Vulnerabilities", "DOM clobbering \u2014 bypass HTML sanitiser", "High", "P1"),
    ("WA-CS-172", "DOM-based Vulnerabilities", "Clobbering DOM attributes to bypass sanitisation", "High", "P1"),
    ("WA-CS-173", "WebSockets", "WebSocket \u2014 manipulating messages (stored XSS)", "High", "P1"),
    ("WA-CS-174", "WebSockets", "WebSocket \u2014 cross-site hijacking (CSWSH)", "High", "P1"),
    ("WA-CS-175", "WebSockets", "WebSocket \u2014 CSWSH to read sensitive messages", "High", "P1"),
    ("WA-ADV-176", "Insecure Deserialization", "Deserialization \u2014 modify serialized data (PHP object)", "High", "P1"),
    ("WA-ADV-177", "Insecure Deserialization", "Deserialization \u2014 modify data types (PHP loose comparison)", "High", "P1"),
    ("WA-ADV-178", "Insecure Deserialization", "Deserialization \u2014 arbitrary object injection", "Critical", "P1"),
    ("WA-ADV-179", "Insecure Deserialization", "Deserialization \u2014 magic method abuse", "Critical", "P1"),
    ("WA-ADV-180", "Insecure Deserialization", "Deserialization \u2014 PHP gadget chain (RCE)", "Critical", "P1"),
    ("WA-ADV-181", "Insecure Deserialization", "Deserialization \u2014 Java gadget chain (Commons Collections)", "Critical", "P1"),
    ("WA-ADV-182", "Insecure Deserialization", "Deserialization \u2014 Python pickle RCE", "Critical", "P1"),
    ("WA-ADV-183", "Insecure Deserialization", "Deserialization \u2014 PHAR PHP deserialization via file upload", "Critical", "P1"),
    ("WA-ADV-184", "Insecure Deserialization", "Deserialization \u2014 Ruby gadget chain RCE", "Critical", "P1"),
    ("WA-ADV-185", "Insecure Deserialization", "Deserialization \u2014 using pre-built gadget chains (tool-based)", "Critical", "P1"),
    ("WA-ADV-186", "Web LLM Attacks", "LLM \u2014 indirect prompt injection via stored content", "High", "P1"),
    ("WA-ADV-187", "Web LLM Attacks", "LLM \u2014 direct prompt injection (jailbreak system prompt)", "High", "P1"),
    ("WA-ADV-188", "Web LLM Attacks", "LLM \u2014 exploiting APIs via prompt injection", "Critical", "P1"),
    ("WA-ADV-189", "Web LLM Attacks", "LLM \u2014 data exfiltration via indirect injection", "High", "P1"),
    ("WA-ADV-190", "Web LLM Attacks", "LLM \u2014 SSRF via prompt injection (Markdown link exfil)", "High", "P1"),
    ("WA-ADV-191", "Web LLM Attacks", "LLM \u2014 insecure plugin/tool invocation", "High", "P1"),
    ("WA-ADV-192", "Web LLM Attacks", "LLM \u2014 training data extraction attack", "Medium", "P2"),
    ("WA-ADV-193", "GraphQL API Security", "GraphQL \u2014 introspection enabled (full schema exposure)", "Medium", "P2"),
    ("WA-ADV-194", "GraphQL API Security", "GraphQL \u2014 bypassing introspection defences", "Medium", "P2"),
    ("WA-ADV-195", "GraphQL API Security", "GraphQL \u2014 accidental data exposure via aliases", "High", "P1"),
    ("WA-ADV-196", "GraphQL API Security", "GraphQL \u2014 CSRF via GET request mutations", "High", "P1"),
    ("WA-ADV-197", "GraphQL API Security", "GraphQL \u2014 batching attack (rate-limit bypass / brute-force)", "High", "P1"),
    ("WA-ADV-198", "Server-Side Template Injection", "SSTI \u2014 detect ({{7*7}} / ${7*7} / #{7*7})", "Critical", "P1"),
    ("WA-ADV-199", "Server-Side Template Injection", "SSTI \u2014 Jinja2 / Python sandbox escape \u2192 RCE", "Critical", "P1"),
    ("WA-ADV-200", "Server-Side Template Injection", "SSTI \u2014 Twig (PHP) \u2192 code exec", "Critical", "P1"),
    ("WA-ADV-201", "Server-Side Template Injection", "SSTI \u2014 FreeMarker (Java) \u2192 RCE", "Critical", "P1"),
    ("WA-ADV-202", "Server-Side Template Injection", "SSTI \u2014 Velocity (Java) \u2192 RCE", "Critical", "P1"),
    ("WA-ADV-203", "Server-Side Template Injection", "SSTI \u2014 unknown engine identification", "High", "P1"),
    ("WA-ADV-204", "Server-Side Template Injection", "SSTI \u2014 sandbox escape via custom filter/method", "Critical", "P1"),
    ("WA-ADV-205", "Web Cache Poisoning", "Cache poisoning \u2014 basic via X-Forwarded-Host", "High", "P1"),
    ("WA-ADV-206", "Web Cache Poisoning", "Cache poisoning \u2014 unknown header (X-Forwarded-Scheme)", "High", "P1"),
    ("WA-ADV-207", "Web Cache Poisoning", "Cache poisoning \u2014 multiple headers required", "High", "P1"),
    ("WA-ADV-208", "Web Cache Poisoning", "Cache poisoning \u2014 targeted at specific user", "High", "P1"),
    ("WA-ADV-209", "Web Cache Poisoning", "Cache poisoning \u2014 via DOM-based vulnerability", "High", "P1"),
    ("WA-ADV-210", "Web Cache Poisoning", "Cache poisoning \u2014 chained with open redirect", "High", "P1"),
    ("WA-ADV-211", "Web Cache Poisoning", "Cache poisoning \u2014 via unkeyed query string", "High", "P1"),
    ("WA-ADV-212", "Web Cache Poisoning", "Cache poisoning \u2014 via unkeyed query parameters", "High", "P1"),
    ("WA-ADV-213", "Web Cache Poisoning", "Cache poisoning \u2014 parameter cloaking (delimiter discrepancy)", "High", "P1"),
    ("WA-ADV-214", "Web Cache Poisoning", "Cache poisoning \u2014 via fat GET request", "Medium", "P2"),
    ("WA-ADV-215", "Web Cache Poisoning", "Cache poisoning \u2014 URL normalization", "Medium", "P2"),
    ("WA-ADV-216", "Web Cache Poisoning", "Cache poisoning \u2014 response header injection (CRLF)", "High", "P1"),
    ("WA-ADV-217", "Web Cache Poisoning", "Cache poisoning \u2014 internal cache via request headers", "High", "P1"),
    ("WA-ADV-218", "HTTP Host Header Attacks", "Host header \u2014 password reset poisoning", "High", "P1"),
    ("WA-ADV-219", "HTTP Host Header Attacks", "Host header \u2014 web cache poisoning via Host", "High", "P1"),
    ("WA-ADV-220", "HTTP Host Header Attacks", "Host header \u2014 SSRF via malformed Host header", "High", "P1"),
    ("WA-ADV-221", "HTTP Host Header Attacks", "Host header \u2014 bypass internal authentication (localhost)", "Critical", "P1"),
    ("WA-ADV-222", "HTTP Host Header Attacks", "Host header \u2014 routing-based SSRF (ambiguous requests)", "High", "P1"),
    ("WA-ADV-223", "HTTP Host Header Attacks", "Host header \u2014 SSRF via connection header", "High", "P1"),
    ("WA-ADV-224", "HTTP Host Header Attacks", "Host header \u2014 X-Host / X-Forwarded-Server override", "High", "P1"),
    ("WA-ADV-225", "HTTP Request Smuggling", "Smuggling \u2014 detect CL.TE using timing", "High", "P1"),
    ("WA-ADV-226", "HTTP Request Smuggling", "Smuggling \u2014 detect TE.CL using timing", "High", "P1"),
    ("WA-ADV-227", "HTTP Request Smuggling", "Smuggling \u2014 CL.TE basic exploit", "Critical", "P1"),
    ("WA-ADV-228", "HTTP Request Smuggling", "Smuggling \u2014 TE.CL basic exploit", "Critical", "P1"),
    ("WA-ADV-229", "HTTP Request Smuggling", "Smuggling \u2014 TE.TE: obfuscating TE header", "Critical", "P1"),
    ("WA-ADV-230", "HTTP Request Smuggling", "Smuggling \u2014 bypass front-end security controls (access control)", "Critical", "P1"),
    ("WA-ADV-231", "HTTP Request Smuggling", "Smuggling \u2014 reveal front-end request rewriting", "High", "P1"),
    ("WA-ADV-232", "HTTP Request Smuggling", "Smuggling \u2014 capture other users' requests", "Critical", "P1"),
    ("WA-ADV-233", "HTTP Request Smuggling", "Smuggling \u2014 exploit reflected XSS via smuggled request", "High", "P1"),
    ("WA-ADV-234", "HTTP Request Smuggling", "Smuggling \u2014 turn reflected XSS into stored via smuggling", "High", "P1"),
    ("WA-ADV-235", "HTTP Request Smuggling", "Smuggling \u2014 SSRF via HTTP request smuggling", "High", "P1"),
    ("WA-ADV-236", "HTTP Request Smuggling", "Smuggling \u2014 poison web cache via differential response", "High", "P1"),
    ("WA-ADV-237", "HTTP Request Smuggling", "HTTP/2 \u2014 H2.CL request smuggling", "Critical", "P1"),
    ("WA-ADV-238", "HTTP Request Smuggling", "HTTP/2 \u2014 H2.TE request smuggling", "Critical", "P1"),
    ("WA-ADV-239", "HTTP Request Smuggling", "HTTP/2 \u2014 response queue poisoning via H2.TE", "Critical", "P1"),
    ("WA-ADV-240", "HTTP Request Smuggling", "HTTP/2 \u2014 request tunnel via header-based injection", "High", "P1"),
    ("WA-ADV-241", "HTTP Request Smuggling", "HTTP/2 \u2014 bypass front-end controls with H2 downgrade", "Critical", "P1"),
    ("WA-ADV-242", "HTTP Request Smuggling", "HTTP/2 \u2014 SSRF via CRLF injection in header name", "High", "P1"),
    ("WA-ADV-243", "HTTP Request Smuggling", "HTTP/2 \u2014 client-side desync exploitation", "High", "P1"),
    ("WA-ADV-244", "HTTP Request Smuggling", "HTTP/2 \u2014 server-side pause-based desync", "High", "P1"),
    ("WA-ADV-245", "HTTP Request Smuggling", "HTTP/2 \u2014 exploiting URL prefix injection", "High", "P1"),
    ("WA-ADV-246", "HTTP Request Smuggling", "HTTP/2 \u2014 browser-powered request smuggling (Chrome + JS)", "High", "P1"),
    ("WA-ADV-247", "OAuth 2.0", "OAuth \u2014 authentication bypass via implicit flow", "Critical", "P1"),
    ("WA-ADV-248", "OAuth 2.0", "OAuth \u2014 CSRF against OAuth state parameter", "High", "P1"),
    ("WA-ADV-249", "OAuth 2.0", "OAuth \u2014 stealing codes via open redirect", "High", "P1"),
    ("WA-ADV-250", "OAuth 2.0", "OAuth \u2014 stealing tokens via proxy page", "High", "P1"),
    ("WA-ADV-251", "OAuth 2.0", "OAuth \u2014 SSRF via dynamic client registration", "High", "P1"),
    ("WA-ADV-252", "OAuth 2.0", "OAuth \u2014 Account hijack via redirect_uri manipulation", "Critical", "P1"),
    ("WA-ADV-253", "JWT Attacks", "JWT \u2014 bypass via unverified signature", "Critical", "P1"),
    ("WA-ADV-254", "JWT Attacks", "JWT \u2014 bypass via alg:none", "Critical", "P1"),
    ("WA-ADV-255", "JWT Attacks", "JWT \u2014 brute-force weak HMAC secret", "High", "P1"),
    ("WA-ADV-256", "JWT Attacks", "JWT \u2014 algorithm confusion (RS256 \u2192 HS256 with public key)", "Critical", "P1"),
    ("WA-ADV-257", "JWT Attacks", "JWT \u2014 inject self-signed JWK via jwk header", "Critical", "P1"),
    ("WA-ADV-258", "JWT Attacks", "JWT \u2014 inject self-signed via jku parameter", "Critical", "P1"),
    ("WA-ADV-259", "JWT Attacks", "JWT \u2014 inject via kid path traversal (read /dev/null \u2192 empty)", "Critical", "P1"),
    ("WA-ADV-260", "JWT Attacks", "JWT \u2014 kid SQL injection to sign with null byte", "Critical", "P1"),
    ("WA-ADV-261", "Prototype Pollution", "Prototype pollution \u2014 client-side via query string", "High", "P1"),
    ("WA-ADV-262", "Prototype Pollution", "Prototype pollution \u2014 client-side via URL fragment", "High", "P1"),
    ("WA-ADV-263", "Prototype Pollution", "Prototype pollution \u2014 client-side via JSON (Object.assign)", "High", "P1"),
    ("WA-ADV-264", "Prototype Pollution", "Prototype pollution \u2014 bypassing flawed key sanitisation", "High", "P1"),
    ("WA-ADV-265", "Prototype Pollution", "Prototype pollution \u2014 gadget chain \u2192 DOM XSS", "High", "P1"),
    ("WA-ADV-266", "Prototype Pollution", "Prototype pollution \u2014 gadget chain \u2192 reflected XSS", "High", "P1"),
    ("WA-ADV-267", "Prototype Pollution", "Prototype pollution \u2014 server-side (Node.js) via JSON body", "Critical", "P1"),
    ("WA-ADV-268", "Prototype Pollution", "Prototype pollution \u2014 server-side via query string", "Critical", "P1"),
    ("WA-ADV-269", "Prototype Pollution", "Prototype pollution \u2014 server-side RCE gadget", "Critical", "P1"),
    ("WA-ADV-270", "Prototype Pollution", "Prototype pollution \u2014 detect server-side using timing attack", "High", "P1"),
    ("WA-ADV-271", "Essential Skills", "Obfuscating attacks \u2014 bypass filters via multiple encoding", "Medium", "P2"),
    ("WA-ADV-272", "Essential Skills", "Identify unknown vuln class via error messages + fuzzing", "Medium", "P2"),
    ("WA-OTG-273", "Information Gathering", "Conduct search engine recon (Google dorks, Shodan)", "Info", "P3"),
    ("WA-OTG-274", "Information Gathering", "Fingerprint web server (Server header, error pages)", "Low", "P3"),
    ("WA-OTG-275", "Information Gathering", "Review webserver metafiles (robots.txt, sitemap.xml)", "Low", "P3"),
    ("WA-OTG-276", "Information Gathering", "Enumerate application entry points (all params/forms)", "Info", "P3"),
    ("WA-OTG-277", "Information Gathering", "Map execution paths through application", "Info", "P3"),
    ("WA-OTG-278", "Information Gathering", "Fingerprint web application framework", "Low", "P3"),
    ("WA-OTG-279", "Information Gathering", "Map application architecture (CDN, WAF, LB, proxy layers)", "Info", "P3"),
    ("WA-OTG-280", "Information Gathering", "Identify application dependencies (package.json, Gemfile, pom)", "Low", "P3"),
    ("WA-OTG-281", "Information Gathering", "Harvest emails, usernames, phone numbers from app", "Info", "P3"),
    ("WA-OTG-282", "Information Gathering", "Identify cloud storage buckets (S3, GCS, Azure Blob)", "High", "P1"),
    ("WA-OTG-283", "Configuration Testing", "Test network/infrastructure config (exposed admin ports)", "High", "P1"),
    ("WA-OTG-284", "Configuration Testing", "Test application platform configuration (default creds)", "High", "P1"),
    ("WA-OTG-285", "Configuration Testing", "Test file extension handling (.bak .old .orig .swp)", "High", "P1"),
    ("WA-OTG-286", "Configuration Testing", "Review backup and unreferenced files", "High", "P1"),
    ("WA-OTG-287", "Configuration Testing", "Enumerate infrastructure and admin interfaces", "Critical", "P1"),
    ("WA-OTG-288", "Configuration Testing", "Test HTTP methods (PUT/DELETE/OPTIONS/TRACE)", "Medium", "P2"),
    ("WA-OTG-289", "Configuration Testing", "Test HTTP Strict Transport Security (HSTS present?)", "Medium", "P2"),
    ("WA-OTG-290", "Configuration Testing", "Test RIA cross domain policy (crossdomain.xml / clientaccesspolicy)", "Medium", "P2"),
    ("WA-OTG-291", "Configuration Testing", "Test file permissions on web server", "Medium", "P2"),
    ("WA-OTG-292", "Configuration Testing", "Test subdomain takeover", "High", "P1"),
    ("WA-OTG-293", "Configuration Testing", "Test cloud storage permissions (public buckets/blobs)", "High", "P1"),
    ("WA-OTG-294", "Configuration Testing", "Test content security policy (CSP header analysis)", "Medium", "P2"),
    ("WA-OTG-295", "Identity Management", "Test role definitions (RBAC enforcement)", "High", "P1"),
    ("WA-OTG-296", "Identity Management", "Test user registration process (self-registration flaws)", "Medium", "P2"),
    ("WA-OTG-297", "Identity Management", "Test account provisioning process", "Medium", "P2"),
    ("WA-OTG-298", "Identity Management", "Test account enumeration (registration / login / password reset)", "Medium", "P2"),
    ("WA-OTG-299", "Identity Management", "Test weak/default credentials policy", "High", "P1"),
    ("WA-OTG-300", "Identity Management", "Test username policy (predictability)", "Low", "P3"),
    ("WA-OTG-301", "Authentication Testing", "Test credentials over encrypted channel (HTTPS enforced)", "High", "P1"),
    ("WA-OTG-302", "Authentication Testing", "Test default credentials (admin/admin, admin/password)", "Critical", "P1"),
    ("WA-OTG-303", "Authentication Testing", "Test account lockout / brute-force protection", "High", "P1"),
    ("WA-OTG-304", "Authentication Testing", "Test for authentication bypass via parameter manipulation", "Critical", "P1"),
    ("WA-OTG-305", "Authentication Testing", "Test remember-me functionality", "Medium", "P2"),
    ("WA-OTG-306", "Authentication Testing", "Test browser cache for sensitive data after logout", "Medium", "P2"),
    ("WA-OTG-307", "Authentication Testing", "Test password policy (complexity, length, history)", "Medium", "P2"),
    ("WA-OTG-308", "Authentication Testing", "Test password reset / forgot password", "High", "P1"),
    ("WA-OTG-309", "Authentication Testing", "Test password change (old password required?)", "Medium", "P2"),
    ("WA-OTG-310", "Authentication Testing", "Test multi-factor authentication (bypass attempts)", "High", "P1"),
    ("WA-OTG-311", "Authorization Testing", "Test directory traversal / file include", "High", "P1"),
    ("WA-OTG-312", "Authorization Testing", "Test bypassing authorization schema (force browse)", "Critical", "P1"),
    ("WA-OTG-313", "Authorization Testing", "Test privilege escalation (horizontal + vertical)", "Critical", "P1"),
    ("WA-OTG-314", "Authorization Testing", "Test insecure direct object references (IDOR)", "High", "P1"),
    ("WA-OTG-315", "Session Management Testing", "Test session management schema (token analysis)", "High", "P1"),
    ("WA-OTG-316", "Session Management Testing", "Test cookie attributes (Secure, HttpOnly, SameSite, Path)", "Medium", "P2"),
    ("WA-OTG-317", "Session Management Testing", "Test session fixation (token recycled after login)", "High", "P1"),
    ("WA-OTG-318", "Session Management Testing", "Test exposed session variables (in URL, logs)", "Medium", "P2"),
    ("WA-OTG-319", "Session Management Testing", "Test CSRF protection (token validation, SameSite)", "High", "P1"),
    ("WA-OTG-320", "Session Management Testing", "Test logout functionality (server-side session invalidation)", "High", "P1"),
    ("WA-OTG-321", "Session Management Testing", "Test session timeout (idle + absolute)", "Medium", "P2"),
    ("WA-OTG-322", "Session Management Testing", "Test session puzzling / overloading", "Medium", "P2"),
    ("WA-OTG-323", "Session Management Testing", "Test session hijacking (token theft via XSS/MitM)", "High", "P1"),
    ("WA-OTG-324", "Input Validation Testing", "Test reflected XSS", "High", "P1"),
    ("WA-OTG-325", "Input Validation Testing", "Test stored XSS", "High", "P1"),
    ("WA-OTG-326", "Input Validation Testing", "Test HTTP verb tampering", "Medium", "P2"),
    ("WA-OTG-327", "Input Validation Testing", "Test HTTP parameter pollution (HPP)", "Medium", "P2"),
    ("WA-OTG-328", "Input Validation Testing", "Test SQL injection", "Critical", "P1"),
    ("WA-OTG-329", "Input Validation Testing", "Test LDAP injection", "High", "P1"),
    ("WA-OTG-330", "Input Validation Testing", "Test XML injection / XXE", "High", "P1"),
    ("WA-OTG-331", "Input Validation Testing", "Test SSI injection", "High", "P1"),
    ("WA-OTG-332", "Input Validation Testing", "Test XPath injection", "High", "P1"),
    ("WA-OTG-333", "Input Validation Testing", "Test IMAP/SMTP injection", "High", "P1"),
    ("WA-OTG-334", "Input Validation Testing", "Test code injection", "Critical", "P1"),
    ("WA-OTG-335", "Input Validation Testing", "Test OS command injection", "Critical", "P1"),
    ("WA-OTG-336", "Input Validation Testing", "Test format string injection", "High", "P1"),
    ("WA-OTG-337", "Input Validation Testing", "Test incubated / second-order injection", "High", "P1"),
    ("WA-OTG-338", "Input Validation Testing", "Test HTTP splitting / smuggling", "High", "P1"),
    ("WA-OTG-339", "Input Validation Testing", "Test template injection (SSTI)", "Critical", "P1"),
    ("WA-OTG-340", "Error Handling", "Test improper error handling (stack traces / debug info)", "Medium", "P2"),
    ("WA-OTG-341", "Error Handling", "Test error code disclosure (different HTTP error codes leak info)", "Low", "P3"),
    ("WA-OTG-342", "Weak Cryptography", "Test weak SSL/TLS config (SSLv3, TLS 1.0, weak ciphers)", "High", "P1"),
    ("WA-OTG-343", "Weak Cryptography", "Test insecure padding (POODLE, BEAST, LUCKY13)", "High", "P1"),
    ("WA-OTG-344", "Weak Cryptography", "Test encryption strength of sensitive data at rest", "High", "P1"),
    ("WA-OTG-345", "Weak Cryptography", "Test data encryption in transit (clear-text credentials)", "High", "P1"),
    ("WA-OTG-346", "Business Logic Testing", "Test business logic data validation", "High", "P1"),
    ("WA-OTG-347", "Business Logic Testing", "Test ability to forge requests", "High", "P1"),
    ("WA-OTG-348", "Business Logic Testing", "Test integrity checks (tamper-evident controls)", "High", "P1"),
    ("WA-OTG-349", "Business Logic Testing", "Test process timing (race conditions)", "High", "P1"),
    ("WA-OTG-350", "Business Logic Testing", "Test function usage limits (replay/reuse attacks)", "Medium", "P2"),
    ("WA-OTG-351", "Business Logic Testing", "Test workflow circumvention", "High", "P1"),
    ("WA-OTG-352", "Business Logic Testing", "Test defense against application misuse", "Medium", "P2"),
    ("WA-OTG-353", "Business Logic Testing", "Test upload of unexpected file types", "High", "P1"),
    ("WA-OTG-354", "Business Logic Testing", "Test upload of malicious files", "Critical", "P1"),
    ("WA-OTG-355", "Client-Side Testing", "Test DOM-based XSS", "High", "P1"),
    ("WA-OTG-356", "Client-Side Testing", "Test JavaScript execution", "High", "P1"),
    ("WA-OTG-357", "Client-Side Testing", "Test HTML injection", "Medium", "P2"),
    ("WA-OTG-358", "Client-Side Testing", "Test client-side URL redirect (open redirect)", "Medium", "P2"),
    ("WA-OTG-359", "Client-Side Testing", "Test CSS injection", "Medium", "P2"),
    ("WA-OTG-360", "Client-Side Testing", "Test client-side resource manipulation", "Medium", "P2"),
    ("WA-OTG-361", "Client-Side Testing", "Test cross-origin resource sharing (CORS)", "High", "P1"),
    ("WA-OTG-362", "Client-Side Testing", "Test cross-site flashing", "Medium", "P2"),
    ("WA-OTG-363", "Client-Side Testing", "Test clickjacking (X-Frame-Options / CSP frame-ancestors)", "Medium", "P2"),
    ("WA-OTG-364", "Client-Side Testing", "Test WebSockets security", "High", "P1"),
    ("WA-OTG-365", "Client-Side Testing", "Test web messaging (postMessage security)", "High", "P1"),
    ("WA-OTG-366", "Client-Side Testing", "Test local storage / sessionStorage for sensitive data", "Medium", "P2"),
    ("WA-LLM-367", "Prompt Injection", "LLM01 \u2014 Direct prompt injection (override system instructions)", "Critical", "P1"),
    ("WA-LLM-368", "Prompt Injection", "LLM01 \u2014 Indirect prompt injection via external content", "Critical", "P1"),
    ("WA-LLM-369", "Prompt Injection", "LLM01 \u2014 Jailbreak via role-play / fictional framing", "High", "P1"),
    ("WA-LLM-370", "Prompt Injection", "LLM01 \u2014 Multi-turn injection (across conversation turns)", "High", "P1"),
    ("WA-LLM-371", "Insecure Output Handling", "LLM02 \u2014 XSS via LLM output rendered in browser", "High", "P1"),
    ("WA-LLM-372", "Insecure Output Handling", "LLM02 \u2014 SQL injection via LLM-generated queries", "Critical", "P1"),
    ("WA-LLM-373", "Insecure Output Handling", "LLM02 \u2014 Code injection via LLM output executed server-side", "Critical", "P1"),
    ("WA-LLM-374", "Training Data Poisoning", "LLM03 \u2014 Extract training data / PII memorisation", "High", "P1"),
    ("WA-LLM-375", "Training Data Poisoning", "LLM03 \u2014 Probe for biased/backdoored outputs", "Medium", "P2"),
    ("WA-LLM-376", "Model Denial of Service", "LLM04 \u2014 Resource exhaustion via recursive/complex prompts", "Medium", "P2"),
    ("WA-LLM-377", "Model Denial of Service", "LLM04 \u2014 Context window flooding (DoS via large inputs)", "Medium", "P2"),
    ("WA-LLM-378", "Supply Chain Vulnerabilities", "LLM05 \u2014 Verify model provenance (signed model, hash check)", "High", "P1"),
    ("WA-LLM-379", "Supply Chain Vulnerabilities", "LLM05 \u2014 Third-party plugin/tool audit", "High", "P1"),
    ("WA-LLM-380", "Sensitive Information Disclosure", "LLM06 \u2014 Extract PII from LLM responses", "High", "P1"),
    ("WA-LLM-381", "Sensitive Information Disclosure", "LLM06 \u2014 System prompt extraction via probing", "High", "P1"),
    ("WA-LLM-382", "Sensitive Information Disclosure", "LLM06 \u2014 API key / secret extraction from model output", "Critical", "P1"),
    ("WA-LLM-383", "Insecure Plugin Design", "LLM07 \u2014 Plugin over-permission (access beyond scope)", "High", "P1"),
    ("WA-LLM-384", "Insecure Plugin Design", "LLM07 \u2014 Plugin input validation bypass", "High", "P1"),
    ("WA-LLM-385", "Insecure Plugin Design", "LLM07 \u2014 Chained plugin exploitation (multi-step tool abuse)", "High", "P1"),
    ("WA-LLM-386", "Excessive Agency", "LLM08 \u2014 LLM can perform unauthorized actions (write/delete)", "Critical", "P1"),
    ("WA-LLM-387", "Excessive Agency", "LLM08 \u2014 Identify overprivileged tool/API integrations", "High", "P1"),
    ("WA-LLM-388", "Overreliance on LLM Output", "LLM09 \u2014 Test for hallucinated content with security impact", "Medium", "P2"),
    ("WA-LLM-389", "Overreliance on LLM Output", "LLM09 \u2014 Test code generated by LLM for security vulnerabilities", "High", "P1"),
    ("WA-LLM-390", "Model Theft", "LLM10 \u2014 Model extraction via API probing / query attacks", "High", "P1"),
    ("WA-LLM-391", "Model Theft", "LLM10 \u2014 Membership inference attack", "Medium", "P2"),
    ("WA-HDR-392", "HTTP Security Headers", "Content-Security-Policy present and strict", "Medium", "P2"),
    ("WA-HDR-393", "HTTP Security Headers", "X-Frame-Options: SAMEORIGIN or DENY present", "Medium", "P2"),
    ("WA-HDR-394", "HTTP Security Headers", "X-Content-Type-Options: nosniff present", "Low", "P3"),
    ("WA-HDR-395", "HTTP Security Headers", "Strict-Transport-Security (HSTS) properly configured", "Medium", "P2"),
    ("WA-HDR-396", "HTTP Security Headers", "Referrer-Policy header present", "Low", "P3"),
    ("WA-HDR-397", "HTTP Security Headers", "Cache-Control: no-store on authenticated/sensitive pages", "Medium", "P2"),
    ("WA-HDR-398", "HTTP Security Headers", "Permissions-Policy restricts sensitive browser APIs", "Low", "P3"),
    ("WA-HDR-399", "HTTP Security Headers", "HTTPS enforced \u2014 HTTP redirects to HTTPS", "High", "P1"),
    ("WA-HDR-400", "HTTP Security Headers", "Verbose error messages / stack traces on 4xx/5xx", "Medium", "P2"),
    ("WA-HDR-401", "HTTP Security Headers", "Server version disclosure in response headers", "Low", "P3"),
    ("WA-TLS-402", "SSL / TLS", "SSL/TLS scan \u2014 grade and cipher strength", "High", "P1"),
    ("WA-TLS-403", "SSL / TLS", "SSLv2, SSLv3, TLSv1.0 disabled", "High", "P1"),
    ("WA-TLS-404", "SSL / TLS", "No weak cipher suites (RC4, DES, NULL, EXPORT)", "High", "P1"),
    ("WA-TLS-405", "SSL / TLS", "Certificate key strength >= 2048-bit RSA / 256-bit ECC", "Medium", "P2"),
    ("WA-TLS-406", "SSL / TLS", "Certificate uses SHA-256+ signature algorithm", "Medium", "P2"),
    ("WA-TLS-407", "SSL / TLS", "Certificate chain complete \u2014 no missing intermediates", "Medium", "P2"),
    ("WA-TLS-408", "SSL / TLS", "HSTS preload list configured", "Medium", "P2"),
    ("WA-TLS-409", "SSL / TLS", "WebSocket endpoints use WSS not WS", "High", "P1"),
    ("WA-MAIL-410", "Email Security", "SPF record present and uses hard fail (-all)", "Medium", "P2"),
    ("WA-MAIL-411", "Email Security", "DMARC policy configured (reject or quarantine)", "Medium", "P2"),
    ("WA-MAIL-412", "Email Security", "DKIM signing configured and valid", "Medium", "P2"),
    ("WA-MAIL-413", "Email Security", "Email spoofing possible if SPF/DMARC absent or weak", "High", "P1"),
    ("WA-SCAN-414", "Scan Tool Analysis", "Burp Suite active scan \u2014 triage all reported findings", "High", "P1"),
    ("WA-SCAN-415", "Scan Tool Analysis", "Nikto scan \u2014 dangerous files, outdated software, misconfigs", "Medium", "P2"),
    ("WA-SCAN-416", "Scan Tool Analysis", "Nuclei \u2014 run CVE, vulnerability and misconfiguration templates", "High", "P1"),
    ("WA-SCAN-417", "Scan Tool Analysis", "SQLMap \u2014 systematic injection testing on all parameters", "High", "P1"),
    ("WA-SCAN-418", "Scan Tool Analysis", "Vulnerable JS libraries \u2014 retire.js / npm audit", "Medium", "P2"),
    ("WA-LOG-419", "Insufficient Logging & Monitoring", "Failed login attempts not logged or triggering lockout", "Medium", "P2"),
    ("WA-LOG-420", "Insufficient Logging & Monitoring", "Sensitive operations not captured in audit log", "Medium", "P2"),
    ("WA-LOG-421", "Insufficient Logging & Monitoring", "No alerting on automated scanning or enumeration", "Medium", "P2"),
]
MASTER_CHECKLIST_BY_ID = {row[0]: row for row in MASTER_CHECKLIST}

# The ~77 IDs checklist_auto_scan.py's add() calls actually use (see its
# own module docstring) - re-extract any time the engine's checks change:
#   grep -oE '"WA-[A-Z0-9]+-[0-9]+"' checklist_auto_scan.py | sort -u
# Used to flag "(automated - already covered by Run All Tests)" in the
# Log Finding dialog's ID picker, so logging one manually is a deliberate
# choice (e.g. overriding/annotating an automated result), not confusion
# about which IDs still need manual coverage.
AUTOMATED_CHECKLIST_IDS = frozenset([
    "WA-ADV-218", "WA-ADV-219", "WA-ADV-220", "WA-ADV-221", "WA-ADV-222", "WA-ADV-223", "WA-ADV-224", "WA-CS-158",
    "WA-CS-159", "WA-CS-160", "WA-CS-161", "WA-CS-162", "WA-CS-163", "WA-CS-164", "WA-CS-165", "WA-HDR-392",
    "WA-HDR-393", "WA-HDR-394", "WA-HDR-395", "WA-HDR-396", "WA-HDR-397", "WA-HDR-398", "WA-HDR-399", "WA-HDR-400",
    "WA-HDR-401", "WA-MAIL-410", "WA-MAIL-411", "WA-MAIL-412", "WA-MAIL-413", "WA-OTG-273", "WA-OTG-274", "WA-OTG-275",
    "WA-OTG-276", "WA-OTG-277", "WA-OTG-278", "WA-OTG-279", "WA-OTG-280", "WA-OTG-281", "WA-OTG-282", "WA-OTG-283",
    "WA-OTG-284", "WA-OTG-285", "WA-OTG-286", "WA-OTG-287", "WA-OTG-288", "WA-OTG-289", "WA-OTG-290", "WA-OTG-291",
    "WA-OTG-292", "WA-OTG-293", "WA-OTG-294", "WA-OTG-312", "WA-OTG-314", "WA-OTG-315", "WA-OTG-316", "WA-OTG-317",
    "WA-OTG-318", "WA-OTG-319", "WA-OTG-320", "WA-OTG-321", "WA-OTG-322", "WA-OTG-323", "WA-OTG-366", "WA-SS-055",
    "WA-SS-056", "WA-SS-057", "WA-SS-058", "WA-SS-059", "WA-SS-071", "WA-TLS-402", "WA-TLS-403", "WA-TLS-404",
    "WA-TLS-405", "WA-TLS-406", "WA-TLS-407", "WA-TLS-408", "WA-TLS-409",
])

# Best-effort OWASP Top 10 (2021) mapping for the master checklist's
# other ~44 mappable categories (on top of the 13 automated ones already
# mapped above) - same "illustrative, not official" caveat applies.
# Categories intentionally left OUT (fall into OWASP_OTHER_KEY instead):
# the OWASP-Top-10-for-LLM-specific ones (Web LLM Attacks, Prompt
# Injection, Insecure Output Handling, Insecure Plugin Design, Training
# Data Poisoning, Model Denial of Service, Excessive Agency, Overreliance
# on LLM Output, Model Theft - these belong to a DIFFERENT OWASP list,
# forcing them into the web Top 10 would misclassify them) and pure
# testing-methodology labels that aren't a vulnerability class on their
# own (API Testing, Scan Tool Analysis, Essential Skills).
OWASP_CATEGORY_MAP.update({
    "SQL Injection": "A03",
    "Cross-Site Scripting (XSS)": "A03",
    "Command Injection": "A03",
    "NoSQL Injection": "A03",
    "XXE Injection": "A05",
    "Server-Side Template Injection": "A03",
    "DOM-based Vulnerabilities": "A03",
    "Prototype Pollution": "A03",
    "Path Traversal": "A01",
    "Insecure Deserialization": "A08",
    "Supply Chain Vulnerabilities": "A08",
    "Authentication": "A07",
    "Authentication Testing": "A07",
    "Identity Management": "A07",
    "OAuth 2.0": "A07",
    "JWT Attacks": "A07",
    "Business Logic": "A04",
    "Business Logic Testing": "A04",
    "Race Conditions": "A04",
    "File Upload": "A05",
    "CSRF": "A01",
    "SSRF": "A10",
    "Web Cache Poisoning": "A05",
    "Web Cache Deception": "A05",
    "Insufficient Logging & Monitoring": "A09",
    "Weak Cryptography": "A02",
    "Sensitive Information Disclosure": "A02",
    "Error Handling": "A05",
    "WebSockets": "A05",
    "GraphQL API Security": "A05",
    "Input Validation Testing": "A03",
})

# Reported directly: "when I can confirm the test XSS in repeater or
# proxy... understand how many findings have been covered" - the
# baseline category list now needs to be the FULL master checklist's
# categories, not just the 13 automatable ones, so Categories/Summary
# show every category (0-filled) whether or not anything's been logged
# against it yet - matches this feature's whole point (visualizing
# progress across all ~421 items, not just the ~77 automated ones).
KNOWN_CATEGORIES = sorted(set(row[1] for row in MASTER_CHECKLIST) | set(OWASP_CATEGORY_MAP.keys()))



# ---------------------------------------------------------------------
# Self-extracting scan engine: checklist_auto_scan.py's full source,
# base64-encoded, embedded directly in this file so the whole extension
# is ONE .py to download/install from the BApp Store / marketplace -
# no second file to lose, mismatch versions with, or have to explain
# how to co-locate. Reported directly: "make it one file instead of two
# python files so it is easy to share with burp extension marketplace
# without the dependency or need to share autoscan script separately."
#
# _materialize_engine_script() below decodes this and writes it out to a
# real .py file on disk at scan time (Jython can't execute this itself -
# see the module docstring at the top of this file for why the engine
# still runs as a separate CPython 3 subprocess) so nothing changes
# about HOW the engine runs, only about not needing a second file
# shipped/installed alongside this one.
#
# To update the bundled engine: replace checklist_auto_scan.py, then
# regenerate this constant from it (base64-encode the file). This copy
# is REV aae64b4f21 (first 10 hex chars of the source's sha256) - shown in
# the Configuration tab so it's obvious which engine build is bundled.
# REV aae64b4f21 added a QUICKCHOP_ROW|<json> stdout line to add() (in
# checklist_auto_scan.py) so a caller can stream per-row progress instead
# of waiting for the whole scan to finish - see _run_checklist_auto_scan
# below, which reads this process's stdout live instead of blocking on
# communicate().
ENGINE_SOURCE_REV = 'ca449e90a2'
_ENGINE_SOURCE_B64 = (
    "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiIKY2hlY2tsaXN0X2F1dG9fc2Nhbi5weQotLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQpBdXRvbWF0ZWQgcHJlLWNoZWNrIHNj"
    "YW5uZXIgZm9yIHRoZSBwYXJ0cyBvZiB0aGUgV1BUIG1hc3RlciBjaGVja2xpc3QKKH40MjEgaXRlbXMsIGNhdGVnb3JpZXMg"
    "bGlrZSBTUUwgSW5qZWN0aW9uIC8gWFNTIC8gQnVzaW5lc3MgTG9naWMgLyBBdXRoClRlc3RpbmcgLyBSYWNlIENvbmRpdGlv"
    "bnMgLyBldGMuKSB0aGF0IENBTiBzYWZlbHkgYmUgdmVyaWZpZWQgYnkgYQpyZWFkLW9ubHkgc2NyaXB0OiBIVFRQIHJlc3Bv"
    "bnNlIGhlYWRlcnMsIFRMUyBoYW5kc2hha2UvY2VydGlmaWNhdGUgaW5mbywKRE5TIFRYVCByZWNvcmRzIChTUEYvRE1BUkMv"
    "REtJTSksIGFuZCBhIHNtYWxsIHNldCBvZiBrbm93bi1zYWZlIEdFVC9PUFRJT05TCnByb2JlcyAocm9ib3RzLnR4dCwgY29t"
    "bW9uIGJhY2t1cC9kb3RmaWxlcywgY3Jvc3Nkb21haW4ueG1sLCBhZG1pbiBwYXRocykuCgpUaGlzIGlzIE5PVCBhIHJlcGxh"
    "Y2VtZW50IGZvciBzcWxtYXAgLyBCdXJwIC8gbnVjbGVpIC8gbWFudWFsIHRlc3RpbmcgLQp0aG9zZSBpdGVtcyBzdGlsbCBu"
    "ZWVkIHRoZSB0b29sIG5hbWVkIGluIHRoZSBjaGVja2xpc3QncyAiVG9vbHMiIGNvbHVtbiwKb3IgYSBodW1hbi4gRXZlcnkg"
    "Y2hlY2tsaXN0IGl0ZW0gdGhpcyBzY3JpcHQgZG9lcyBOT1QgdGVzdCBpcyBsaXN0ZWQgaW4KdGhlIG91dHB1dCBhcyByZXN1"
    "bHQ9TUFOVUFMIHdpdGggYSBub3RlLCBzbyBub3RoaW5nIGxvb2tzIHNpbGVudGx5CnNraXBwZWQgb3Igc2lsZW50bHkgInBh"
    "c3NlZCIuCgpERUZBVUxUIEJFSEFWSU9VUiAtIFJFQUQgVEhJUyBGSVJTVAogIEJ5IGRlZmF1bHQgZXZlcnkgVVJMIHlvdSBn"
    "aXZlIGlzIHRlc3RlZCBUV0lDRSwgYXV0b21hdGljYWxseSwgd2l0aCBubwogIGZsYWcgbmVlZGVkOgogICAgMS4gdGhlIEVY"
    "QUNUIFVSTCB5b3UgZ2F2ZSwgaW5jbHVkaW5nIGl0cyBzdWItZm9sZGVyL3BhdGggLSBlLmcuCiAgICAgICBodHRwczovLzEy"
    "Ny4wLjAuMTo0NDM0L3N1YmZvbGRlciBpcyB0ZXN0ZWQgYXMtaXMsIGFuZCBhbnkKICAgICAgIHBhdGgtYmFzZWQgcHJvYmUg"
    "KHJvYm90cy50eHQsIGJhY2t1cCBmaWxlcywgLmdpdCBleHBvc3VyZSwgYWRtaW4KICAgICAgIHBhdGhzLCBjcm9zc2RvbWFp"
    "bi54bWwsIGRlcGVuZGVuY3kgbWFuaWZlc3RzLCAuLi4pIGlzIHJ1biBVTkRFUgogICAgICAgdGhhdCBzYW1lIHN1Yi1mb2xk"
    "ZXIgKGh0dHBzOi8vMTI3LjAuMC4xOjQ0MzQvc3ViZm9sZGVyL3JvYm90cy50eHQpLgogICAgMi4gdGhlIFNJVEUgUk9PVCBv"
    "ZiB0aGF0IHNhbWUgaG9zdCAtIGh0dHBzOi8vMTI3LjAuMC4xOjQ0MzQvIC0gc2luY2UKICAgICAgIGEgbG90IG9mIHdoYXQg"
    "dGhlIGNoZWNrbGlzdCBpcyBsb29raW5nIGZvciAoc2VydmVyIGNvbmZpZywgVExTLAogICAgICAgYWRtaW4gaW50ZXJmYWNl"
    "cywgRE5TL2VtYWlsIHJlY29yZHMsIGJhY2t1cCBmaWxlcyB0aGF0IHdlcmUgbmV2ZXIKICAgICAgIG1lYW50IHRvIGJlIHJl"
    "YWNoYWJsZSkgdXN1YWxseSBsaXZlcyBhdCB0aGUgcm9vdCByZWdhcmRsZXNzIG9mCiAgICAgICB3aGljaCBwYWdlL2FwcCBw"
    "YXRoIHlvdSB3ZXJlIGdpdmVuLgogIEV2ZXJ5IHJlc3VsdCByb3cgc2F5cyB3aGljaCBvZiB0aGUgdHdvICh1cmxfcm9sZTog"
    "ImdpdmVuLXVybCIgb3IKICAic2l0ZS1yb290IikgaXQgY2FtZSBmcm9tLCBzbyBub3RoaW5nIGlzIGFtYmlndW91cyBpbiB0"
    "aGUgcmVwb3J0LiBQYXNzCiAgLS1za2lwLXJvb3QtcGFzcyBpZiB5b3Ugb25seSB3YW50IHRoZSBleGFjdCBVUkwgdGVzdGVk"
    "IGFuZCBub3QgdGhlCiAgYXV0b21hdGljIGV4dHJhIHJvb3QgcGFzcy4KCiAgRXZlcnkgcm93IHdoZXJlIGEgY2hlY2sgY2Fu"
    "J3QgYmUgdmVyaWZpZWQgYXV0b21hdGljYWxseSBhbmQgbmVlZHMgYQogIGh1bWFuL2RlZGljYXRlZCB0b29sIGlzIG1hcmtl"
    "ZCByZXN1bHQ9TUFOVUFMLCBhbmQgaXRzIGNvbW1lbnQgYWx3YXlzCiAgc3RhcnRzIHdpdGggdGhlIGZpeGVkIHBocmFzZSAi"
    "TWFudWFsIHRlc3QgcmVxdWlyZWQuIiAocGx1cyBzcGVjaWZpY3MKICBhZnRlciBpdCkgLSBzbyB5b3UgY2FuIGZpbHRlci9z"
    "ZWFyY2ggZm9yIGV4YWN0bHkgdGhhdCBwaHJhc2UgaW4gdGhlCiAgcmVwb3J0IHRvIGJ1aWxkIHlvdXIgbWFudWFsIHdvcmsg"
    "cXVldWUuCgpVU0FHRQogICMgc2luZ2xlIFVSTCAtIHRlc3RzIGJvdGggdGhlIFVSTCBpdHNlbGYgYW5kIGl0cyBzaXRlIHJv"
    "b3QgYnkgZGVmYXVsdAogIHB5dGhvbjMgY2hlY2tsaXN0X2F1dG9fc2Nhbi5weSAtLXVybCBodHRwczovLzEyNy4wLjAuMTo0"
    "NDM0L3N1YmZvbGRlcgoKICAjIGEgbGlzdCBvZiBVUkxzLCBvbmUgcGVyIGxpbmUgKCMgY29tbWVudHMgLyBibGFuayBsaW5l"
    "cyBpZ25vcmVkKSAtCiAgIyBFVkVSWSB1cmwgaW4gdGhlIGZpbGUgZ2V0cyB0aGUgc2FtZSBmdWxsIHRyZWF0bWVudCAoYm90"
    "aCBwYXNzZXMpCiAgcHl0aG9uMyBjaGVja2xpc3RfYXV0b19zY2FuLnB5IC0tdXJsLWZpbGUgdXJscy50eHQgLS1vdXQgcmVz"
    "dWx0cwoKICAjIHNlbGYtc2lnbmVkIC8gaW50ZXJuYWwgbGFiIHRhcmdldCwgbG9uZ2VyIHRpbWVvdXQKICBweXRob24zIGNo"
    "ZWNrbGlzdF9hdXRvX3NjYW4ucHkgLS11cmwgaHR0cHM6Ly8xMC4wLjAuNSAtLWluc2VjdXJlIC0tdGltZW91dCAxNQoKICAj"
    "IG9ubHkgdGVzdCB0aGUgZXhhY3QgVVJMIGdpdmVuLCBza2lwIHRoZSBhdXRvbWF0aWMgc2l0ZS1yb290IHBhc3MKICBweXRo"
    "b24zIGNoZWNrbGlzdF9hdXRvX3NjYW4ucHkgLS11cmwgaHR0cHM6Ly9leGFtcGxlLmNvbS9wb3J0YWwvIC0tc2tpcC1yb290"
    "LXBhc3MKCiAgIyBhbHNvIHJ1biB0aGUgbGlnaHQgY29tbW9uLWFkbWluLXBvcnQgc2NhbiAob2ZmIGJ5IGRlZmF1bHQsIG5v"
    "aXNpZXIpCiAgcHl0aG9uMyBjaGVja2xpc3RfYXV0b19zY2FuLnB5IC0tdXJsIGh0dHBzOi8vdGFyZ2V0LmV4YW1wbGUuY29t"
    "IC0tcG9ydC1zY2FuCgogICMgc2tpcCBhdXRvLXNjcmVlbnNob3RzIGVudGlyZWx5ICh0aGV5J3JlIG9uIGJ5IGRlZmF1bHQg"
    "Zm9yIEZBSUwgcm93cykKICBweXRob24zIGNoZWNrbGlzdF9hdXRvX3NjYW4ucHkgLS11cmwgaHR0cHM6Ly90YXJnZXQuZXhh"
    "bXBsZS5jb20gLS1zY3JlZW5zaG90IG5vbmUKCiAgIyBhbHNvIGdlbmVyYXRlIG9uZSBmb3IgUEFTUyByb3dzIChwcm9vZiBv"
    "ZiBhIGNsZWFuIGNoZWNrKSwgb3IgZm9yIGV2ZXJ5dGhpbmcKICBweXRob24zIGNoZWNrbGlzdF9hdXRvX3NjYW4ucHkgLS11"
    "cmwgaHR0cHM6Ly90YXJnZXQuZXhhbXBsZS5jb20gLS1zY3JlZW5zaG90IGZhaWwrcGFzcwogIHB5dGhvbjMgY2hlY2tsaXN0"
    "X2F1dG9fc2Nhbi5weSAtLXVybCBodHRwczovL3RhcmdldC5leGFtcGxlLmNvbSAtLXNjcmVlbnNob3QgYWxsCgpBVVRPLUdF"
    "TkVSQVRFRCAiRVZJREVOQ0UgU0NSRUVOU0hPVFMiIC0gbm8gbWFudWFsIHNjcmVlbnNob3R0aW5nIG5lZWRlZAogIFRha2lu"
    "ZyBhIHNjcmVlbnNob3QgYnkgaGFuZCBmb3IgZXZlcnkgb25lIG9mIH43NyBhdXRvbWF0ZWQgY2hlY2tzIHgKICBob3dldmVy"
    "IG1hbnkgVVJMcyB5b3UncmUgdGVzdGluZyBkb2Vzbid0IHNjYWxlLiBTbyBieSBkZWZhdWx0LCBldmVyeQogIEZBSUwgcm93"
    "IGdldHMgaXRzIG93biBhdXRvLWdlbmVyYXRlZCBldmlkZW5jZSBjYXJkIC0gYSByZW5kZXJlZCBQTkcKICBzaG93aW5nIHRo"
    "ZSBVUkwsIGNoZWNrbGlzdCBJRC90ZXN0IG5hbWUsIGNhdGVnb3J5L3NldmVyaXR5LCB0aGUgZXhhY3QKICBldmlkZW5jZSB0"
    "ZXh0LCBhbmQgdGltZXN0YW1wIC0gdGhlIHNhbWUgaW5mb3JtYXRpb24geW91J2Qgb3RoZXJ3aXNlIGJlCiAgc2NyZWVuc2hv"
    "dHRpbmcgZnJvbSBhIHRlcm1pbmFsIGJ5IGhhbmQuIEl0J3MgYSByZW5kZXJlZCBzdW1tYXJ5IGNhcmQsCiAgTk9UIGEgbGl2"
    "ZSBicm93c2VyIHNjcmVlbnNob3Qgb2YgdGhlIHRhcmdldCBwYWdlIC0gaXQncyBtZWFudCB0byBzdGFuZAogIGluIGFzIHRo"
    "ZSAiQXJ0ZWZhY3RzIiBldmlkZW5jZSBhIHJlcG9ydCBuZWVkcyBmb3IgYW4gYXV0b21hdGVkIGNoZWNrLAogIG5vdCB0byBy"
    "ZXBsYWNlIGFuIGFjdHVhbCBicm93c2VyIHNjcmVlbnNob3Qgb2YgYW4gZXhwbG9pdGVkIFhTUy9TUUxpL2V0Yy4KICBOZWVk"
    "cyBQaWxsb3cgKHBpcDMgaW5zdGFsbCBQaWxsb3cpOyBzY2FubmluZyBzdGlsbCBjb21wbGV0ZXMgbm9ybWFsbHkKICB3aXRo"
    "b3V0IGl0LCBqdXN0IHdpdGhvdXQgc2NyZWVuc2hvdHMgKGEgd2FybmluZyBpcyBwcmludGVkIG9uY2UpLgogIENvbnRyb2wg"
    "d2hpY2ggcm93cyBnZXQgb25lIHdpdGggLS1zY3JlZW5zaG90IHtub25lLGZhaWwsZmFpbCtwYXNzLGFsbH0KICAoZGVmYXVs"
    "dDogZmFpbCkuCgogIFdoZXJlIHRoZSBzY3JlZW5zaG90cyBlbmQgdXA6CiAgICAtIEVtYmVkZGVkIGFzIGJhc2U2NCBQTkcg"
    "aW4gPG91dD4uanNvbiAoZmllbGQ6IGV2aWRlbmNlX2ltYWdlX2Jhc2U2NCkKICAgICAgb24gZXZlcnkgcm93IHRoYXQgZ290"
    "IG9uZSAtIE5PVCB3cml0dGVuIHRvIC5jc3YgKGtlZXBzIGl0IHJlYWRhYmxlOwogICAgICAuY3N2IGluc3RlYWQgZ2V0cyBh"
    "IFNjcmVlbnNob3Q6IHllcy9ubyBjb2x1bW4pLgogICAgLSBBbHNvIGVtYmVkZGVkIGFzIHJlYWwsIHZpZXdhYmxlIGltYWdl"
    "cyBkaXJlY3RseSBpbiA8b3V0Pi54bHN4IG9uIGEKICAgICAgZGVkaWNhdGVkICJFdmlkZW5jZSIgc2hlZXQgKG5lZWRzIFBp"
    "bGxvdyBvbmx5IC0geGxzeHdyaXRlciBlbWJlZHMKICAgICAgd2hhdGV2ZXIgaW1hZ2UgYnl0ZXMgaXQncyBnaXZlbiBlaXRo"
    "ZXIgd2F5KS4KICAgIC0gSlVNUCBIT1NUIC8gUkVTVFJJQ1RFRC1DT1BZIFdPUktGTE9XOiBpZiB5b3UncmUgcnVubmluZyB0"
    "aGlzIG9uIGEKICAgICAganVtcCBob3N0IHdoZXJlIG9ubHkgY2xpcGJvYXJkIHRleHQgY29tZXMgYmFjayB0byB5b3VyIHJl"
    "YWwgbWFjaGluZQogICAgICAobm8gZmlsZSB0cmFuc2ZlciksIGNvcHkgdGhlIHByaW50ZWQgSlNPTiAob3IganVzdCBwYXN0"
    "ZSB0aGUKICAgICAgcmVsZXZhbnQgcm93J3MgZXZpZGVuY2VfaW1hZ2VfYmFzZTY0IHZhbHVlKSBiYWNrIHRvIHlvdXIgb3du"
    "CiAgICAgIG1hY2hpbmUgYW5kIHJ1biB0aGUgY29tcGFuaW9uIHNjcmlwdCB0byB0dXJuIGl0IGJhY2sgaW50byByZWFsCiAg"
    "ICAgIC5wbmcgZmlsZXM6CiAgICAgICAgcHl0aG9uMyBleHRyYWN0X2V2aWRlbmNlX2ltYWdlcy5weSByZXN1bHRzLmpzb24g"
    "LS1vdXQgc2NyZWVuc2hvdHMvCiAgICAgIFNlZSBleHRyYWN0X2V2aWRlbmNlX2ltYWdlcy5weSdzIG93biAtLWhlbHAgZm9y"
    "IGRldGFpbHM7IGl0IHNoaXBzCiAgICAgIGFsb25nc2lkZSB0aGlzIHNjcmlwdC4KCk9VVFBVVAogIEV2ZXJ5IHJ1biB3cml0"
    "ZXMgVEhSRUUgZmlsZXMgZnJvbSB0aGUgc2FtZSByZXN1bHRzIChubyBmbGFnIG5lZWRlZCk6CiAgPG91dD4uY3N2LCA8b3V0"
    "Pi5qc29uLCBhbmQgPG91dD4ueGxzeCAtIGEgY29sb3ItY29kZWQsIGZpbHRlcmFibGUKICB3b3JrYm9vayAoUEFTUy9GQUlM"
    "L01BTlVBTC9JTkZPL0VSUk9SIGhpZ2hsaWdodGVkLCBhdXRvZmlsdGVyICsgZnJvemVuCiAgaGVhZGVyIHJvdykgcGx1cyBh"
    "IFN1bW1hcnkgc2hlZXQsIHNvIGl0J3MgZWFzeSB0byBuYXZpZ2F0ZSBhcyBhCiAgdHJhY2tpbmcgbGlzdC4gPG91dD4gZGVm"
    "YXVsdHMgdG8gY2hlY2tsaXN0X3NjYW5fPHRpbWVzdGFtcD4uIFRoZSAueGxzeAogIG5lZWRzICJwYW5kYXMiIGFuZCAieGxz"
    "eHdyaXRlciIgKHBpcDMgaW5zdGFsbCBwYW5kYXMgeGxzeHdyaXRlcik7IGlmCiAgZWl0aGVyIGlzIG1pc3NpbmcgdGhlIHNj"
    "cmlwdCBzdGlsbCB3cml0ZXMgLmNzdi8uanNvbiBhbmQganVzdCBza2lwcwogIC54bHN4IHdpdGggYSBub3RlLgoKUkVBTCBD"
    "T01NQU5ELUxJTkUgVE9PTCBJTlRFR1JBVElPTiAoY3VybCAvIG5tYXAgLyBzc2x5emUgLyBzc2xzY2FuIC8gdGVzdHNzbC5z"
    "aCkKICBBdXRvLWRldGVjdGVkIHZpYSBQQVRILCBubyBmbGFnL2NvbmZpZyBuZWVkZWQgLSBpZiBhIHRvb2wgaXMgaW5zdGFs"
    "bGVkLAogIGl0J3MgdXNlZCBhdXRvbWF0aWNhbGx5IHRvIGNhcHR1cmUgUkVBTCBjb21tYW5kIG91dHB1dCBhcyBldmlkZW5j"
    "ZToKICAgIC0gY3VybCBydW5zIG9uY2UgcGVyIEhUVFAgU2VjdXJpdHkgSGVhZGVycyBjaGVjayAoV0EtSERSLTM5Mi4uMzk4"
    "LDQwMSkKICAgICAgYW5kIGl0cyBleGFjdCAiJCBjdXJsIC4uLiIgY29tbWFuZCArIHJhdyByZXNwb25zZSBoZWFkZXJzIGlz"
    "CiAgICAgIGFwcGVuZGVkIHRvIHRoZSBldmlkZW5jZSB0ZXh0LgogICAgLSBUaGUgZmlyc3Qgb2Ygbm1hcCAoLS1zY3JpcHQg"
    "c3NsLWVudW0tY2lwaGVycyksIHNzbHl6ZSwgc3Nsc2Nhbiwgb3IKICAgICAgdGVzdHNzbC5zaCBmb3VuZCBvbiBQQVRIIHJ1"
    "bnMgb25jZSBwZXIgSFRUUFMgdGFyZ2V0IGFuZCBpdHMgb3V0cHV0CiAgICAgIGJvdGggYmVjb21lcyB0aGUgZXZpZGVuY2Ug"
    "Zm9yIFdBLVRMUy00MDIvNDA0IEFORCBkcml2ZXMgYSByZWFsCiAgICAgIFBBU1MvRkFJTCBkZXRlcm1pbmF0aW9uICh3ZWFr"
    "LWNpcGhlci93ZWFrLXByb3RvY29sIHBhdHRlcm4KICAgICAgbWF0Y2hpbmcpIGluc3RlYWQgb2YgbGVhdmluZyB0aG9zZSB0"
    "d28gTUFOVUFMLgogIFJvd3MgY2FycnlpbmcgdGhpcyBraW5kIG9mIHJlYWwgY29tbWFuZCBvdXRwdXQgZ2V0IGEgVEVSTUlO"
    "QUwtU1RZTEUKICBldmlkZW5jZSBzY3JlZW5zaG90IChibGFjayBiYWNrZ3JvdW5kLCBtb25vc3BhY2UpIGluc3RlYWQgb2Yg"
    "dGhlIHVzdWFsCiAgc3VtbWFyeSBjYXJkLCBzbyB0aGUgc2NyZWVuc2hvdCBpdHNlbGYgbG9va3MgbGlrZSBhbiBhY3R1YWwg"
    "dGVybWluYWwKICBjYXB0dXJlIG9mIHRoZSBjb21tYW5kIHRoYXQgcmFuLiBQYXNzIC0tbm8tY2xpLXRvb2xzIHRvIGRpc2Fi"
    "bGUgYWxsIG9mCiAgdGhpcyBhbmQgdXNlIHRoZSBwdXJlLVB5dGhvbi9NQU5VQUwgZmFsbGJhY2sgb25seSAoZS5nLiBmb3Ig"
    "c3BlZWQsIG9yIGlmCiAgeW91IGRvbid0IHdhbnQgc3VicHJvY2Vzc2VzIHNoZWxsZWQgb3V0IGF0IGFsbCkuCgpBVVRIRU5U"
    "SUNBVEVEIFNDQU5OSU5HIEFORCBBQ0NFU1MgQ09OVFJPTCBURVNUSU5HIChvcHQtaW4sIC0tY29va2llIC8gLS1jb29raWUy"
    "KQogIFRoaXMgc2NyaXB0IE5FVkVSIGxvZ3MgaW4sIGJydXRlLWZvcmNlcywgZ3Vlc3Nlcywgb3IgaGFydmVzdHMKICBjcmVk"
    "ZW50aWFscyBhbnl3aGVyZSAtIGl0IGhhcyBubyBsb2dpbiBmbG93IGF0IGFsbC4gV2hhdCBpdCBDQU4gZG8sIGlmCiAgeW91"
    "IGhhbmQgaXQgYSBzZXNzaW9uIENvb2tpZSBoZWFkZXIgdmFsdWUgeW91IGFscmVhZHkgb2J0YWluZWQgeW91cnNlbGYKICBi"
    "eSBsb2dnaW5nIGluIChlLmcuIGNvcGllZCBmcm9tIHlvdXIgYnJvd3NlcidzIGRldiB0b29scywgb3IgYSBCdXJwCiAgUHJv"
    "eHkgaGlzdG9yeSBlbnRyeSksIGlzIHVzZSB0aGF0IHByZS1hdXRoZW50aWNhdGVkIHNlc3Npb24gdG8gcnVuCiAgRVZFUlkg"
    "Y2hlY2sgaW4gdGhlIHN1aXRlIGFzIHRoYXQgbG9nZ2VkLWluIHVzZXIsIGFuZCBhdXRvbWF0aWNhbGx5CiAgZXh0ZW5kIGNv"
    "dmVyYWdlIGFzIGZvbGxvd3MgLSB0aGlzIGlzICJhdXRvIGNoZWNrIjogcGFzcyBvbmUgY29va2llIGFuZAogIGl0IGNvdmVy"
    "cyBldmVyeXRoaW5nIGEgc2luZ2xlIHNlc3Npb24gY2FuIHRlc3Q7IGFkZCBhIHNlY29uZCBhbmQgaXQKICBjb3ZlcnMgdGhl"
    "IHR3by1hY2NvdW50IGNoZWNrcyB0b28sIHdpdGggbm8gZXh0cmEgZmxhZ3MgbmVlZGVkOgogICAgLSAtLWNvb2tpZSBhbG9u"
    "ZTogZXZlcnkgb25lIG9mIHRoZSB+MTAwIGNoZWNrcyBydW5zIGF1dGhlbnRpY2F0ZWQsCiAgICAgIFBMVVMgV0EtT1RHLTMx"
    "MiAoYXV0aCBieXBhc3MgLyBmb3JjZS1icm93c2UpIGdldHMgcmVhbCB0ZXN0aW5nIC0KICAgICAgY29tcGFyZXMgdGhlIFNB"
    "TUUgdXJsIHdpdGggbm8gc2Vzc2lvbiBhdCBhbGwgdnMuIHdpdGggLS1jb29raWUncwogICAgICBzZXNzaW9uOyBieXRlLWlk"
    "ZW50aWNhbCByZXNwb25zZXMgbWVhbiB0aGUgcGFnZSBkb2Vzbid0IGFjdHVhbGx5CiAgICAgIHJlcXVpcmUgbG9naW4uCiAg"
    "ICAtIC0tY29va2llICsgLS1jb29raWUyIChhIFNFQ09ORCwgRElGRkVSRU5UIGFjY291bnQncyBvd24gc2Vzc2lvbik6CiAg"
    "ICAgIEFMU08gZ2V0cyBXQS1TUy0wNzEgKGhvcml6b250YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24pIGFuZAogICAgICBXQS1P"
    "VEctMzE0IChJRE9SKSByZWFsIHRlc3RpbmcgLSBjb21wYXJlcyB3aGF0IGFjY291bnQgMSAoLS1jb29raWUpCiAgICAgIGFu"
    "ZCBhY2NvdW50IDIgKC0tY29va2llMikgZWFjaCBzZWUgYXQgdGhlIHNhbWUgVVJMLiBCeXRlLWlkZW50aWNhbAogICAgICBy"
    "ZXNwb25zZXMgYXJlIHJlcG9ydGVkIGFzIE1BTlVBTCAobm90IGFuIGF1dG9tYXRpYyBGQUlMKSBzaW5jZSBvbmx5CiAgICAg"
    "IGEgaHVtYW4gY2FuIGNvbmZpcm0gdGhlIFVSTC9yZXNvdXJjZSBpcyBhY3R1YWxseSBtZWFudCB0byBiZQogICAgICBhY2Nv"
    "dW50LXNwZWNpZmljIHJhdGhlciB0aGFuIHNoYXJlZC9wdWJsaWMuCiAgICAtIEEgY292ZXJhZ2UgcmVwb3J0IHByaW50cyBi"
    "ZWZvcmUgc2Nhbm5pbmcgc3RhcnRzICh3aGF0IHdpbGwgYmUKICAgICAgYXR0ZW1wdGVkKSBhbmQgYWdhaW4gaW4gdGhlIGZp"
    "bmFsIHN1bW1hcnkgKHdoYXQgd2FzIGFjdHVhbGx5CiAgICAgIHJlY29yZGVkKSwgc28geW91IGFsd2F5cyBrbm93IGV4YWN0"
    "bHkgd2hpY2ggY2hlY2tsaXN0IElEcyBnb3QgcmVhbAogICAgICB0ZXN0aW5nIHZzLiBzdGF5ZWQgTUFOVUFMIGZvciB0aGUg"
    "cnVuIHlvdSBqdXN0IGRpZC4KICAtLWFjY291bnQxLWNvb2tpZS8tLWFjY291bnQyLWNvb2tpZS8tLWFjY291bnQxLWxhYmVs"
    "Ly0tYWNjb3VudDItbGFiZWwKICBzdGlsbCB3b3JrIGV4YWN0bHkgYXMgYmVmb3JlIChhbmQgLS1jb29raWUvLS1jb29raWUy"
    "IGF1dG8tcG9wdWxhdGUgdGhlbQogIHVubGVzcyB5b3Ugc2V0IHRob3NlIGV4cGxpY2l0bHkpIC0gLS1jb29raWUvLS1jb29r"
    "aWUyIGFyZSBqdXN0IHRoZQogIHNpbXBsZXIgbmFtZXMgdG8gcmVhY2ggZm9yLCBzaW5jZSB0aGV5IGFsc28gYXV0aGVudGlj"
    "YXRlIGV2ZXJ5dGhpbmcKICBlbHNlIGluIHRoZSBzdWl0ZS4gVGhlIGNvb2tpZSBWQUxVRVMgdGhlbXNlbHZlcyBhcmUgbmV2"
    "ZXIgd3JpdHRlbiB0bwogIGV2aWRlbmNlL0pTT04vQ1NWL3NjcmVlbnNob3RzIC0gb25seSBzdGF0dXMgY29kZXMsIGJ5dGUg"
    "bGVuZ3RocywgYW5kCiAgdGhlIHBhc3MvZmFpbCBjb21wYXJpc29uIG91dGNvbWUgYXJlLgoKUkVRVUlSRU1FTlRTCiAgUHl0"
    "aG9uIDMuNyssIHN0YW5kYXJkIGxpYnJhcnkgb25seSBmb3IgdGhlIENTVi9KU09OIHNjYW4gaXRzZWxmLiBVc2VzCiAgdGhl"
    "IHN5c3RlbSAib3BlbnNzbCIgYW5kICJuc2xvb2t1cCIgY29tbWFuZC1saW5lIHRvb2xzIGlmIHByZXNlbnQgKGJvdGgKICBz"
    "aGlwIHdpdGggbWFjT1MvTGludXg7IG5zbG9va3VwIGFsc28gc2hpcHMgd2l0aCBXaW5kb3dzLCBidXQgb24gV2luZG93cwog"
    "IHVzZSB0aGUgUG93ZXJTaGVsbCBzY3JpcHQgaW5zdGVhZCAtIENoZWNrbGlzdF9BdXRvU2Nhbi5wczEgLSB3aGljaCB1c2Vz"
    "CiAgbmF0aXZlIC5ORVQvUG93ZXJTaGVsbCBjbWRsZXRzIGFuZCBuZWVkcyBubyBleHRlcm5hbCB0b29scyBhdCBhbGwpIHRv"
    "CiAgZW5yaWNoIHRoZSBUTFMgYW5kIEVtYWlsIFNlY3VyaXR5IGNoZWNrcywgYW5kICJjdXJsIi8ibm1hcCIvInNzbHl6ZSIv"
    "CiAgInNzbHNjYW4iLyJ0ZXN0c3NsLnNoIiBpZiBwcmVzZW50IHRvIGVucmljaCBIZWFkZXIgYW5kIFRMUyBjaGVja3Mgd2l0"
    "aAogIHJlYWwgY29tbWFuZCBvdXRwdXQgKHNlZSBhYm92ZSkuIFRoZWlyIGFic2VuY2UgZGVncmFkZXMgdGhvc2Ugc3BlY2lm"
    "aWMKICBjaGVja3MgdG8gSU5GTy9NQU5VQUwgLSBpdCBkb2VzIG5vdCBicmVhayB0aGUgcmVzdCBvZiB0aGUgc2Nhbi4KIiIi"
    "CgppbXBvcnQgYXJncGFyc2UKaW1wb3J0IGJhc2U2NAppbXBvcnQgY3N2CmltcG9ydCBoYXNobGliCmltcG9ydCBpbwppbXBv"
    "cnQganNvbgppbXBvcnQgcmFuZG9tCmltcG9ydCByZQppbXBvcnQgc2h1dGlsCmltcG9ydCBzb2NrZXQKaW1wb3J0IHNzbApp"
    "bXBvcnQgc3RyaW5nCmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCBzeXMKaW1wb3J0IHRleHR3cmFwCmltcG9ydCB0aW1lCmlt"
    "cG9ydCB3YXJuaW5ncwpmcm9tIGRhdGV0aW1lIGltcG9ydCBkYXRldGltZSwgdGltZXpvbmUKZnJvbSBodHRwLmNsaWVudCBp"
    "bXBvcnQgSFRUUENvbm5lY3Rpb24sIEhUVFBTQ29ubmVjdGlvbgpmcm9tIHVybGxpYi5wYXJzZSBpbXBvcnQgdXJscGFyc2Us"
    "IHVybGpvaW4KCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0KIyBDb25zdGFudHMKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKREVGQVVMVF9VQSA9ICJSZXBvcnRTeXN0ZW0tQ2hlY2tsaXN0QXV0"
    "b1NjYW4vMS4wICgrYXV0aG9yaXplZC1wZW50ZXN0LXJlY29uKSIKU1RBQ0tfVFJBQ0VfUEFUVEVSTlMgPSBbCiAgICByIlRy"
    "YWNlYmFjayBcKG1vc3QgcmVjZW50IGNhbGwgbGFzdFwpIiwgciJhdCBTeXN0ZW1cLiIsIHIiRXhjZXB0aW9uIGluIHRocmVh"
    "ZCIsCiAgICByIkZhdGFsIGVycm9yOiIsIHIiV2FybmluZzpccytcdytcKFwpIiwgciJPUkEtXGR7NX0iLCByIlNRTFNUQVRF"
    "XFsiLAogICAgciJNaWNyb3NvZnQgT0xFIERCIFByb3ZpZGVyIiwgciJ1bmhhbmRsZWQgZXhjZXB0aW9uIiwgciJTdGFjayB0"
    "cmFjZToiLAogICAgciJkamFuZ29cLmNvcmVcLmV4Y2VwdGlvbnMiLCByIk5vTWV0aG9kRXJyb3IiLCByImphdmFcLmxhbmdc"
    "Llx3K0V4Y2VwdGlvbiIsCiAgICByInBzcWw6IGVycm9yIiwgciJVbmhhbmRsZWQgRXhjZXB0aW9uIiwgciJERUJVRyA9IFRy"
    "dWUiLCByIldTT0QiLApdCkRFQlVHX1BBR0VTID0gWyIvcGhwaW5mby5waHAiLCAiL2luZm8ucGhwIiwgIi9fcHJvZmlsZXIv"
    "IiwgIi9yYWlscy9pbmZvL3Byb3BlcnRpZXMiLAogICAgICAgICAgICAgICAiL2RlYnVnIiwgIi9lbG1haC5heGQiLCAiL3Ry"
    "YWNlLmF4ZCIsICIvc2VydmVyLXN0YXR1cyIsICIvc2VydmVyLWluZm8iXQpCQUNLVVBfRVhUX1BST0JFUyA9IFsiL2luZGV4"
    "LnBocC5iYWsiLCAiL2luZGV4Lmh0bWwuYmFrIiwgIi9pbmRleC5iYWsiLCAiL2NvbmZpZy5waHAuYmFrIiwKICAgICAgICAg"
    "ICAgICAgICAgICAgICIvd2ViLmNvbmZpZy5iYWsiLCAiLy5lbnYuYmFrIiwgIi9hcHAuanMuYmFrIiwgIi93cC1jb25maWcu"
    "cGhwLmJhayIsCiAgICAgICAgICAgICAgICAgICAgICAiL2luZGV4LnBocC5vbGQiLCAiL2luZGV4LnBocC5vcmlnIiwgIi9p"
    "bmRleC5waHAuc3dwIl0KQkFDS1VQX0ZJTEVfUFJPQkVTID0gWyIvYmFja3VwLnppcCIsICIvYmFja3VwLnRhci5neiIsICIv"
    "c2l0ZS1iYWNrdXAuemlwIiwgIi9kYi5zcWwiLAogICAgICAgICAgICAgICAgICAgICAgICIvZGF0YWJhc2Uuc3FsIiwgIi8u"
    "ZW52IiwgIi9jb25maWcucGhwfiIsICIvZHVtcC5zcWwiLCAiL2JhY2t1cC5zcWwuZ3oiXQpHSVRfU1ZOX1BST0JFUyA9IFsi"
    "Ly5naXQvSEVBRCIsICIvLmdpdC9jb25maWciLCAiLy5zdm4vZW50cmllcyIsICIvLnN2bi93Yy5kYiIsCiAgICAgICAgICAg"
    "ICAgICAgICAiLy5EU19TdG9yZSIsICIvLmhnL3N0b3JlIiwgIi9DVlMvUm9vdCJdCkRFUEVOREVOQ1lfUFJPQkVTID0gWyIv"
    "cGFja2FnZS5qc29uIiwgIi9jb21wb3Nlci5qc29uIiwgIi9yZXF1aXJlbWVudHMudHh0IiwgIi9HZW1maWxlIiwKICAgICAg"
    "ICAgICAgICAgICAgICAgICIvcG9tLnhtbCIsICIvUGlwZmlsZSIsICIveWFybi5sb2NrIl0KQURNSU5fUEFUSF9QUk9CRVMg"
    "PSBbIi9hZG1pbiIsICIvYWRtaW5pc3RyYXRvciIsICIvd3AtYWRtaW4vIiwgIi9tYW5hZ2VyL2h0bWwiLAogICAgICAgICAg"
    "ICAgICAgICAgICAgIi9waHBteWFkbWluLyIsICIvYWRtaW5lci5waHAiLCAiL2NwYW5lbCIsICIvd2VibWluLyJdCkNPTU1P"
    "Tl9BRE1JTl9QT1JUUyA9IFsyMSwgMjIsIDIzLCAzMzA2LCAzMzg5LCA1NDMyLCA2Mzc5LCA4MDgwLCA4NDQzLCA5MjAwLCAy"
    "NzAxNywgNTk4NCwgMjM3NV0KQ09NTU9OX0RLSU1fU0VMRUNUT1JTID0gWyJkZWZhdWx0IiwgImdvb2dsZSIsICJzZWxlY3Rv"
    "cjEiLCAic2VsZWN0b3IyIiwgImRraW0iLCAiazEiLCAibWFpbCIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgInMxIiwg"
    "InMyIiwgInNtdHAiLCAibWFuZHJpbGwiLCAic2VuZGdyaWQiXQpDTE9VRF9CVUNLRVRfUEFUVEVSTlMgPSBbciJbXHcuXC1d"
    "K1wuczNcLmFtYXpvbmF3c1wuY29tIiwgciJzM1wuYW1hem9uYXdzXC5jb20vW1x3LlwtXSsiLAogICAgICAgICAgICAgICAg"
    "ICAgICAgICAgIHIic3RvcmFnZVwuZ29vZ2xlYXBpc1wuY29tL1tcdy5cLV0rIiwgciJbXHcuXC1dK1wuYmxvYlwuY29yZVwu"
    "d2luZG93c1wubmV0Il0KQ0ROX1dBRl9IRUFERVJfSElOVFMgPSB7CiAgICAic2VydmVyIjogeyJjbG91ZGZsYXJlIjogIkNs"
    "b3VkZmxhcmUiLCAiYWthbWFpZ2hvc3QiOiAiQWthbWFpIiwgInN1Y3VyaS9jbG91ZHByb3h5IjogIlN1Y3VyaSJ9LAogICAg"
    "ImNmLXJheSI6IHsiIjogIkNsb3VkZmxhcmUifSwgIngtYW16LWNmLWlkIjogeyIiOiAiQW1hem9uIENsb3VkRnJvbnQifSwK"
    "ICAgICJ4LXN1Y3VyaS1pZCI6IHsiIjogIlN1Y3VyaSJ9LCAieC1jYWNoZSI6IHsiIjogInNvbWUgQ0ROL3JldmVyc2UtcHJv"
    "eHkgY2FjaGUifSwKICAgICJ4LWFrYW1haS10cmFuc2Zvcm1lZCI6IHsiIjogIkFrYW1haSJ9LCAieC12YXJuaXNoIjogeyIi"
    "OiAiVmFybmlzaCBjYWNoZSJ9LAp9CgpSRVNVTFRTID0gW10KTUFOVUFMX1BSRUZJWCA9ICJNYW51YWwgdGVzdCByZXF1aXJl"
    "ZC4gIgojIFNldCBieSBzY2FuX3VybCgpL3J1bl9mdWxsX3N1aXRlKCkgYmVmb3JlIGVhY2ggcGFzcyBzbyBhZGQoKSBjYW4g"
    "dGFnIGV2ZXJ5CiMgcm93IHdpdGggd2hpY2ggaW5wdXQgVVJMIGl0IGNhbWUgZnJvbSBhbmQgd2hpY2ggb2YgdGhlIHR3byBw"
    "YXNzZXMKIyAoZ2l2ZW4tdXJsIC8gc2l0ZS1yb290KSBwcm9kdWNlZCBpdCwgd2l0aG91dCB0aHJlYWRpbmcgdHdvIGV4dHJh"
    "CiMgcGFyYW1ldGVycyB0aHJvdWdoIGV2ZXJ5IG9uZSBvZiB0aGUgfjcwIGFkZCgpIGNhbGwgc2l0ZXMgYmVsb3cuCkNUWCA9"
    "IHsic291cmNlX2lucHV0IjogTm9uZSwgInVybF9yb2xlIjogImdpdmVuLXVybCJ9CgojIFBvcHVsYXRlZCBmcm9tIC0tY29v"
    "a2llLy0taGVhZGVyIGJ5IG1haW4oKSBiZWZvcmUgc2Nhbm5pbmcgc3RhcnRzLCB0aGVuCiMgbWVyZ2VkIGludG8gZXZlcnkg"
    "cmVxdWVzdCByYXdfcmVxdWVzdCgpIG1ha2VzIChzZWUgcmF3X3JlcXVlc3QoKSBiZWxvdykgLQojIHRoaXMgaXMgd2hhdCBs"
    "ZXRzIGFuIGF1dGhlbnRpY2F0ZWQgQnVycCBzZXNzaW9uJ3MgY29va2llL0F1dGhvcml6YXRpb24KIyBoZWFkZXIgZmxvdyB0"
    "aHJvdWdoIHRvIGV2ZXJ5IG9uZSBvZiB0aGUgfjEwMCBjaGVja3Mgd2l0aG91dCB0b3VjaGluZyBlYWNoCiMgY2hlY2sgZnVu"
    "Y3Rpb24gaW5kaXZpZHVhbGx5LiBBIHBlci1jYWxsIGV4dHJhX2hlYWRlcnM9IChlLmcuIHRoZQojIGFjY291bnQxL2FjY291"
    "bnQyIElET1IgY29va2llIGluIF9mZXRjaF93aXRoX2Nvb2tpZSgpKSBhbHdheXMgb3ZlcnJpZGVzCiMgdGhlc2Ugb24gYSBu"
    "YW1lIGNvbGxpc2lvbiAtIGdsb2JhbCBzZXNzaW9uIGlkZW50aXR5IGlzIHRoZSBkZWZhdWx0LCBhbgojIGV4cGxpY2l0IHBl"
    "ci1jaGVjayBpZGVudGl0eSBhbHdheXMgd2lucy4KRVhUUkFfQVVUSF9IRUFERVJTID0ge30KCiMgUG9wdWxhdGVkIGZyb20g"
    "KHJlcGVhdGFibGUpIC0tb25seSA8SUQ+IGJ5IG1haW4oKSAtIHdoZW4gc2V0LCBhZGQoKSBkcm9wcwojIGFueSByb3cgd2hv"
    "c2UgQ2hlY2tsaXN0IElEIGlzbid0IGluIHRoaXMgc2V0IGluc3RlYWQgb2YgcmVjb3JkaW5nIGl0LiBUaGUKIyBjaGVjayBp"
    "dHNlbGYgc3RpbGwgcnVucyAodGhlc2UgYXJlIGFsbCBmYXN0IEhUVFAvVExTIHByb2Jlcywgbm90IGFuCiMgZXhwZW5zaXZl"
    "IGV4dGVybmFsIHNjYW4pLCBidXQgb25seSB0aGUgcmVxdWVzdGVkIElEcyBlbmQgdXAgaW4gdGhlIG91dHB1dAojIC0gdGhp"
    "cyBpcyB3aGF0IHBvd2VycyBhICJyZS1ydW4gc2VsZWN0ZWQgcm93cyBvbmx5IiBmZWF0dXJlIGluIGEgY2FsbGVyCiMgbGlr"
    "ZSBhIEJ1cnAgZXh0ZW5zaW9uLCB3aXRob3V0IG5lZWRpbmcgZXZlcnkgb25lIG9mIHRoZSB+MzAgY2hlY2tfKigpCiMgZnVu"
    "Y3Rpb25zIHRvIGtub3cgaG93IHRvIHNraXAgdGhlbXNlbHZlcyBpbmRpdmlkdWFsbHkuCk9OTFlfSURTID0gTm9uZQoKCmRl"
    "ZiBub3dfaXNvKCk6CiAgICByZXR1cm4gZGF0ZXRpbWUubm93KHRpbWV6b25lLnV0Yykuc3RyZnRpbWUoIiVZLSVtLSVkICVI"
    "OiVNOiVTIFVUQyIpCgoKZGVmIGFkZCh1cmwsIGNpZCwgY2F0ZWdvcnksIHRlc3QsIHNldmVyaXR5LCBwcmlvcml0eSwgcmVz"
    "dWx0LCBldmlkZW5jZSk6CiAgICBpZiBPTkxZX0lEUyBpcyBub3QgTm9uZSBhbmQgY2lkIG5vdCBpbiBPTkxZX0lEUzoKICAg"
    "ICAgICByZXR1cm4KICAgIGV2aWRlbmNlID0gZXZpZGVuY2Uuc3RyaXAoKSBpZiBldmlkZW5jZSBlbHNlICIiCiAgICBpZiBy"
    "ZXN1bHQgPT0gIk1BTlVBTCIgYW5kIG5vdCBldmlkZW5jZS5zdGFydHN3aXRoKE1BTlVBTF9QUkVGSVgpOgogICAgICAgIGV2"
    "aWRlbmNlID0gTUFOVUFMX1BSRUZJWCArIGV2aWRlbmNlCiAgICByb3cgPSB7CiAgICAgICAgInNvdXJjZV9pbnB1dCI6IENU"
    "WC5nZXQoInNvdXJjZV9pbnB1dCIpIG9yIHVybCwKICAgICAgICAidXJsX3JvbGUiOiBDVFguZ2V0KCJ1cmxfcm9sZSIpIG9y"
    "ICJnaXZlbi11cmwiLAogICAgICAgICJ1cmwiOiB1cmwsICJpZCI6IGNpZCwgImNhdGVnb3J5IjogY2F0ZWdvcnksICJ0ZXN0"
    "IjogdGVzdCwKICAgICAgICAic2V2ZXJpdHkiOiBzZXZlcml0eSwgInByaW9yaXR5IjogcHJpb3JpdHksICJyZXN1bHQiOiBy"
    "ZXN1bHQsCiAgICAgICAgImV2aWRlbmNlIjogZXZpZGVuY2UsICJjaGVja2VkX2F0Ijogbm93X2lzbygpLAogICAgICAgICJl"
    "dmlkZW5jZV9pbWFnZV9iYXNlNjQiOiBOb25lLCAgIyBmaWxsZWQgaW4gYnkgZ2VuZXJhdGVfc2NyZWVuc2hvdHMoKSBpZiB0"
    "aGlzIHJvdyBxdWFsaWZpZXMKICAgIH0KICAgIFJFU1VMVFMuYXBwZW5kKHJvdykKICAgICMgTGl2ZS1wcm9ncmVzcyBsaW5l"
    "IGZvciBhIGNhbGxlciAoZS5nLiB0aGUgQnVycCBleHRlbnNpb24pIHJlYWRpbmcKICAgICMgdGhpcyBwcm9jZXNzJ3Mgc3Rk"
    "b3V0IEFTIElUIFJVTlMgaW5zdGVhZCBvZiB3YWl0aW5nIGZvciBpdCB0byBleGl0IC0KICAgICMgb25lIHNlbGYtY29udGFp"
    "bmVkIEpTT04gcm93IHBlciBsaW5lLCBkaXN0aW5jdGl2ZWx5IHByZWZpeGVkIHNvIGl0J3MKICAgICMgZWFzeSB0byBwaWNr"
    "IG91dCBmcm9tIHRoZSBzY2FuJ3Mgbm9ybWFsIHByaW50ZWQgbmFycmF0aW9uLiBGbHVzaGVkCiAgICAjIGltbWVkaWF0ZWx5"
    "IHNvIGl0IGlzbid0IHNpdHRpbmcgaW4gUHl0aG9uJ3MgYnVmZmVyZWQgc3Rkb3V0IHdoZW4gdGhlCiAgICAjIGNhbGxlciBy"
    "ZWFkcyBpdC4gTmV2ZXIgbGV0cyBhIHByaW50L2VuY29kaW5nIGhpY2N1cCBicmVhayB0aGUgYWN0dWFsCiAgICAjIHNjYW4g"
    "LSB0aGlzIGlzIGEgbmljZS10by1oYXZlIHNpZGUgY2hhbm5lbCwgbm90IHRoZSBzb3VyY2Ugb2YgdHJ1dGgKICAgICMgKFJF"
    "U1VMVFMgYWJvdmUsIGFuZCB0aGUgZmluYWwgLmpzb24sIGFsd2F5cyBoYXZlIHRoZSByZWFsIGRhdGEpLgogICAgdHJ5Ogog"
    "ICAgICAgIHByaW50KCJRVUlDS0NIT1BfUk9XfCIgKyBqc29uLmR1bXBzKHJvdykpCiAgICAgICAgc3lzLnN0ZG91dC5mbHVz"
    "aCgpCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHBhc3MKCgpkZWYgcmFuZF90b2tlbihuPTEwKToKICAgIHJldHVy"
    "biAiIi5qb2luKHJhbmRvbS5jaG9pY2VzKHN0cmluZy5hc2NpaV9sb3dlcmNhc2UgKyBzdHJpbmcuZGlnaXRzLCBrPW4pKQoK"
    "CiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0KIyBBdXRvLWdlbmVyYXRlZCAiZXZpZGVuY2Ugc2NyZWVuc2hvdCIgLSBhIHJlbmRlcmVkIFBORyBjYXJkIHN0YW5k"
    "aW5nIGluCiMgZm9yIHRoZSBtYW51YWwgc2NyZWVuc2hvdCBhIHJlcG9ydCB3b3VsZCBvdGhlcndpc2UgbmVlZCBwZXIgZmlu"
    "ZGluZy4gU2VlCiMgbW9kdWxlIGRvY3N0cmluZyAiQVVUTy1HRU5FUkFURUQgRVZJREVOQ0UgU0NSRUVOU0hPVFMiIGZvciB0"
    "aGUgZnVsbAojIGV4cGxhbmF0aW9uLiBEZWdyYWRlcyBncmFjZWZ1bGx5ICh3aG9sZSBzY2FuIHN0aWxsIGNvbXBsZXRlcykg"
    "aWYgUGlsbG93CiMgaXNuJ3QgaW5zdGFsbGVkIC0gY2hlY2tlZCBvbmNlIHZpYSBfcGlsbG93X2F2YWlsYWJsZSgpLgojIC0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "CgpfUElMTE9XX1dBUk5FRCA9IEZhbHNlCgoKZGVmIF9waWxsb3dfYXZhaWxhYmxlKCk6CiAgICBnbG9iYWwgX1BJTExPV19X"
    "QVJORUQKICAgIHRyeToKICAgICAgICBpbXBvcnQgUElMICAjIG5vcWE6IEY0MDEKICAgICAgICByZXR1cm4gVHJ1ZQogICAg"
    "ZXhjZXB0IEltcG9ydEVycm9yOgogICAgICAgIGlmIG5vdCBfUElMTE9XX1dBUk5FRDoKICAgICAgICAgICAgcHJpbnQoIlxu"
    "WyFdICdQaWxsb3cnIG5vdCBpbnN0YWxsZWQgLSBza2lwcGluZyBhdXRvLWdlbmVyYXRlZCBldmlkZW5jZSBzY3JlZW5zaG90"
    "cyAiCiAgICAgICAgICAgICAgICAgICIodGhlIHJlc3Qgb2YgdGhlIHNjYW4gaXMgdW5hZmZlY3RlZCkuIikKICAgICAgICAg"
    "ICAgcHJpbnQoIiAgICBJbnN0YWxsIHdpdGg6IHBpcDMgaW5zdGFsbCBQaWxsb3cgICAiCiAgICAgICAgICAgICAgICAgICIo"
    "YWRkIC0tYnJlYWstc3lzdGVtLXBhY2thZ2VzIGlmIHlvdXIgUHl0aG9uIHJlcG9ydHMgYW4gZXh0ZXJuYWxseS1tYW5hZ2Vk"
    "LWVudmlyb25tZW50IGVycm9yKSIpCiAgICAgICAgICAgIF9QSUxMT1dfV0FSTkVEID0gVHJ1ZQogICAgICAgIHJldHVybiBG"
    "YWxzZQoKCl9SRVNVTFRfQ09MT1JTID0gewogICAgIlBBU1MiOiAoIiMxZTdlMzQiLCAiI2VhZmFmMSIpLAogICAgIkZBSUwi"
    "OiAoIiNhNDI2MmMiLCAiI2ZkZWNlYSIpLAogICAgIk1BTlVBTCI6ICgiIzhhNmQwMCIsICIjZmZmOGUxIiksCiAgICAiSU5G"
    "TyI6ICgiIzFmNGU3OCIsICIjZWFmMWZiIiksCiAgICAiRVJST1IiOiAoIiMzYjNiM2IiLCAiI2VlZWVlZSIpLAp9CgoKZGVm"
    "IF93cmFwX2J5X3BpeGVsKGRyYXcsIHRleHQsIGZvbnQsIG1heF93aWR0aF9weCk6CiAgICAiIiJXb3JkLXdyYXBzIGJ5IGFj"
    "dHVhbGx5IE1FQVNVUklORyBlYWNoIGNhbmRpZGF0ZSBsaW5lJ3MgcGl4ZWwKICAgIHdpZHRoIGFnYWluc3QgdGhlIGZvbnQg"
    "aW4gdXNlLCBpbnN0ZWFkIG9mIGd1ZXNzaW5nIGEgZml4ZWQKICAgIGNoYXJhY3RlciBjb3VudCAtIGEgY2hhci1jb3VudCBn"
    "dWVzcyAoZS5nLiB3aWR0aD0xMjgpIHNpbGVudGx5CiAgICBvdmVyZmxvd3MgdGhlIGltYWdlIGVkZ2Ugd2hlbmV2ZXIgdGhl"
    "IHJlYWwgZ2x5cGggd2lkdGggZG9lc24ndAogICAgbWF0Y2ggdGhlIGd1ZXNzIChkaWZmZXJlbnQgZm9udCwgYm9sZCB2cyBy"
    "ZWd1bGFyLCBvciB0aGUKICAgIGxvYWRfZGVmYXVsdCgpIGZhbGxiYWNrIHdoZW4gRGVqYVZ1U2Fuc01vbm8gaXNuJ3QgaW5z"
    "dGFsbGVkLAogICAgd2hpY2ggaXNuJ3QgZXZlbiBtb25vc3BhY2UpLiBGYWxscyBiYWNrIHRvIGEgc2luZ2xlIGNoYXJhY3Rl"
    "ci1ieS0KICAgIGNoYXJhY3RlciBicmVhayBvbmx5IGZvciBvbmUgd29yZCB0b28gbG9uZyB0byBmaXQgYXQgYWxsLiBTaGFy"
    "ZWQgYnkKICAgIHJlbmRlcl9ldmlkZW5jZV9pbWFnZSgpIGFuZCByZW5kZXJfdGVybWluYWxfaW1hZ2UoKSBzbyBldmVyeQog"
    "ICAgc2NyZWVuc2hvdCAtIGN1cmwvbm1hcC1iYWNrZWQgb3Igbm90IC0gd3JhcHMgdGV4dCBpZGVudGljYWxseS4iIiIKICAg"
    "IHdvcmRzID0gdGV4dC5zcGxpdCgiICIpCiAgICBsaW5lc19vdXQsIGN1ciA9IFtdLCAiIgogICAgZm9yIHdvcmQgaW4gd29y"
    "ZHM6CiAgICAgICAgY2FuZGlkYXRlID0gd29yZCBpZiBub3QgY3VyIGVsc2UgZiJ7Y3VyfSB7d29yZH0iCiAgICAgICAgaWYg"
    "ZHJhdy50ZXh0bGVuZ3RoKGNhbmRpZGF0ZSwgZm9udD1mb250KSA8PSBtYXhfd2lkdGhfcHg6CiAgICAgICAgICAgIGN1ciA9"
    "IGNhbmRpZGF0ZQogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIGN1cjoKICAgICAgICAgICAgbGluZXNfb3V0LmFw"
    "cGVuZChjdXIpCiAgICAgICAgaWYgZHJhdy50ZXh0bGVuZ3RoKHdvcmQsIGZvbnQ9Zm9udCkgPD0gbWF4X3dpZHRoX3B4Ogog"
    "ICAgICAgICAgICBjdXIgPSB3b3JkCiAgICAgICAgZWxzZToKICAgICAgICAgICAgIyBhIHNpbmdsZSAid29yZCIgKGUuZy4g"
    "b25lIGxvbmcgVVJML3Rva2VuKSB3aWRlciB0aGFuIHRoZQogICAgICAgICAgICAjIGxpbmUgaXRzZWxmIC0gaGFyZC1icmVh"
    "ayBpdCBjaGFyYWN0ZXIgYnkgY2hhcmFjdGVyCiAgICAgICAgICAgIGNodW5rID0gIiIKICAgICAgICAgICAgZm9yIGNoIGlu"
    "IHdvcmQ6CiAgICAgICAgICAgICAgICBpZiBkcmF3LnRleHRsZW5ndGgoY2h1bmsgKyBjaCwgZm9udD1mb250KSA+IG1heF93"
    "aWR0aF9weDoKICAgICAgICAgICAgICAgICAgICBsaW5lc19vdXQuYXBwZW5kKGNodW5rKQogICAgICAgICAgICAgICAgICAg"
    "IGNodW5rID0gY2gKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgY2h1bmsgKz0gY2gKICAgICAg"
    "ICAgICAgY3VyID0gY2h1bmsKICAgIGlmIGN1cjoKICAgICAgICBsaW5lc19vdXQuYXBwZW5kKGN1cikKICAgIHJldHVybiBs"
    "aW5lc19vdXQgb3IgWyIiXQoKCmRlZiBfbW9ub19mb250cygpOgogICAgIiIiTG9hZHMgdGhlIG1vbm9zcGFjZSBmb250IHBh"
    "aXIgdXNlZCBieSBldmVyeSB0ZXJtaW5hbC1zdHlsZQogICAgc2NyZWVuc2hvdC4gQ2VudHJhbGl6ZWQgc28gcmVuZGVyX2V2"
    "aWRlbmNlX2ltYWdlKCkgYW5kCiAgICByZW5kZXJfdGVybWluYWxfaW1hZ2UoKSBhbHdheXMgbWF0Y2guIiIiCiAgICBmcm9t"
    "IFBJTCBpbXBvcnQgSW1hZ2VGb250CgogICAgbW9ub19ib2xkID0gbW9ubyA9IE5vbmUKICAgIGZvciBjYW5kaWRhdGUgaW4g"
    "KCJEZWphVnVTYW5zTW9uby1Cb2xkLnR0ZiIsKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIG1vbm9fYm9sZCA9IEltYWdl"
    "Rm9udC50cnVldHlwZShjYW5kaWRhdGUsIDE1KQogICAgICAgICAgICBicmVhawogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246"
    "CiAgICAgICAgICAgIHBhc3MKICAgIGZvciBjYW5kaWRhdGUgaW4gKCJEZWphVnVTYW5zTW9uby50dGYiLCk6CiAgICAgICAg"
    "dHJ5OgogICAgICAgICAgICBtb25vID0gSW1hZ2VGb250LnRydWV0eXBlKGNhbmRpZGF0ZSwgMTMpCiAgICAgICAgICAgIGJy"
    "ZWFrCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgcGFzcwogICAgaWYgbW9ub19ib2xkIGlzIE5vbmU6"
    "CiAgICAgICAgbW9ub19ib2xkID0gSW1hZ2VGb250LmxvYWRfZGVmYXVsdCgpCiAgICBpZiBtb25vIGlzIE5vbmU6CiAgICAg"
    "ICAgbW9ubyA9IEltYWdlRm9udC5sb2FkX2RlZmF1bHQoKQogICAgcmV0dXJuIG1vbm9fYm9sZCwgbW9ubwoKCmRlZiByZW5k"
    "ZXJfZXZpZGVuY2VfaW1hZ2Uocm93KToKICAgICIiIlJldHVybnMgKGJhc2U2NF9wbmdfc3RyLCByYXdfcG5nX2J5dGVzKSBm"
    "b3Igb25lIHJlc3VsdCByb3csIG9yCiAgICAoTm9uZSwgTm9uZSkgaWYgUGlsbG93IGlzbid0IGF2YWlsYWJsZS4gRXZlcnkg"
    "c2NyZWVuc2hvdCBub3cgdXNlcyB0aGUKICAgIHNhbWUgYmxhY2svdGVybWluYWwgbG9vayAtIHJlcXVlc3RlZCBkaXJlY3Rs"
    "eTogInNjcmVlbnNob3QgZm9yIGJsYWMKICAgIG9uZSBhdXRoZW50aWNhIGxvb2tzIGxpa2UgY29tbWFuZCBvdXRwdXQgaW5z"
    "dGVkIG9mIHdoaXRlIG9uZSB5b3UKICAgIHNoYXJlZCwgb3V0cHV0IHNob3VkbCBiZSBjb21tYW5kIGxpbmUgb3B0dXQuIiBS"
    "b3dzIGNhcnJ5aW5nIHJlYWwKICAgIGNvbW1hbmQtbGluZSB0b29sIG91dHB1dCAoY3VybC9ubWFwL3NzbHl6ZS8uLi4pIHN0"
    "aWxsIGdvIHRocm91Z2gKICAgIHJlbmRlcl90ZXJtaW5hbF9pbWFnZSgpIChyZWFsICIkICIgY29tbWFuZCArIHJlYWwgb3V0"
    "cHV0KTsgcm93cwogICAgd2l0aG91dCBvbmUgKGhldXJpc3RpYy9tYW51YWwtcmV2aWV3IGNoZWNrcykgZ2V0IGEgdGVybWlu"
    "YWwtc3R5bGVkCiAgICBjYXJkIGJ1aWx0IGZyb20gdGhpcyByb3cncyBvd24gZmllbGRzIGluc3RlYWQgb2YgdGhlIG9sZCB3"
    "aGl0ZQogICAgImxhYmVsOnZhbHVlIiBzdW1tYXJ5IGNhcmQuIiIiCiAgICBpZiBub3QgX3BpbGxvd19hdmFpbGFibGUoKToK"
    "ICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgaWYgQ01EX0JMT0NLX01BUktFUiBpbiAocm93LmdldCgiZXZpZGVuY2Ui"
    "KSBvciAiIik6CiAgICAgICAgcmV0dXJuIHJlbmRlcl90ZXJtaW5hbF9pbWFnZShyb3cpCiAgICBmcm9tIFBJTCBpbXBvcnQg"
    "SW1hZ2UsIEltYWdlRHJhdwoKICAgIFcsIEggPSA5ODAsIDY0MAogICAgZmcsIF9iZyA9IF9SRVNVTFRfQ09MT1JTLmdldChy"
    "b3dbInJlc3VsdCJdLCAoIiMzMzMzMzMiLCAiI2Y1ZjVmNSIpKQogICAgaW1nID0gSW1hZ2UubmV3KCJSR0IiLCAoVywgSCks"
    "ICIjMGMwYzBjIikKICAgIGRyYXcgPSBJbWFnZURyYXcuRHJhdyhpbWcpCiAgICBtb25vX2JvbGQsIG1vbm8gPSBfbW9ub19m"
    "b250cygpCgogICAgZHJhdy5yZWN0YW5nbGUoWzAsIDAsIFcsIDQwXSwgZmlsbD1mZykKICAgIGRyYXcudGV4dCgoMTYsIDEw"
    "KSwgZiJ7cm93WydyZXN1bHQnXX0gLSB7cm93WydpZCddfSAtIHtyb3dbJ3Rlc3QnXVs6NzBdfSIsIGZvbnQ9bW9ub19ib2xk"
    "LCBmaWxsPSJ3aGl0ZSIpCgogICAgbWF4X3dpZHRoX3B4ID0gVyAtIDMyICAjIDE2cHggbWFyZ2luIGVhY2ggc2lkZQogICAg"
    "eSA9IDUyCgogICAgZGVmIGZpZWxkX2xpbmUobGFiZWwsIHZhbHVlLCB5KToKICAgICAgICBkcmF3LnRleHQoKDE2LCB5KSwg"
    "ZiJ7bGFiZWx9OiIsIGZvbnQ9bW9ub19ib2xkLCBmaWxsPSIjNTdlMzg5IikKICAgICAgICBkcmF3LnRleHQoKDE1MCwgeSks"
    "IHN0cih2YWx1ZSlbOjExMF0sIGZvbnQ9bW9ubywgZmlsbD0iI2UwZTBlMCIpCiAgICAgICAgcmV0dXJuIHkgKyAxOQoKICAg"
    "IHkgPSBmaWVsZF9saW5lKCJVUkwiLCByb3dbInVybCJdLCB5KQogICAgeSA9IGZpZWxkX2xpbmUoIlVSTCBSb2xlIiwgcm93"
    "WyJ1cmxfcm9sZSJdLCB5KQogICAgeSA9IGZpZWxkX2xpbmUoIkNhdGVnb3J5Iiwgcm93WyJjYXRlZ29yeSJdLCB5KQogICAg"
    "eSA9IGZpZWxkX2xpbmUoIlNldmVyaXR5IiwgZiJ7cm93WydzZXZlcml0eSddfSAoe3Jvd1sncHJpb3JpdHknXX0pIiwgeSkK"
    "ICAgIHkgPSBmaWVsZF9saW5lKCJDaGVja2VkIEF0Iiwgcm93WyJjaGVja2VkX2F0Il0sIHkpCiAgICB5ICs9IDYKICAgIGRy"
    "YXcubGluZShbMTYsIHksIFcgLSAxNiwgeV0sIGZpbGw9IiMzYTNhM2EiLCB3aWR0aD0xKQogICAgeSArPSAxMgogICAgZHJh"
    "dy50ZXh0KCgxNiwgeSksICJFdmlkZW5jZToiLCBmb250PW1vbm9fYm9sZCwgZmlsbD0iIzU3ZTM4OSIpCiAgICB5ICs9IDIw"
    "CgogICAgbWF4X2xpbmVzID0gbWF4KChIIC0gMzAgLSB5KSAvLyAxNywgMSkKICAgIGxpbmVzID0gW10KICAgIGZvciByYXdf"
    "bGluZSBpbiAocm93LmdldCgiZXZpZGVuY2UiKSBvciAiIikuc3BsaXRsaW5lcygpOgogICAgICAgIGxpbmVzLmV4dGVuZChf"
    "d3JhcF9ieV9waXhlbChkcmF3LCByYXdfbGluZSwgbW9ubywgbWF4X3dpZHRoX3B4KSBpZiByYXdfbGluZSBlbHNlIFsiIl0p"
    "CiAgICBmb3IgbGluZV90eHQgaW4gbGluZXNbOm1heF9saW5lc106CiAgICAgICAgZHJhdy50ZXh0KCgxNiwgeSksIGxpbmVf"
    "dHh0LCBmb250PW1vbm8sIGZpbGw9IiNkMGQwZDAiKQogICAgICAgIHkgKz0gMTcKICAgIGlmIGxlbihsaW5lcykgPiBtYXhf"
    "bGluZXM6CiAgICAgICAgZHJhdy50ZXh0KCgxNiwgeSksIGYiLi4uICh7bGVuKGxpbmVzKSAtIG1heF9saW5lc30gbW9yZSBs"
    "aW5lKHMpIHRydW5jYXRlZCAtIHNlZSBKU09OL0NTViBmb3IgZnVsbCB0ZXh0KSIsCiAgICAgICAgICAgICAgICAgICBmb250"
    "PW1vbm8sIGZpbGw9IiM4ODg4ODgiKQoKICAgIGRyYXcudGV4dCgoMTYsIEggLSAyMCksICJBdXRvLWdlbmVyYXRlZCBldmlk"
    "ZW5jZSBjYXJkIChjaGVja2xpc3RfYXV0b19zY2FuLnB5KSAtIG5vdCBhIGxpdmUgYnJvd3NlciBzY3JlZW5zaG90IiwKICAg"
    "ICAgICAgICAgICAgZm9udD1tb25vLCBmaWxsPSIjNjY2NjY2IikKCiAgICBidWYgPSBpby5CeXRlc0lPKCkKICAgIGltZy5z"
    "YXZlKGJ1ZiwgZm9ybWF0PSJQTkciKQogICAgcmF3ID0gYnVmLmdldHZhbHVlKCkKICAgIHJldHVybiBiYXNlNjQuYjY0ZW5j"
    "b2RlKHJhdykuZGVjb2RlKCJhc2NpaSIpLCByYXcKCgpkZWYgcmVuZGVyX3Rlcm1pbmFsX2ltYWdlKHJvdyk6CiAgICAiIiJU"
    "ZXJtaW5hbC1zdHlsZSBzY3JlZW5zaG90IGZvciByb3dzIGNhcnJ5aW5nIHJlYWwgY29tbWFuZC1saW5lIHRvb2wKICAgIG91"
    "dHB1dCAoY3VybC9ubWFwL3NzbHl6ZS8uLi4pLiBSZXF1ZXN0ZWQgZGlyZWN0bHk6ICJjaGVjayB3aXQgaGNvbW1hbmQKICAg"
    "IGxpbmUgdG9vbHMgSSBoYXZlIG5vdCBzZWVuIHN5IHNjcmVlbnNob3RzIGZvciBnaXZlIGZpbmRpbmdzIiAtIHRoaXMgaXMK"
    "ICAgIHdoYXQgbWFrZXMgdGhvc2Ugc2NyZWVuc2hvdHMgbG9vayBsaWtlIGFuIGFjdHVhbCB0ZXJtaW5hbCBjYXB0dXJlIG9m"
    "CiAgICB0aGUgcmVhbCBjb21tYW5kICsgb3V0cHV0LCBpbnN0ZWFkIG9mIHRoZSBnZW5lcmljIHN1bW1hcnkgY2FyZC4iIiIK"
    "ICAgIGZyb20gUElMIGltcG9ydCBJbWFnZSwgSW1hZ2VEcmF3CgogICAgVywgSCA9IDk4MCwgNjQwCiAgICBmZywgX2JnID0g"
    "X1JFU1VMVF9DT0xPUlMuZ2V0KHJvd1sicmVzdWx0Il0sICgiIzMzMzMzMyIsICIjZjVmNWY1IikpCiAgICBpbWcgPSBJbWFn"
    "ZS5uZXcoIlJHQiIsIChXLCBIKSwgIiMwYzBjMGMiKQogICAgZHJhdyA9IEltYWdlRHJhdy5EcmF3KGltZykKICAgIG1vbm9f"
    "Ym9sZCwgbW9ubyA9IF9tb25vX2ZvbnRzKCkKCiAgICBkcmF3LnJlY3RhbmdsZShbMCwgMCwgVywgNDBdLCBmaWxsPWZnKQog"
    "ICAgZHJhdy50ZXh0KCgxNiwgMTApLCBmIntyb3dbJ3Jlc3VsdCddfSAtIHtyb3dbJ2lkJ119IC0ge3Jvd1sndGVzdCddWzo3"
    "MF19IiwgZm9udD1tb25vX2JvbGQsIGZpbGw9IndoaXRlIikKCiAgICBldmlkZW5jZSA9IHJvdy5nZXQoImV2aWRlbmNlIikg"
    "b3IgIiIKICAgIG1hcmtlcl9wb3MgPSBldmlkZW5jZS5maW5kKENNRF9CTE9DS19NQVJLRVIpCiAgICBzdW1tYXJ5ID0gZXZp"
    "ZGVuY2VbOm1hcmtlcl9wb3NdLnN0cmlwKCkgaWYgbWFya2VyX3BvcyA+PSAwIGVsc2UgZXZpZGVuY2Uuc3RyaXAoKQogICAg"
    "Y21kX2Jsb2NrID0gZXZpZGVuY2VbbWFya2VyX3BvcyArIDI6XS5zdHJpcCgpIGlmIG1hcmtlcl9wb3MgPj0gMCBlbHNlICIi"
    "ICAjIGtlZXAgbGVhZGluZyAiJCAiCgogICAgbWF4X3dpZHRoX3B4ID0gVyAtIDMyICAjIDE2cHggbWFyZ2luIGVhY2ggc2lk"
    "ZQoKICAgIHkgPSA1MgogICAgZHJhdy50ZXh0KCgxNiwgeSksIGYiVVJMOiB7cm93Wyd1cmwnXX0gIHwgIFJvbGU6IHtyb3db"
    "J3VybF9yb2xlJ119ICB8ICB7cm93WydjaGVja2VkX2F0J119IiwKICAgICAgICAgICAgICBmb250PW1vbm8sIGZpbGw9IiM5"
    "YWE1YjEiKQogICAgeSArPSAyMgoKICAgIGlmIHN1bW1hcnk6CiAgICAgICAgZm9yIGxpbmVfdHh0IGluIF93cmFwX2J5X3Bp"
    "eGVsKGRyYXcsIHN1bW1hcnksIG1vbm8sIG1heF93aWR0aF9weClbOjRdOgogICAgICAgICAgICBkcmF3LnRleHQoKDE2LCB5"
    "KSwgbGluZV90eHQsIGZvbnQ9bW9ubywgZmlsbD0iI2QwZDBkMCIpCiAgICAgICAgICAgIHkgKz0gMTgKICAgICAgICB5ICs9"
    "IDYKCiAgICBkcmF3LmxpbmUoWzE2LCB5LCBXIC0gMTYsIHldLCBmaWxsPSIjM2EzYTNhIiwgd2lkdGg9MSkKICAgIHkgKz0g"
    "MTAKCiAgICBtYXhfbGluZXMgPSBtYXgoKEggLSAzMCAtIHkpIC8vIDE3LCAxKQogICAgbGluZXMgPSBbXQogICAgZm9yIHJh"
    "d19saW5lIGluIGNtZF9ibG9jay5zcGxpdGxpbmVzKCk6CiAgICAgICAgbGluZXMuZXh0ZW5kKF93cmFwX2J5X3BpeGVsKGRy"
    "YXcsIHJhd19saW5lLCBtb25vLCBtYXhfd2lkdGhfcHgpIGlmIHJhd19saW5lIGVsc2UgWyIiXSkKICAgIGZvciBsaW5lX3R4"
    "dCBpbiBsaW5lc1s6bWF4X2xpbmVzXToKICAgICAgICBjb2xvciA9ICIjNTdlMzg5IiBpZiBsaW5lX3R4dC5zdGFydHN3aXRo"
    "KCIkICIpIGVsc2UgIiNlMGUwZTAiCiAgICAgICAgZHJhdy50ZXh0KCgxNiwgeSksIGxpbmVfdHh0LCBmb250PW1vbm8sIGZp"
    "bGw9Y29sb3IpCiAgICAgICAgeSArPSAxNwogICAgaWYgbGVuKGxpbmVzKSA+IG1heF9saW5lczoKICAgICAgICBkcmF3LnRl"
    "eHQoKDE2LCB5KSwgZiIuLi4gKHtsZW4obGluZXMpIC0gbWF4X2xpbmVzfSBtb3JlIGxpbmUocykgdHJ1bmNhdGVkIC0gc2Vl"
    "IEpTT04vQ1NWIGZvciBmdWxsIG91dHB1dCkiLAogICAgICAgICAgICAgICAgICBmb250PW1vbm8sIGZpbGw9IiM4ODg4ODgi"
    "KQoKICAgIGRyYXcudGV4dCgoMTYsIEggLSAyMCksICJSZWFsIGNvbW1hbmQtbGluZSB0b29sIG91dHB1dCAoY2hlY2tsaXN0"
    "X2F1dG9fc2Nhbi5weSkgLSBub3QgYSBsaXZlIGJyb3dzZXIgc2NyZWVuc2hvdCIsCiAgICAgICAgICAgICAgZm9udD1tb25v"
    "LCBmaWxsPSIjNjY2NjY2IikKCiAgICBidWYgPSBpby5CeXRlc0lPKCkKICAgIGltZy5zYXZlKGJ1ZiwgZm9ybWF0PSJQTkci"
    "KQogICAgcmF3ID0gYnVmLmdldHZhbHVlKCkKICAgIHJldHVybiBiYXNlNjQuYjY0ZW5jb2RlKHJhdykuZGVjb2RlKCJhc2Np"
    "aSIpLCByYXcKCgpkZWYgc2hvdWxkX3NjcmVlbnNob3QocmVzdWx0LCBwb2xpY3kpOgogICAgaWYgcG9saWN5ID09ICJub25l"
    "IjoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGlmIHBvbGljeSA9PSAiYWxsIjoKICAgICAgICByZXR1cm4gcmVzdWx0IGlu"
    "ICgiUEFTUyIsICJGQUlMIiwgIk1BTlVBTCIsICJJTkZPIiwgIkVSUk9SIikKICAgIGlmIHBvbGljeSA9PSAiZmFpbCtwYXNz"
    "IjoKICAgICAgICByZXR1cm4gcmVzdWx0IGluICgiUEFTUyIsICJGQUlMIikKICAgIHJldHVybiByZXN1bHQgPT0gIkZBSUwi"
    "ICAjIGRlZmF1bHQgcG9saWN5OiAiZmFpbCIKCgpkZWYgZ2VuZXJhdGVfc2NyZWVuc2hvdHMocG9saWN5KToKICAgICIiIlJ1"
    "bnMgb25jZSwgYWZ0ZXIgYWxsIHNjYW5uaW5nIGlzIGRvbmUuIEZpbGxzIGluCiAgICByb3dbImV2aWRlbmNlX2ltYWdlX2Jh"
    "c2U2NCJdIGZvciBxdWFsaWZ5aW5nIHJvd3MgYW5kIHJldHVybnMKICAgIHtyb3dfaW5kZXg6IHJhd19wbmdfYnl0ZXN9IGZv"
    "ciB0aGUgb25lcyB3cml0dGVuIHRvIGRpc2sgKHVzZWQgYnkKICAgIHdyaXRlX3hsc3ggdG8gZW1iZWQgcmVhbCBpbWFnZXMp"
    "IC0gaW1hZ2UgZ2VuZXJhdGlvbiBoYXBwZW5zIGV4YWN0bHkKICAgIG9uY2UgcGVyIHJvdyBlaXRoZXIgd2F5LCBiYXNlNjQg"
    "YW5kIHJhdyBieXRlcyBjb21lIGZyb20gdGhlIHNhbWUgY2FsbC4iIiIKICAgIGlmIHBvbGljeSA9PSAibm9uZSI6CiAgICAg"
    "ICAgcmV0dXJuIHt9CiAgICBpbWFnZV9ieXRlcyA9IHt9CiAgICBnZW5lcmF0ZWQgPSAwCiAgICBmb3IgaWR4LCByb3cgaW4g"
    "ZW51bWVyYXRlKFJFU1VMVFMpOgogICAgICAgIGlmIG5vdCBzaG91bGRfc2NyZWVuc2hvdChyb3dbInJlc3VsdCJdLCBwb2xp"
    "Y3kpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGI2NCwgcmF3ID0gcmVuZGVyX2V2aWRlbmNlX2ltYWdlKHJvdykK"
    "ICAgICAgICBpZiBiNjQgaXMgTm9uZToKICAgICAgICAgICAgYnJlYWsgICMgUGlsbG93IHVuYXZhaWxhYmxlIC0gbm8gcG9p"
    "bnQgcmV0cnlpbmcgb24gZXZlcnkgcmVtYWluaW5nIHJvdwogICAgICAgIHJvd1siZXZpZGVuY2VfaW1hZ2VfYmFzZTY0Il0g"
    "PSBiNjQKICAgICAgICBpbWFnZV9ieXRlc1tpZHhdID0gcmF3CiAgICAgICAgZ2VuZXJhdGVkICs9IDEKICAgIGlmIGdlbmVy"
    "YXRlZDoKICAgICAgICBwcmludChmIlxuWypdIEdlbmVyYXRlZCB7Z2VuZXJhdGVkfSBhdXRvLWV2aWRlbmNlIHNjcmVlbnNo"
    "b3QocykgKC0tc2NyZWVuc2hvdCB7cG9saWN5fSkuIikKICAgIHJldHVybiBpbWFnZV9ieXRlcwoKCiMgLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KIyBMb3ctbGV2"
    "ZWwgSFRUUCBoZWxwZXIgKHN0ZGxpYiBvbmx5IC0gbm8gInJlcXVlc3RzIiBkZXBlbmRlbmN5LCBzbyB0aGlzCiMgcnVucyBv"
    "biBhIGJhcmUtYm9uZXMgUHl0aG9uIGluc3RhbGwgd2l0aCBub3RoaW5nIGV4dHJhIHBpcC1pbnN0YWxsZWQpCiMgLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmNs"
    "YXNzIEh0dHBSZXN1bHQ6CiAgICBkZWYgX19pbml0X18oc2VsZiwgc3RhdHVzPU5vbmUsIGhlYWRlcnM9Tm9uZSwgYm9keT1i"
    "IiIsIGVycm9yPU5vbmUsIGZpbmFsX3VybD1Ob25lKToKICAgICAgICBzZWxmLnN0YXR1cyA9IHN0YXR1cwogICAgICAgIHNl"
    "bGYuaGVhZGVycyA9IGhlYWRlcnMgb3Ige30KICAgICAgICBzZWxmLmJvZHkgPSBib2R5CiAgICAgICAgc2VsZi5lcnJvciA9"
    "IGVycm9yCiAgICAgICAgc2VsZi5maW5hbF91cmwgPSBmaW5hbF91cmwKCiAgICBkZWYgaGVhZGVyKHNlbGYsIG5hbWUsIGRl"
    "ZmF1bHQ9IiIpOgogICAgICAgIGZvciBrLCB2IGluIHNlbGYuaGVhZGVycy5pdGVtcygpOgogICAgICAgICAgICBpZiBrLmxv"
    "d2VyKCkgPT0gbmFtZS5sb3dlcigpOgogICAgICAgICAgICAgICAgcmV0dXJuIHYKICAgICAgICByZXR1cm4gZGVmYXVsdAoK"
    "ICAgIGRlZiB0ZXh0KHNlbGYsIGxpbWl0PTIwMDAwMCk6CiAgICAgICAgdHJ5OgogICAgICAgICAgICByZXR1cm4gc2VsZi5i"
    "b2R5WzpsaW1pdF0uZGVjb2RlKCJ1dGYtOCIsIGVycm9ycz0icmVwbGFjZSIpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoK"
    "ICAgICAgICAgICAgcmV0dXJuICIiCgoKIyBTdGFibGUgbWFya2VyIHByZWZpeCBzdGFtcGVkIG9udG8gZXZlcnkgSHR0cFJl"
    "c3VsdC5lcnJvciBwcm9kdWNlZCBieSB0aGUKIyBzc2wuU1NMQ2VydFZlcmlmaWNhdGlvbkVycm9yIGhhbmRsZXIgaW4gcmF3"
    "X3JlcXVlc3QoKSBiZWxvdyAtIHVzZWQgb25seSB0bwojIHJlbGlhYmx5IGRldGVjdCAidGhpcyByb3cgZmFpbGVkIGJlY2F1"
    "c2Ugb2YgYSBUTFMgY2hhaW4tdmVyaWZ5IHByb2JsZW0iCiMgZnJvbSBldmlkZW5jZS9lcnJvciB0ZXh0IGxhdGVyIChwcmlu"
    "dF9zc2xfdmVyaWZ5X3N1bW1hcnlfY2FsbG91dCgpKSwKIyBpbmRlcGVuZGVudCBvZiB3aGF0ZXZlciBleGFjdCB3b3JkaW5n"
    "IE9wZW5TU0wvUHl0aG9uIGhhcHBlbiB0byB1c2UgZm9yCiMgdGhlIHVuZGVybHlpbmcgZXJyb3Igb24gYSBnaXZlbiBwbGF0"
    "Zm9ybS92ZXJzaW9uLgpfU1NMX1ZFUklGWV9ISU5UX01BUktFUiA9ICJbU1NMLUNFUlQtVkVSSUZZLUZBSUxFRF0iCgoKZGVm"
    "IHJhd19yZXF1ZXN0KHVybCwgbWV0aG9kPSJHRVQiLCBleHRyYV9oZWFkZXJzPU5vbmUsIHRpbWVvdXQ9MTAsIGluc2VjdXJl"
    "PUZhbHNlLAogICAgICAgICAgICAgICAgIGZvbGxvd19yZWRpcmVjdHM9RmFsc2UsIG1heF9yZWRpcmVjdHM9MywgaG9zdF9v"
    "dmVycmlkZT1Ob25lKToKICAgICIiIk1pbmltYWwgSFRUUCBjbGllbnQgdXNpbmcgaHR0cC5jbGllbnQgc28gd2UgY29udHJv"
    "bCByYXcgaGVhZGVycwogICAgZXhhY3RseSAobmVlZGVkIGZvciB0aGUgSG9zdC1oZWFkZXIgcHJvYmUgYW5kIE9QVElPTlMv"
    "VFJBQ0UgY2hlY2tzKSAtCiAgICB1cmxsaWIgcmV3cml0ZXMvbm9ybWFsaXplcyBzb21lIGhlYWRlcnMgaW4gd2F5cyB0aGF0"
    "IGdldCBpbiB0aGUgd2F5IGhlcmUuIiIiCiAgICBoZWFkZXJzID0geyJVc2VyLUFnZW50IjogREVGQVVMVF9VQSwgIkFjY2Vw"
    "dCI6ICIqLyoiLCAiQ29ubmVjdGlvbiI6ICJjbG9zZSJ9CiAgICBpZiBFWFRSQV9BVVRIX0hFQURFUlM6CiAgICAgICAgaGVh"
    "ZGVycy51cGRhdGUoRVhUUkFfQVVUSF9IRUFERVJTKQogICAgaWYgZXh0cmFfaGVhZGVyczoKICAgICAgICBoZWFkZXJzLnVw"
    "ZGF0ZShleHRyYV9oZWFkZXJzKQoKICAgIHBhcnNlZCA9IHVybHBhcnNlKHVybCkKICAgIHNjaGVtZSA9IHBhcnNlZC5zY2hl"
    "bWUgb3IgImh0dHBzIgogICAgaG9zdCA9IHBhcnNlZC5ob3N0bmFtZQogICAgcG9ydCA9IHBhcnNlZC5wb3J0IG9yICg0NDMg"
    "aWYgc2NoZW1lID09ICJodHRwcyIgZWxzZSA4MCkKICAgIHBhdGggPSBwYXJzZWQucGF0aCBvciAiLyIKICAgIGlmIHBhcnNl"
    "ZC5xdWVyeToKICAgICAgICBwYXRoICs9ICI/IiArIHBhcnNlZC5xdWVyeQoKICAgIHRyeToKICAgICAgICBpZiBzY2hlbWUg"
    "PT0gImh0dHBzIjoKICAgICAgICAgICAgY3R4ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoKQogICAgICAgICAgICBp"
    "ZiBpbnNlY3VyZToKICAgICAgICAgICAgICAgIGN0eC5jaGVja19ob3N0bmFtZSA9IEZhbHNlCiAgICAgICAgICAgICAgICBj"
    "dHgudmVyaWZ5X21vZGUgPSBzc2wuQ0VSVF9OT05FCiAgICAgICAgICAgIGNvbm4gPSBIVFRQU0Nvbm5lY3Rpb24oaG9zdCwg"
    "cG9ydCwgdGltZW91dD10aW1lb3V0LCBjb250ZXh0PWN0eCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBjb25uID0gSFRU"
    "UENvbm5lY3Rpb24oaG9zdCwgcG9ydCwgdGltZW91dD10aW1lb3V0KQoKICAgICAgICBzZW5kX2hlYWRlcnMgPSBkaWN0KGhl"
    "YWRlcnMpCiAgICAgICAgaWYgIkhvc3QiIG5vdCBpbiBzZW5kX2hlYWRlcnM6CiAgICAgICAgICAgIHNlbmRfaGVhZGVyc1si"
    "SG9zdCJdID0gaG9zdF9vdmVycmlkZSBvciAoaG9zdCBpZiBub3QgcGFyc2VkLnBvcnQgZWxzZSBmIntob3N0fTp7cGFyc2Vk"
    "LnBvcnR9IikKICAgICAgICBlbHNlOgogICAgICAgICAgICBwYXNzCgogICAgICAgIGNvbm4ucmVxdWVzdChtZXRob2QsIHBh"
    "dGgsIGhlYWRlcnM9c2VuZF9oZWFkZXJzKQogICAgICAgIHJlc3AgPSBjb25uLmdldHJlc3BvbnNlKCkKICAgICAgICBzdGF0"
    "dXMgPSByZXNwLnN0YXR1cwogICAgICAgIHJlc3BfaGVhZGVycyA9IGRpY3QocmVzcC5nZXRoZWFkZXJzKCkpCiAgICAgICAg"
    "Ym9keSA9IHJlc3AucmVhZCg1MDAwMDApCiAgICAgICAgY29ubi5jbG9zZSgpCgogICAgICAgIHJlc3VsdCA9IEh0dHBSZXN1"
    "bHQoc3RhdHVzPXN0YXR1cywgaGVhZGVycz1yZXNwX2hlYWRlcnMsIGJvZHk9Ym9keSwgZmluYWxfdXJsPXVybCkKCiAgICAg"
    "ICAgaWYgZm9sbG93X3JlZGlyZWN0cyBhbmQgc3RhdHVzIGluICgzMDEsIDMwMiwgMzAzLCAzMDcsIDMwOCkgYW5kIG1heF9y"
    "ZWRpcmVjdHMgPiAwOgogICAgICAgICAgICBsb2NhdGlvbiA9IHJlc3BfaGVhZGVycy5nZXQoIkxvY2F0aW9uIikgb3IgcmVz"
    "cF9oZWFkZXJzLmdldCgibG9jYXRpb24iKQogICAgICAgICAgICBpZiBsb2NhdGlvbjoKICAgICAgICAgICAgICAgIG5leHRf"
    "dXJsID0gdXJsam9pbih1cmwsIGxvY2F0aW9uKQogICAgICAgICAgICAgICAgcmV0dXJuIHJhd19yZXF1ZXN0KG5leHRfdXJs"
    "LCBtZXRob2QsIGV4dHJhX2hlYWRlcnMsIHRpbWVvdXQsIGluc2VjdXJlLAogICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICBmb2xsb3dfcmVkaXJlY3RzLCBtYXhfcmVkaXJlY3RzIC0gMSkKICAgICAgICByZXR1cm4gcmVzdWx0CiAgICBl"
    "eGNlcHQgc3NsLlNTTENlcnRWZXJpZmljYXRpb25FcnJvciBhcyBlOgogICAgICAgICMgaW5zZWN1cmU9VHJ1ZSBzZXRzIHZl"
    "cmlmeV9tb2RlPUNFUlRfTk9ORSBhYm92ZSwgd2hpY2ggbWVhbnMKICAgICAgICAjIE9wZW5TU0wgbmV2ZXIgcmFpc2VzIHRo"
    "aXMgaW4gdGhlIGZpcnN0IHBsYWNlIHdoZW4gLS1pbnNlY3VyZSB3YXMKICAgICAgICAjIHVzZWQgLSBzbyByZWFjaGluZyB0"
    "aGlzIGJyYW5jaCBhbHdheXMgbWVhbnMgdmVyaWZpY2F0aW9uIHdhcyBPTgogICAgICAgICMgYW5kIGdlbnVpbmVseSBmYWls"
    "ZWQuIFRoZSBleGFjdCBlcnJvciB0ZXh0IFB5dGhvbidzIHNzbCBtb2R1bGUKICAgICAgICAjIHJhaXNlcyBmb3IgYSBicm9r"
    "ZW4vc2VsZi1zaWduZWQvaW5jb21wbGV0ZSBjaGFpbiAoImNlcnRpZmljYXRlCiAgICAgICAgIyB2ZXJpZnkgZmFpbGVkOiB1"
    "bmFibGUgdG8gZ2V0IGxvY2FsIGlzc3VlciBjZXJ0aWZpY2F0ZSIsIGV0Yy4pIGlzCiAgICAgICAgIyBhY2N1cmF0ZSBidXQg"
    "ZG9lc24ndCBzYXkgd2hhdCB0byBETyBhYm91dCBpdCAtIGV2ZXJ5IG9uZSBvZiB0aGUKICAgICAgICAjIH4zMCBjaGVja18q"
    "KCkgZnVuY3Rpb25zIHJvdXRlcyBIVFRQUyByZXF1ZXN0cyB0aHJvdWdoIGhlcmUsIHNvCiAgICAgICAgIyBmaXhpbmcgdGhl"
    "IG1lc3NhZ2Ugb25jZSBoZXJlIGZpeGVzIGl0IGV2ZXJ5d2hlcmUgaXQgY2FuIHN1cmZhY2UsCiAgICAgICAgIyBpbnN0ZWFk"
    "IG9mIG9ubHkgd2hlcmV2ZXIgYSBjaGVjayBoYXBwZW5lZCB0byBwcmludCBpdC4gU2VlIGFsc28KICAgICAgICAjIHRoZSBT"
    "U0wgY2VydC12ZXJpZnkgY2FsbG91dCBpbiBwcmludF9zdW1tYXJ5KCksIHdoaWNoIHN1cmZhY2VzCiAgICAgICAgIyB0aGlz"
    "IHNhbWUgY2xhc3Mgb2YgZmFpbHVyZSBhcyBhIHNpbmdsZSB0b3Atb2Ytc3VtbWFyeSBub3RlIHdoZW4KICAgICAgICAjIGl0"
    "IGFmZmVjdHMgc2V2ZXJhbCByb3dzLCBpbnN0ZWFkIG9mIGl0IG9ubHkgYXBwZWFyaW5nIHNjYXR0ZXJlZAogICAgICAgICMg"
    "YWNyb3NzIGluZGl2aWR1YWwgZXZpZGVuY2UgdGV4dC4KICAgICAgICByZXR1cm4gSHR0cFJlc3VsdChlcnJvcj1mIntfU1NM"
    "X1ZFUklGWV9ISU5UX01BUktFUn0ge2V9IC0gaWYgdGhpcyBpcyBhbiBleHBlY3RlZCBzZWxmLXNpZ25lZC9pbnRlcm5hbC9V"
    "QVQgIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmImNlcnRpZmljYXRlLCByZS1ydW4gd2l0aCAtLWluc2Vj"
    "dXJlIHRvIHNraXAgdmVyaWZpY2F0aW9uIGFuZCB0ZXN0IGFueXdheTsgaWYgIgogICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICBmInlvdSBleHBlY3RlZCB0aGlzIHRvIGJlIGEgcmVhbCwgdHJ1c3RlZCBjZXJ0aWZpY2F0ZSwgdGhpcyBJUyBh"
    "IGxlZ2l0aW1hdGUgIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmImZpbmRpbmcgKFdBLVRMUy00MDctc3R5"
    "bGUgY2hhaW4gaXNzdWUpIC0gb3IgeW91ciBtYWNoaW5lJ3Mgb3duIENBIGJ1bmRsZSBtYXkgIgogICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICBmImJlIG91dCBvZiBkYXRlICh0cnk6IHBpcDMgaW5zdGFsbCAtLXVwZ3JhZGUgY2VydGlmaSku"
    "IikKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICByZXR1cm4gSHR0cFJlc3VsdChlcnJvcj1zdHIoZSkpCgoK"
    "ZGVmIGJhc2VfdXJsX29mKHVybCk6CiAgICAiIiJzY2hlbWU6Ly9ob3N0Wzpwb3J0XS8gLSBhbHdheXMgdGhlIFNJVEUgUk9P"
    "VCwgZHJvcHBpbmcgYW55IHBhdGguCiAgICBVc2VkIG9uY2UgcGVyIGlucHV0IFVSTCB0byBjb21wdXRlIHRoZSBhdXRvbWF0"
    "aWMgc2Vjb25kICgic2l0ZS1yb290IikKICAgIHBhc3M7IHNlZSBkaXJfb2YoKSBiZWxvdyBmb3IgdGhlIHBlci1wYXNzIGRp"
    "cmVjdG9yeSB1c2VkIGZvciBwcm9iZXMuIiIiCiAgICBwID0gdXJscGFyc2UodXJsKQogICAgcG9ydF9wYXJ0ID0gZiI6e3Au"
    "cG9ydH0iIGlmIHAucG9ydCBhbmQgbm90ICgocC5zY2hlbWUgPT0gImh0dHBzIiBhbmQgcC5wb3J0ID09IDQ0Mykgb3IKICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAocC5zY2hlbWUgPT0gImh0dHAiIGFuZCBw"
    "LnBvcnQgPT0gODApKSBlbHNlICIiCiAgICByZXR1cm4gZiJ7cC5zY2hlbWV9Oi8ve3AuaG9zdG5hbWV9e3BvcnRfcGFydH0v"
    "IgoKCmRlZiBkaXJfb2YodXJsKToKICAgICIiInNjaGVtZTovL2hvc3RbOnBvcnRdLzxwYXRoPi8gLSB0aGUgVVJMIGN1cnJl"
    "bnRseSBiZWluZyB0ZXN0ZWQsCiAgICB0cmVhdGVkIGFzIGEgZGlyZWN0b3J5ICh0cmFpbGluZyBzbGFzaCBhZGRlZCBpZiBt"
    "aXNzaW5nKS4gUGF0aC1iYXNlZAogICAgcHJvYmVzIGFyZSBqb2luZWQgdW5kZXIgVEhJUywgc28gd2hlbiB0aGUgY3VycmVu"
    "dCBwYXNzJ3MgdGFyZ2V0IGlzCiAgICBodHRwczovL2hvc3Qvc3ViZm9sZGVyLCBwcm9iZXMgbGFuZCBhdCBodHRwczovL2hv"
    "c3Qvc3ViZm9sZGVyL3JvYm90cy50eHQKICAgIGV0Yy47IHdoZW4gdGhlIGN1cnJlbnQgcGFzcydzIHRhcmdldCBpcyB0aGUg"
    "c2l0ZSByb290LCB0aGV5IGxhbmQgYXQKICAgIGh0dHBzOi8vaG9zdC9yb2JvdHMudHh0IC0gc2FtZSBoZWxwZXIsIGNvcnJl"
    "Y3QgZWl0aGVyIHdheS4iIiIKICAgIHAgPSB1cmxwYXJzZSh1cmwpCiAgICBwb3J0X3BhcnQgPSBmIjp7cC5wb3J0fSIgaWYg"
    "cC5wb3J0IGFuZCBub3QgKChwLnNjaGVtZSA9PSAiaHR0cHMiIGFuZCBwLnBvcnQgPT0gNDQzKSBvcgogICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIChwLnNjaGVtZSA9PSAiaHR0cCIgYW5kIHAucG9ydCA9PSA4"
    "MCkpIGVsc2UgIiIKICAgIHBhdGggPSBwLnBhdGggb3IgIi8iCiAgICBpZiBub3QgcGF0aC5lbmRzd2l0aCgiLyIpOgogICAg"
    "ICAgIHBhdGggKz0gIi8iCiAgICByZXR1cm4gZiJ7cC5zY2hlbWV9Oi8ve3AuaG9zdG5hbWV9e3BvcnRfcGFydH17cGF0aH0i"
    "CgoKZGVmIGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgpOgogICAgIyBwYXRoIGNvbnN0YW50cyBiZWxvdyBhcmUgd3JpdHRlbiBh"
    "cyAiL3JvYm90cy50eHQiIGV0Yy4gZm9yCiAgICAjIHJlYWRhYmlsaXR5OyBzdHJpcCB0aGUgbGVhZGluZyAiLyIgYmVmb3Jl"
    "IGpvaW5pbmcgc28gdXJsam9pbiB0cmVhdHMKICAgICMgdGhlbSBhcyByZWxhdGl2ZSB0byBgYmFzZWAncyBkaXJlY3Rvcnkg"
    "aW5zdGVhZCBvZiByZXNldHRpbmcgdG8gdGhlCiAgICAjIGRvbWFpbiByb290ICh3aGljaCBpcyB3aGF0IGEgbGVhZGluZyAi"
    "LyIgbWVhbnMgdG8gdXJsam9pbikuCiAgICByZXR1cm4gdXJsam9pbihiYXNlLCBwYXRoLmxzdHJpcCgiLyIpKQoKCiMgLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0K"
    "IyBDb21tYW5kLWxpbmUgdG9vbCBpbnRlZ3JhdGlvbiAoY3VybCAvIG5tYXAgLyBzc2x5emUgLyBzc2xzY2FuIC8gdGVzdHNz"
    "bC5zaCkKIyAtIHVzZWQgQVVUT01BVElDQUxMWSB3aGVuZXZlciB0aGUgdG9vbCBpcyBmb3VuZCBvbiBQQVRILCBubyBmbGFn"
    "IG5lZWRlZAojICAgKG9wdCBPVVQgd2l0aCAtLW5vLWNsaS10b29scykuIFJlcXVlc3RlZCBkaXJlY3RseTogIkkgaGF2ZSBj"
    "dWxzIGFuZAojICAgbm1hcCBhbmQgc3NsYWx5emVyIGluc3RhbGxlZCBpbiB0aGUgcmVtb3RlIHNlcnZlciAuLi4gY2hlY2sg"
    "d2l0CiMgICBoY29tbWFuZCBsaW5lIHRvb2xzIEkgaGF2ZSBub3Qgc2VlbiBzeSBzY3JlZW5zaG90cyBmb3IgZ2l2ZSBmaW5k"
    "aW5ncy4iCiMgICBFdmVyeXRoaW5nIGhlcmUgaXMgUkVBRC1PTkxZIChHRVQgLyBUTFMgaGFuZHNoYWtlIHByb2JlcyBvbmx5"
    "KSAtIG5vCiMgICBjcmVkZW50aWFscyBhcmUgZXZlciB1c2VkLCBzZW50LCBvciByZXF1ZXN0ZWQgYW55d2hlcmUgaW4gdGhp"
    "cyBzY3JpcHQsCiMgICBwZXIgIm5ldmVyIHRha2UgdGhlIGNyZWRldGlscyBhbHNvIHRvIG5hdmlnYXRlIGluc2lkZSIuIFdo"
    "ZW4gYSB0b29sCiMgICBpc24ndCBpbnN0YWxsZWQsIGV2ZXJ5IGNhbGxlciBiZWxvdyBmYWxscyBiYWNrIHRvIHRoZSBleGFj"
    "dCBzYW1lCiMgICBQeXRob24tb25seS9NQU5VQUwgYmVoYXZpb3VyIHRoaXMgc2NyaXB0IGFsd2F5cyBoYWQgLSBhIG1pc3Np"
    "bmcgdG9vbAojICAgbmV2ZXIgYnJlYWtzIG9yIGJsb2NrcyB0aGUgc2Nhbi4KIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKQ01EX0JMT0NLX01BUktFUiA9ICJc"
    "blxuJCAiICAjIHJlbmRlcl9ldmlkZW5jZV9pbWFnZSgpIHN3aXRjaGVzIHRvIHRoZSB0ZXJtaW5hbC1zdHlsZSBjYXJkIG9u"
    "IHRoaXMgbWFya2VyCk1BWF9DTURfT1VUUFVUX0NIQVJTID0gNDAwMAoKCmRlZiBfY2xpX2F2YWlsYWJsZShuYW1lKToKICAg"
    "IHJldHVybiBzaHV0aWwud2hpY2gobmFtZSkgaXMgbm90IE5vbmUKCgpkZWYgX2Zvcm1hdF9jbWRfYmxvY2soY21kX2xpc3Qs"
    "IG91dHB1dF90ZXh0LCBtYXhfbGVuPU1BWF9DTURfT1VUUFVUX0NIQVJTKToKICAgICIiIkFwcGVuZHMgYSByZWFsICIkIDxj"
    "b21tYW5kPlxcbjxvdXRwdXQ+IiBibG9jayB0byBhbiBldmlkZW5jZSBzdHJpbmcuCiAgICBUaGlzIGlzIHdoYXQgbWFrZXMg"
    "cmVuZGVyX2V2aWRlbmNlX2ltYWdlKCkgc3dpdGNoIHRvIGEgdGVybWluYWwtc3R5bGUKICAgIHNjcmVlbnNob3QgaW5zdGVh"
    "ZCBvZiB0aGUgZ2VuZXJpYyBzdW1tYXJ5IGNhcmQsIGFuZCBzaG93cyB1cCB2ZXJiYXRpbQogICAgaW4gdGhlIEpTT04vQ1NW"
    "L1hMU1ggZXZpZGVuY2UgY29sdW1uIGFzIGdlbnVpbmUgY29tbWFuZC1saW5lIHByb29mCiAgICByYXRoZXIgdGhhbiBhIHN5"
    "bnRoZXNpemVkIHN1bW1hcnkuIiIiCiAgICBjbWRfc3RyID0gIiAiLmpvaW4oY21kX2xpc3QpCiAgICBvdXQgPSAob3V0cHV0"
    "X3RleHQgb3IgIiIpLnN0cmlwKCkKICAgIGlmIGxlbihvdXQpID4gbWF4X2xlbjoKICAgICAgICBvdXQgPSBvdXRbOm1heF9s"
    "ZW5dICsgZiJcbi4uLiAodHJ1bmNhdGVkLCB7bGVuKG91dCkgLSBtYXhfbGVufSBtb3JlIGNoYXJzIC0gc2VlIEpTT04gZm9y"
    "IGZ1bGwgb3V0cHV0KSIKICAgIHJldHVybiBmIntDTURfQkxPQ0tfTUFSS0VSfXtjbWRfc3RyfVxue291dH0iCgoKZGVmIHJ1"
    "bl9jdXJsX3dpdGhfaG9zdF9oZWFkZXIodXJsLCBob3N0X3ZhbHVlLCB0aW1lb3V0PTEwLCBpbnNlY3VyZT1GYWxzZSk6CiAg"
    "ICAiIiJTYW1lIGlkZWEgYXMgcnVuX2N1cmxfaGVhZGVycygpIGJ1dCBzZW5kcyBhIGN1c3RvbSBIb3N0OiBoZWFkZXIgdmlh"
    "CiAgICBgY3VybCAtSCAiSG9zdDogLi4uImAgLSB1c2VkIGJ5IGNoZWNrX2hvc3RfaGVhZGVyKCkgc28gVEhBVCBjaGVjayBh"
    "bHNvCiAgICBnZXRzIHJlYWwgY29tbWFuZC1saW5lIGV2aWRlbmNlL3Rlcm1pbmFsIHNjcmVlbnNob3QgaW5zdGVhZCBvZiB0"
    "aGUKICAgIGdlbmVyaWMgc3VtbWFyeSBjYXJkLiBSZXF1ZXN0ZWQgZGlyZWN0bHkgYWZ0ZXIgc2VlaW5nIGEgSG9zdCBIZWFk"
    "ZXIKICAgIGZpbmRpbmcncyBzY3JlZW5zaG90IHdpdGhvdXQgY29tbWFuZCBvdXRwdXQ6ICJnaXZlIHRoZSBjb21tYWRuIG91"
    "dAogICAgcHV0IG9mIHByb3BlciBvdXQgcHV0Ii4iIiIKICAgIGlmIG5vdCBfY2xpX2F2YWlsYWJsZSgiY3VybCIpOgogICAg"
    "ICAgIHJldHVybiBOb25lCiAgICBjbWQgPSBbImN1cmwiLCAiLXNTIiwgIi1EIiwgIi0iLCAiLW8iLCAiL2Rldi9udWxsIiwg"
    "Ii0tbWF4LXRpbWUiLCBzdHIoaW50KHRpbWVvdXQpIG9yIDEwKSwKICAgICAgICAgICAiLUEiLCBERUZBVUxUX1VBLCAiLUgi"
    "LCBmIkhvc3Q6IHtob3N0X3ZhbHVlfSJdCiAgICBpZiBpbnNlY3VyZToKICAgICAgICBjbWQuYXBwZW5kKCItayIpCiAgICBj"
    "bWQuYXBwZW5kKHVybCkKICAgIHRyeToKICAgICAgICBwcm9jID0gc3VicHJvY2Vzcy5ydW4oY21kLCBjYXB0dXJlX291dHB1"
    "dD1UcnVlLCB0aW1lb3V0PXRpbWVvdXQgKyAxMCkKICAgICAgICBvdXQgPSBwcm9jLnN0ZG91dC5kZWNvZGUoInV0Zi04Iiwg"
    "ZXJyb3JzPSJyZXBsYWNlIikKICAgICAgICBlcnIgPSBwcm9jLnN0ZGVyci5kZWNvZGUoInV0Zi04IiwgZXJyb3JzPSJyZXBs"
    "YWNlIikuc3RyaXAoKQogICAgICAgIGlmIGVycjoKICAgICAgICAgICAgb3V0ICs9ICgiXG4iIGlmIG91dCBlbHNlICIiKSAr"
    "IGVycgogICAgICAgIHJldHVybiBjbWQsIG91dAogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIHJldHVybiBj"
    "bWQsIGYiKGN1cmwgZXhlY3V0aW9uIGZhaWxlZDoge2V9KSIKCgpkZWYgcnVuX2N1cmxfaGVhZGVycyh1cmwsIHRpbWVvdXQ9"
    "MTAsIGluc2VjdXJlPUZhbHNlKToKICAgICIiIlJ1bnMgYGN1cmwgLXNTIC1EIC0gLW8gL2Rldi9udWxsIC4uLmAgYWdhaW5z"
    "dCBgdXJsYCBhbmQgcmV0dXJucwogICAgKGNtZF9saXN0LCBvdXRwdXRfdGV4dCksIG9yIE5vbmUgaWYgY3VybCBpc24ndCBv"
    "biBQQVRILiBBIG5vbi0yeHgvM3h4CiAgICBIVFRQIHN0YXR1cyBpcyBOT1QgdHJlYXRlZCBhcyBmYWlsdXJlIGhlcmUgLSBj"
    "dXJsIHN0aWxsIHByaW50cyB0aGUKICAgIHJlYWwgcmVzcG9uc2UgaGVhZGVycyBlaXRoZXIgd2F5LCB3aGljaCBpcyB0aGUg"
    "cG9pbnQuIiIiCiAgICBpZiBub3QgX2NsaV9hdmFpbGFibGUoImN1cmwiKToKICAgICAgICByZXR1cm4gTm9uZQogICAgY21k"
    "ID0gWyJjdXJsIiwgIi1zUyIsICItRCIsICItIiwgIi1vIiwgIi9kZXYvbnVsbCIsICItLW1heC10aW1lIiwgc3RyKGludCh0"
    "aW1lb3V0KSBvciAxMCksCiAgICAgICAgICAgIi1BIiwgREVGQVVMVF9VQV0KICAgIGlmIGluc2VjdXJlOgogICAgICAgIGNt"
    "ZC5hcHBlbmQoIi1rIikKICAgIGNtZC5hcHBlbmQodXJsKQogICAgdHJ5OgogICAgICAgIHByb2MgPSBzdWJwcm9jZXNzLnJ1"
    "bihjbWQsIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRpbWVvdXQ9dGltZW91dCArIDEwKQogICAgICAgIG91dCA9IHByb2Muc3Rk"
    "b3V0LmRlY29kZSgidXRmLTgiLCBlcnJvcnM9InJlcGxhY2UiKQogICAgICAgIGVyciA9IHByb2Muc3RkZXJyLmRlY29kZSgi"
    "dXRmLTgiLCBlcnJvcnM9InJlcGxhY2UiKS5zdHJpcCgpCiAgICAgICAgaWYgZXJyOgogICAgICAgICAgICBvdXQgKz0gKCJc"
    "biIgaWYgb3V0IGVsc2UgIiIpICsgZXJyCiAgICAgICAgcmV0dXJuIGNtZCwgb3V0CiAgICBleGNlcHQgRXhjZXB0aW9uIGFz"
    "IGU6CiAgICAgICAgcmV0dXJuIGNtZCwgZiIoY3VybCBleGVjdXRpb24gZmFpbGVkOiB7ZX0pIgoKCiMgVHJpZWQgaW4gdGhp"
    "cyBvcmRlciAtIGZpcnN0IG9uZSBmb3VuZCBvbiBQQVRIIGlzIHVzZWQuIG5tYXAgaXMgdHJpZWQKIyBmaXJzdCBzaW5jZSBz"
    "c2wtZW51bS1jaXBoZXJzIG91dHB1dCBpcyB3aGF0IHRoZSBwYXJzZXIgYmVsb3cgdW5kZXJzdGFuZHMKIyBiZXN0LCBhbmQg"
    "dGhlIHVzZXIgY29uZmlybWVkIG5tYXAgaXMgaW5zdGFsbGVkOyBzc2x5emUvc3Nsc2Nhbi90ZXN0c3NsLnNoCiMgYXJlIHVz"
    "ZWQgYXMtaXMgaWYgbm1hcCBpc24ndCBwcmVzZW50LgpfU1NMX0NMSV9UT09MUyA9IFsKICAgICgibm1hcCIsIGxhbWJkYSBo"
    "LCBwLCB0OiBbIm5tYXAiLCAiLVBuIiwgIi0tc2NyaXB0IiwgInNzbC1lbnVtLWNpcGhlcnMiLCAiLXAiLCBzdHIocCksIGhd"
    "KSwKICAgICgic3NseXplIiwgbGFtYmRhIGgsIHAsIHQ6IFsic3NseXplIiwgZiJ7aH06e3B9Il0pLAogICAgKCJzc2xzY2Fu"
    "IiwgbGFtYmRhIGgsIHAsIHQ6IFsic3Nsc2NhbiIsIGYie2h9OntwfSJdKSwKICAgICgidGVzdHNzbC5zaCIsIGxhbWJkYSBo"
    "LCBwLCB0OiBbInRlc3Rzc2wuc2giLCAiLS1mYXN0IiwgZiJ7aH06e3B9Il0pLApdCgoKZGVmIHJ1bl9zc2xfY2xpX3NjYW4o"
    "aG9zdCwgcG9ydCwgdGltZW91dD00NSk6CiAgICAiIiJSdW5zIHRoZSBGSVJTVCBhdmFpbGFibGUgU1NML1RMUyBDTEkgc2Nh"
    "bm5lciAoc2VlIF9TU0xfQ0xJX1RPT0xTKQogICAgYWdhaW5zdCBob3N0OnBvcnQgYW5kIHJldHVybnMgKHRvb2xfbmFtZSwg"
    "Y21kX2xpc3QsIG91dHB1dF90ZXh0KSwgb3IKICAgIE5vbmUgaWYgbm9uZSBvZiB0aGVtIGFyZSBpbnN0YWxsZWQuIE9ubHkg"
    "b25lIHRvb2wgaXMgcnVuIChub3QgYWxsCiAgICBmb3VyKSB0byBrZWVwIHNjYW4gdGltZSByZWFzb25hYmxlLiIiIgogICAg"
    "Zm9yIG5hbWUsIGJ1aWxkX2NtZCBpbiBfU1NMX0NMSV9UT09MUzoKICAgICAgICBpZiBub3QgX2NsaV9hdmFpbGFibGUobmFt"
    "ZSk6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgY21kID0gYnVpbGRfY21kKGhvc3QsIHBvcnQsIHRpbWVvdXQpCiAg"
    "ICAgICAgdHJ5OgogICAgICAgICAgICBwcm9jID0gc3VicHJvY2Vzcy5ydW4oY21kLCBjYXB0dXJlX291dHB1dD1UcnVlLCB0"
    "aW1lb3V0PXRpbWVvdXQpCiAgICAgICAgICAgIG91dCA9IHByb2Muc3Rkb3V0LmRlY29kZSgidXRmLTgiLCBlcnJvcnM9InJl"
    "cGxhY2UiKQogICAgICAgICAgICBlcnIgPSBwcm9jLnN0ZGVyci5kZWNvZGUoInV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIiku"
    "c3RyaXAoKQogICAgICAgICAgICBpZiBlcnI6CiAgICAgICAgICAgICAgICBvdXQgKz0gKCJcbiIgaWYgb3V0IGVsc2UgIiIp"
    "ICsgZXJyCiAgICAgICAgICAgIHJldHVybiBuYW1lLCBjbWQsIG91dAogICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLlRpbWVv"
    "dXRFeHBpcmVkOgogICAgICAgICAgICByZXR1cm4gbmFtZSwgY21kLCBmIihzY2FuIHRpbWVkIG91dCBhZnRlciB7dGltZW91"
    "dH1zIC0gdGFyZ2V0IG1heSBiZSBzbG93L3VucmVhY2hhYmxlLCB0cnkgYSBsb25nZXIgLS10aW1lb3V0KSIKICAgICAgICBl"
    "eGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgIHJldHVybiBuYW1lLCBjbWQsIGYiKHtuYW1lfSBleGVjdXRpb24g"
    "ZmFpbGVkOiB7ZX0pIgogICAgcmV0dXJuIE5vbmUKCgpfV0VBS19DSVBIRVJfSElOVFMgPSByZS5jb21waWxlKHIiXGIoUkM0"
    "fERFU3wzREVTfE5VTEx8RVhQT1JUfE1ENXxhbm9ufElERUF8U0VFRClcYiIsIHJlLklHTk9SRUNBU0UpCl9XRUFLX1RMU19W"
    "RVJTSU9OX0hJTlRTID0gcmUuY29tcGlsZShyIlxiKFNTTHYyfFNTTHYzfFRMU3YxXC4wfFRMU3YxXC4xfFRMUyAxXC4wfFRM"
    "UyAxXC4xKVxiIikKCgpkZWYgX3BhcnNlX3NzbF9jbGlfb3V0cHV0KG91dHB1dF90ZXh0KToKICAgICIiIkJlc3QtZWZmb3J0"
    "IHBhcnNlIG9mIHdoaWNoZXZlciBTU0wgQ0xJIHRvb2wgcmFuLCB1c2VkIHRvIHR1cm4KICAgIFdBLVRMUy00MDIvNDA0IGlu"
    "dG8gYSByZWFsIFBBU1MvRkFJTCBpbnN0ZWFkIG9mIGxlYXZpbmcgdGhlbSBNQU5VQUwuCiAgICBEZWxpYmVyYXRlbHkgY29u"
    "c2VydmF0aXZlIC0gYW4gaW5jb25jbHVzaXZlIHBhcnNlIGZhbGxzIGJhY2sgdG8KICAgIElORk8vTUFOVUFMIHJhdGhlciB0"
    "aGFuIGd1ZXNzaW5nIGEgUEFTUy4KCiAgICBPbmx5IHNjYW5zIGxpbmVzIHRoYXQgYWN0dWFsbHkgbG9vayBsaWtlIGNpcGhl"
    "ci1zdWl0ZSBvdXRwdXQgKGNvbnRhaW4KICAgICJfV0lUSF8iLCBzdGFydCB3aXRoIFRMU18vU1NMXywgb3IgY29tZSBmcm9t"
    "IHNzbHNjYW4vdGVzdHNzbC1zdHlsZQogICAgIkFjY2VwdGVkIC4uLiIgbGluZXMpIC0gTk9UIHRoZSB3aG9sZSByYXcgYmxv"
    "Yi4gbm1hcCdzIHNzbC1lbnVtLWNpcGhlcnMKICAgIGFsc28gcHJpbnRzIGFuIHVucmVsYXRlZCAiY29tcHJlc3NvcnM6IE5V"
    "TEwiIGxpbmUgKE5VTEwgPSBubyBUTFMKICAgIGNvbXByZXNzaW9uIG5lZ290aWF0ZWQsIGkuZS4gQ1JJTUUtc2FmZSAtIGEg"
    "R09PRCB0aGluZyksIGFuZCBtYXRjaGluZwogICAgIk5VTEwiIHRoZXJlIGFzIGEgd2Vhay1jaXBoZXIgaGl0IHdvdWxkIGJl"
    "IGEgZmFsc2UgcG9zaXRpdmUuIiIiCiAgICBpZiBub3Qgb3V0cHV0X3RleHQ6CiAgICAgICAgcmV0dXJuIHsid2Vha19jaXBo"
    "ZXJzIjogTm9uZSwgIndlYWtfcHJvdG9jb2xzIjogTm9uZSwgImxlYXN0X3N0cmVuZ3RoIjogTm9uZX0KCiAgICBjaXBoZXJf"
    "bGluZXMgPSAiXG4iLmpvaW4oCiAgICAgICAgbGluZSBmb3IgbGluZSBpbiBvdXRwdXRfdGV4dC5zcGxpdGxpbmVzKCkKICAg"
    "ICAgICBpZiAiY29tcHJlc3MiIG5vdCBpbiBsaW5lLmxvd2VyKCkKICAgICAgICBhbmQgKCJfV0lUSF8iIGluIGxpbmUgb3Ig"
    "IlRMU18iIGluIGxpbmUgb3IgIlNTTF8iIGluIGxpbmUKICAgICAgICAgICAgIG9yIHJlLnNlYXJjaChyIlxiKEFjY2VwdGVk"
    "fFByZWZlcnJlZHxSZWplY3RlZClcYiIsIGxpbmUsIHJlLklHTk9SRUNBU0UpKQogICAgKQoKICAgIHdlYWtfY2lwaGVycyA9"
    "IHNvcnRlZChzZXQobS5ncm91cCgwKSBmb3IgbSBpbiBfV0VBS19DSVBIRVJfSElOVFMuZmluZGl0ZXIoY2lwaGVyX2xpbmVz"
    "KSkpCiAgICB3ZWFrX3Byb3RvY29scyA9IHNvcnRlZChzZXQobS5ncm91cCgwKSBmb3IgbSBpbiBfV0VBS19UTFNfVkVSU0lP"
    "Tl9ISU5UUy5maW5kaXRlcihvdXRwdXRfdGV4dCkpKQogICAgbSA9IHJlLnNlYXJjaChyImxlYXN0IHN0cmVuZ3RoOlxzKihb"
    "QS1aYS16XSspIiwgb3V0cHV0X3RleHQsIHJlLklHTk9SRUNBU0UpICAjIG5tYXAgc3NsLWVudW0tY2lwaGVycwogICAgbGVh"
    "c3Rfc3RyZW5ndGggPSBtLmdyb3VwKDEpIGlmIG0gZWxzZSBOb25lCiAgICByZXR1cm4geyJ3ZWFrX2NpcGhlcnMiOiB3ZWFr"
    "X2NpcGhlcnMgb3IgTm9uZSwgIndlYWtfcHJvdG9jb2xzIjogd2Vha19wcm90b2NvbHMgb3IgTm9uZSwKICAgICAgICAgICAg"
    "ImxlYXN0X3N0cmVuZ3RoIjogbGVhc3Rfc3RyZW5ndGh9CgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDEuIEhUVFAgU2VjdXJpdHkgSGVhZGVycyAtIFdB"
    "LUhEUi0zOTIuLjQwMQojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tCgpkZWYgY2hlY2tfc2VjdXJpdHlfaGVhZGVycyhmdWxsX3VybCwgYXJncyk6CiAgICByID0g"
    "cmF3X3JlcXVlc3QoZnVsbF91cmwsICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3Vy"
    "ZSkKICAgIGlmIHIuZXJyb3I6CiAgICAgICAgZm9yIGNpZCwgbmFtZSwgc2V2LCBwcmkgaW4gWwogICAgICAgICAgICAoIldB"
    "LUhEUi0zOTIiLCAiQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgcHJlc2VudCBhbmQgc3RyaWN0IiwgIk1lZGl1bSIsICJQMiIp"
    "LAogICAgICAgICAgICAoIldBLUhEUi0zOTMiLCAiWC1GcmFtZS1PcHRpb25zOiBTQU1FT1JJR0lOIG9yIERFTlkgcHJlc2Vu"
    "dCIsICJNZWRpdW0iLCAiUDIiKSwKICAgICAgICAgICAgKCJXQS1IRFItMzk0IiwgIlgtQ29udGVudC1UeXBlLU9wdGlvbnM6"
    "IG5vc25pZmYgcHJlc2VudCIsICJMb3ciLCAiUDMiKSwKICAgICAgICAgICAgKCJXQS1IRFItMzk1IiwgIlN0cmljdC1UcmFu"
    "c3BvcnQtU2VjdXJpdHkgKEhTVFMpIHByb3Blcmx5IGNvbmZpZ3VyZWQiLCAiTWVkaXVtIiwgIlAyIiksCiAgICAgICAgICAg"
    "ICgiV0EtSERSLTM5NiIsICJSZWZlcnJlci1Qb2xpY3kgaGVhZGVyIHByZXNlbnQiLCAiTG93IiwgIlAzIiksCiAgICAgICAg"
    "ICAgICgiV0EtSERSLTM5NyIsICJDYWNoZS1Db250cm9sOiBuby1zdG9yZSBvbiBhdXRoZW50aWNhdGVkL3NlbnNpdGl2ZSBw"
    "YWdlcyIsICJNZWRpdW0iLCAiUDIiKSwKICAgICAgICAgICAgKCJXQS1IRFItMzk4IiwgIlBlcm1pc3Npb25zLVBvbGljeSBy"
    "ZXN0cmljdHMgc2Vuc2l0aXZlIGJyb3dzZXIgQVBJcyIsICJMb3ciLCAiUDMiKSwKICAgICAgICAgICAgKCJXQS1IRFItMzk5"
    "IiwgIkhUVFBTIGVuZm9yY2VkIC0gSFRUUCByZWRpcmVjdHMgdG8gSFRUUFMiLCAiSGlnaCIsICJQMSIpLAogICAgICAgICAg"
    "ICAoIldBLUhEUi00MDAiLCAiVmVyYm9zZSBlcnJvciBtZXNzYWdlcyAvIHN0YWNrIHRyYWNlcyBvbiA0eHgvNXh4IiwgIk1l"
    "ZGl1bSIsICJQMiIpLAogICAgICAgICAgICAoIldBLUhEUi00MDEiLCAiU2VydmVyIHZlcnNpb24gZGlzY2xvc3VyZSBpbiBy"
    "ZXNwb25zZSBoZWFkZXJzIiwgIkxvdyIsICJQMyIpLAogICAgICAgIF06CiAgICAgICAgICAgIGFkZChmdWxsX3VybCwgY2lk"
    "LCAiSFRUUCBTZWN1cml0eSBIZWFkZXJzIiwgbmFtZSwgc2V2LCBwcmksICJFUlJPUiIsCiAgICAgICAgICAgICAgICBmIkNv"
    "dWxkIG5vdCBjb25uZWN0OiB7ci5lcnJvcn0iKQogICAgICAgIHJldHVybiByLCAiIgoKICAgIGN1cmxfcmVzdWx0ID0gTm9u"
    "ZSBpZiBnZXRhdHRyKGFyZ3MsICJub19jbGlfdG9vbHMiLCBGYWxzZSkgZWxzZSBydW5fY3VybF9oZWFkZXJzKAogICAgICAg"
    "IGZ1bGxfdXJsLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIGN1cmxfYmxvY2sg"
    "PSBfZm9ybWF0X2NtZF9ibG9jayhjdXJsX3Jlc3VsdFswXSwgY3VybF9yZXN1bHRbMV0pIGlmIGN1cmxfcmVzdWx0IGVsc2Ug"
    "IiIKCiAgICBjc3AgPSByLmhlYWRlcigiQ29udGVudC1TZWN1cml0eS1Qb2xpY3kiKQogICAgaWYgbm90IGNzcDoKICAgICAg"
    "ICBhZGQoZnVsbF91cmwsICJXQS1IRFItMzkyIiwgIkhUVFAgU2VjdXJpdHkgSGVhZGVycyIsICJDb250ZW50LVNlY3VyaXR5"
    "LVBvbGljeSBwcmVzZW50IGFuZCBzdHJpY3QiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiLAogICAgICAg"
    "ICAgICAiQ09ORklSTUVEIEJZOiB0aGUgcmVzcG9uc2UgaGVhZGVycyBiZWxvdyBjb250YWluIG5vICdDb250ZW50LVNlY3Vy"
    "aXR5LVBvbGljeScgZW50cnkgYXQgYWxsICIKICAgICAgICAgICAgIihjaGVja2VkIGNhc2UtaW5zZW5zaXRpdmVseSBhY3Jv"
    "c3MgZXZlcnkgaGVhZGVyIHJldHVybmVkKS4iICsgY3VybF9ibG9jaykKICAgIGVsc2U6CiAgICAgICAgbWF0Y2hlZF90b2tl"
    "bnMgPSBbdCBmb3IgdCBpbiAoInVuc2FmZS1pbmxpbmUiLCAidW5zYWZlLWV2YWwiLCAiKiAiKSBpZiB0IGluIGNzcF0KICAg"
    "ICAgICBsb29zZSA9IGJvb2wobWF0Y2hlZF90b2tlbnMpIG9yIGNzcC5zdHJpcCgpLmVuZHN3aXRoKCIqIikKICAgICAgICBp"
    "ZiBsb29zZToKICAgICAgICAgICAgcmVhc29uID0gKGYiQ1NQIGNvbnRhaW5zIHdlYWsgdG9rZW4ocykge21hdGNoZWRfdG9r"
    "ZW5zfSIgaWYgbWF0Y2hlZF90b2tlbnMKICAgICAgICAgICAgICAgICAgICAgICBlbHNlICJDU1AgdmFsdWUgZW5kcyB3aXRo"
    "IGEgYmFyZSB3aWxkY2FyZCAnKiciKQogICAgICAgICAgICBldmlkZW5jZSA9IGYiQ09ORklSTUVEIEJZOiB7cmVhc29ufSAt"
    "IGZ1bGwgaGVhZGVyIHZhbHVlOiB7Y3NwWzozMDBdfSIKICAgICAgICBlbHNlOgogICAgICAgICAgICBldmlkZW5jZSA9IGYi"
    "Q1NQOiB7Y3NwWzozMDBdfSIKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1IRFItMzkyIiwgIkhUVFAgU2VjdXJpdHkgSGVh"
    "ZGVycyIsICJDb250ZW50LVNlY3VyaXR5LVBvbGljeSBwcmVzZW50IGFuZCBzdHJpY3QiLAogICAgICAgICAgICAiTWVkaXVt"
    "IiwgIlAyIiwgIkZBSUwiIGlmIGxvb3NlIGVsc2UgIlBBU1MiLCBldmlkZW5jZSArIGN1cmxfYmxvY2spCgogICAgeGZvID0g"
    "ci5oZWFkZXIoIlgtRnJhbWUtT3B0aW9ucyIpCiAgICBmcmFtZV9hbmNlc3RvcnMgPSAiZnJhbWUtYW5jZXN0b3JzIiBpbiBj"
    "c3AubG93ZXIoKSBpZiBjc3AgZWxzZSBGYWxzZQogICAgaWYgeGZvIGFuZCB4Zm8uc3RyaXAoKS51cHBlcigpIGluICgiREVO"
    "WSIsICJTQU1FT1JJR0lOIik6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5MyIsICJIVFRQIFNlY3VyaXR5IEhl"
    "YWRlcnMiLCAiWC1GcmFtZS1PcHRpb25zOiBTQU1FT1JJR0lOIG9yIERFTlkgcHJlc2VudCIsCiAgICAgICAgICAgICJNZWRp"
    "dW0iLCAiUDIiLCAiUEFTUyIsIGYiWC1GcmFtZS1PcHRpb25zOiB7eGZvfSIgKyBjdXJsX2Jsb2NrKQogICAgZWxpZiBmcmFt"
    "ZV9hbmNlc3RvcnM6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5MyIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMi"
    "LCAiWC1GcmFtZS1PcHRpb25zOiBTQU1FT1JJR0lOIG9yIERFTlkgcHJlc2VudCIsCiAgICAgICAgICAgICJNZWRpdW0iLCAi"
    "UDIiLCAiUEFTUyIsICJObyBYLUZyYW1lLU9wdGlvbnMsIGJ1dCBDU1AgZnJhbWUtYW5jZXN0b3JzIGlzIHNldCAoY292ZXJz"
    "IG1vZGVybiBicm93c2VycykuIiArIGN1cmxfYmxvY2spCiAgICBlbHNlOgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLUhE"
    "Ui0zOTMiLCAiSFRUUCBTZWN1cml0eSBIZWFkZXJzIiwgIlgtRnJhbWUtT3B0aW9uczogU0FNRU9SSUdJTiBvciBERU5ZIHBy"
    "ZXNlbnQiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiLAogICAgICAgICAgICBmIkNPTkZJUk1FRCBCWTog"
    "WC1GcmFtZS1PcHRpb25zIGhlYWRlciB2YWx1ZSBpcyAne3hmbyBvciAnKG5vdCBwcmVzZW50IGluIHJlc3BvbnNlIGhlYWRl"
    "cnMpJ30nICIKICAgICAgICAgICAgIihleHBlY3RlZCBERU5ZIG9yIFNBTUVPUklHSU4pIGFuZCB0aGUgQ1NQIGhhcyBubyBm"
    "cmFtZS1hbmNlc3RvcnMgZGlyZWN0aXZlIGVpdGhlci4iICsgY3VybF9ibG9jaykKCiAgICB4Y3RvID0gci5oZWFkZXIoIlgt"
    "Q29udGVudC1UeXBlLU9wdGlvbnMiKQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5NCIsICJIVFRQIFNlY3VyaXR5IEhl"
    "YWRlcnMiLCAiWC1Db250ZW50LVR5cGUtT3B0aW9uczogbm9zbmlmZiBwcmVzZW50IiwKICAgICAgICAiTG93IiwgIlAzIiwg"
    "IlBBU1MiIGlmIHhjdG8ubG93ZXIoKSA9PSAibm9zbmlmZiIgZWxzZSAiRkFJTCIsCiAgICAgICAgKGYiWC1Db250ZW50LVR5"
    "cGUtT3B0aW9uczoge3hjdG8gb3IgJ21pc3NpbmcnfSIgaWYgeGN0by5sb3dlcigpID09ICJub3NuaWZmIiBlbHNlCiAgICAg"
    "ICAgIGYiQ09ORklSTUVEIEJZOiBYLUNvbnRlbnQtVHlwZS1PcHRpb25zIGhlYWRlciB2YWx1ZSBpcyAne3hjdG8gb3IgJyhu"
    "b3QgcHJlc2VudCBpbiByZXNwb25zZSBoZWFkZXJzKSd9JyAiCiAgICAgICAgICIoZXhwZWN0ZWQgZXhhY3RseSAnbm9zbmlm"
    "ZicpLiIpICsgY3VybF9ibG9jaykKCiAgICBoc3RzID0gci5oZWFkZXIoIlN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkiKQog"
    "ICAgaWYgZnVsbF91cmwuc3RhcnRzd2l0aCgiaHR0cHMiKSBhbmQgaHN0czoKICAgICAgICBtID0gcmUuc2VhcmNoKHIibWF4"
    "LWFnZT0oXGQrKSIsIGhzdHMpCiAgICAgICAgbWF4X2FnZV9vayA9IG0gYW5kIGludChtLmdyb3VwKDEpKSA+PSAxNTU1MjAw"
    "MCAgIyAxODAgZGF5cwogICAgICAgIGV2aWRlbmNlID0gKGYiSFNUUzoge2hzdHN9IiBpZiBtYXhfYWdlX29rIGVsc2UKICAg"
    "ICAgICAgICAgICAgICAgICBmIkNPTkZJUk1FRCBCWTogU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSBtYXgtYWdlIGlzIHtt"
    "Lmdyb3VwKDEpIGlmIG0gZWxzZSAnbWlzc2luZy91bnBhcnNlYWJsZSd9ICIKICAgICAgICAgICAgICAgICAgICBmIihyZWNv"
    "bW1lbmQgPj0gMTU1NTIwMDApIC0gZnVsbCBoZWFkZXIgdmFsdWU6IHtoc3RzfSIpCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAi"
    "V0EtSERSLTM5NSIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMiLCAiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSAoSFNUUykg"
    "cHJvcGVybHkgY29uZmlndXJlZCIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIgaWYgbWF4X2FnZV9vayBl"
    "bHNlICJGQUlMIiwgZXZpZGVuY2UgKyBjdXJsX2Jsb2NrKQogICAgZWxpZiBmdWxsX3VybC5zdGFydHN3aXRoKCJodHRwcyIp"
    "OgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLUhEUi0zOTUiLCAiSFRUUCBTZWN1cml0eSBIZWFkZXJzIiwgIlN0cmljdC1U"
    "cmFuc3BvcnQtU2VjdXJpdHkgKEhTVFMpIHByb3Blcmx5IGNvbmZpZ3VyZWQiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAy"
    "IiwgIkZBSUwiLAogICAgICAgICAgICAiQ09ORklSTUVEIEJZOiBubyBTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5IGhlYWRl"
    "ciBwcmVzZW50IGluIHRoZSByZXNwb25zZSBoZWFkZXJzIGJlbG93LCAiCiAgICAgICAgICAgICJvbiBhbiBIVFRQUyByZXNw"
    "b25zZS4iICsgY3VybF9ibG9jaykKICAgIGVsc2U6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5NSIsICJIVFRQ"
    "IFNlY3VyaXR5IEhlYWRlcnMiLCAiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSAoSFNUUykgcHJvcGVybHkgY29uZmlndXJl"
    "ZCIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiSU5GTyIsICJVUkwgaXMgSFRUUCwgbm90IEhUVFBTIC0gSFNUUyBv"
    "bmx5IG1lYW5pbmdmdWwgb3ZlciBIVFRQUy4iICsgY3VybF9ibG9jaykKCiAgICByZWZwb2wgPSByLmhlYWRlcigiUmVmZXJy"
    "ZXItUG9saWN5IikKICAgIGFkZChmdWxsX3VybCwgIldBLUhEUi0zOTYiLCAiSFRUUCBTZWN1cml0eSBIZWFkZXJzIiwgIlJl"
    "ZmVycmVyLVBvbGljeSBoZWFkZXIgcHJlc2VudCIsCiAgICAgICAgIkxvdyIsICJQMyIsICJQQVNTIiBpZiByZWZwb2wgZWxz"
    "ZSAiRkFJTCIsCiAgICAgICAgKGYiUmVmZXJyZXItUG9saWN5OiB7cmVmcG9sfSIgaWYgcmVmcG9sIGVsc2UKICAgICAgICAg"
    "IkNPTkZJUk1FRCBCWTogbm8gUmVmZXJyZXItUG9saWN5IGhlYWRlciBwcmVzZW50IGluIHRoZSByZXNwb25zZSBoZWFkZXJz"
    "IGJlbG93LiIpICsgY3VybF9ibG9jaykKCiAgICBjYWNoZV9jdHJsID0gci5oZWFkZXIoIkNhY2hlLUNvbnRyb2wiKQogICAg"
    "YWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5NyIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMiLCAiQ2FjaGUtQ29udHJvbDogbm8t"
    "c3RvcmUgb24gYXV0aGVudGljYXRlZC9zZW5zaXRpdmUgcGFnZXMiLAogICAgICAgICJNZWRpdW0iLCAiUDIiLCAiTUFOVUFM"
    "IiwKICAgICAgICBmIkNhY2hlLUNvbnRyb2wgb24gdGhpcyBwYWdlOiB7Y2FjaGVfY3RybCBvciAnbWlzc2luZyd9LiBBdXRv"
    "bWF0ZWQgc2NhbiBjYW4ndCBrbm93IGlmIHRoaXMgIgogICAgICAgICJzcGVjaWZpYyBwYWdlIGlzIGF1dGhlbnRpY2F0ZWQv"
    "c2Vuc2l0aXZlIC0gY29uZmlybSBtYW51YWxseSBhbmQgY2hlY2sgbm8tc3RvcmUgaXMgc2V0IGlmIHNvLiIgKyBjdXJsX2Js"
    "b2NrKQoKICAgIHBlcm1wb2wgPSByLmhlYWRlcigiUGVybWlzc2lvbnMtUG9saWN5Iikgb3Igci5oZWFkZXIoIkZlYXR1cmUt"
    "UG9saWN5IikKICAgIGFkZChmdWxsX3VybCwgIldBLUhEUi0zOTgiLCAiSFRUUCBTZWN1cml0eSBIZWFkZXJzIiwgIlBlcm1p"
    "c3Npb25zLVBvbGljeSByZXN0cmljdHMgc2Vuc2l0aXZlIGJyb3dzZXIgQVBJcyIsCiAgICAgICAgIkxvdyIsICJQMyIsICJQ"
    "QVNTIiBpZiBwZXJtcG9sIGVsc2UgIkZBSUwiLAogICAgICAgIChmIlBlcm1pc3Npb25zLVBvbGljeToge3Blcm1wb2x9IiBp"
    "ZiBwZXJtcG9sIGVsc2UKICAgICAgICAgIkNPTkZJUk1FRCBCWTogbm8gUGVybWlzc2lvbnMtUG9saWN5IG9yIEZlYXR1cmUt"
    "UG9saWN5IGhlYWRlciBwcmVzZW50IGluIHRoZSByZXNwb25zZSBoZWFkZXJzIGJlbG93LiIpICsgY3VybF9ibG9jaykKCiAg"
    "ICBpZiBmdWxsX3VybC5zdGFydHN3aXRoKCJodHRwOi8vIik6CiAgICAgICAgcmVkaXJfdGFyZ2V0ID0gZnVsbF91cmwucmVw"
    "bGFjZSgiaHR0cDovLyIsICJodHRwczovLyIsIDEpCiAgICAgICAgcjIgPSByYXdfcmVxdWVzdChmdWxsX3VybCwgIkdFVCIs"
    "IHRpbWVvdXQ9YXJncy50aW1lb3V0LCBpbnNlY3VyZT1hcmdzLmluc2VjdXJlLCBmb2xsb3dfcmVkaXJlY3RzPUZhbHNlKQog"
    "ICAgICAgIGxvYyA9IHIyLmhlYWRlcigiTG9jYXRpb24iKQogICAgICAgIHJlZGlyZWN0ZWRfdG9faHR0cHMgPSBib29sKGxv"
    "YyBhbmQgbG9jLmxvd2VyKCkuc3RhcnRzd2l0aCgiaHR0cHMiKSkKICAgICAgICBjdXJsX3Jlc3VsdF8zOTkgPSBOb25lIGlm"
    "IGdldGF0dHIoYXJncywgIm5vX2NsaV90b29scyIsIEZhbHNlKSBlbHNlIHJ1bl9jdXJsX2hlYWRlcnMoCiAgICAgICAgICAg"
    "IGZ1bGxfdXJsLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgICAgICBjdXJsX2Js"
    "b2NrXzM5OSA9IF9mb3JtYXRfY21kX2Jsb2NrKGN1cmxfcmVzdWx0XzM5OVswXSwgY3VybF9yZXN1bHRfMzk5WzFdKSBpZiBj"
    "dXJsX3Jlc3VsdF8zOTkgZWxzZSAiIgogICAgICAgIGV2aWRlbmNlMzk5ID0gKGYiSFRUUCByZXNwb25zZToge3IyLnN0YXR1"
    "c30sIExvY2F0aW9uOiB7bG9jIG9yICdub25lJ30uIiBpZiByZWRpcmVjdGVkX3RvX2h0dHBzIGVsc2UKICAgICAgICAgICAg"
    "ICAgICAgICAgICBmIkNPTkZJUk1FRCBCWTogcGxhaW4gaHR0cDovLyByZXF1ZXN0IHJldHVybmVkIHN0YXR1cyB7cjIuc3Rh"
    "dHVzfSB3aXRoICIKICAgICAgICAgICAgICAgICAgICAgICBmIkxvY2F0aW9uOiAne2xvYyBvciAnKG5vIExvY2F0aW9uIGhl"
    "YWRlciBhdCBhbGwpJ30nIC0gZGlkIG5vdCByZWRpcmVjdCB0byBhbiBodHRwczovLyBVUkwuIikKICAgICAgICBhZGQoZnVs"
    "bF91cmwsICJXQS1IRFItMzk5IiwgIkhUVFAgU2VjdXJpdHkgSGVhZGVycyIsICJIVFRQUyBlbmZvcmNlZCAtIEhUVFAgcmVk"
    "aXJlY3RzIHRvIEhUVFBTIiwKICAgICAgICAgICAgIkhpZ2giLCAiUDEiLCAiUEFTUyIgaWYgcmVkaXJlY3RlZF90b19odHRw"
    "cyBlbHNlICJGQUlMIiwgZXZpZGVuY2UzOTkgKyBjdXJsX2Jsb2NrXzM5OSkKICAgIGVsc2U6CiAgICAgICAgYWRkKGZ1bGxf"
    "dXJsLCAiV0EtSERSLTM5OSIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMiLCAiSFRUUFMgZW5mb3JjZWQgLSBIVFRQIHJlZGly"
    "ZWN0cyB0byBIVFRQUyIsCiAgICAgICAgICAgICJIaWdoIiwgIlAxIiwgIklORk8iLCAiVVJMIGdpdmVuIHdhcyBhbHJlYWR5"
    "IEhUVFBTIC0gcmUtcnVuIHdpdGggdGhlIGh0dHA6Ly8gdmVyc2lvbiB0byB0ZXN0IHRoZSByZWRpcmVjdC4iKQoKICAgIGJh"
    "c2UgPSBkaXJfb2YoZnVsbF91cmwpCiAgICBwcm9iZV9wYXRoID0gam9pbl90YXJnZXQoYmFzZSwgIi90aGlzLXBhdGgtc2hv"
    "dWxkLW5vdC1leGlzdC0iICsgcmFuZF90b2tlbigpKQogICAgcjQwNCA9IHJhd19yZXF1ZXN0KHByb2JlX3BhdGgsICJHRVQi"
    "LCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIHRyYWNlX2ZvdW5kID0gTm9uZQog"
    "ICAgdHJhY2Vfc25pcHBldCA9ICIiCiAgICBpZiBub3QgcjQwNC5lcnJvcjoKICAgICAgICBib2R5X3RleHQgPSByNDA0LnRl"
    "eHQoKQogICAgICAgIGZvciBwYXQgaW4gU1RBQ0tfVFJBQ0VfUEFUVEVSTlM6CiAgICAgICAgICAgIG00MDQgPSByZS5zZWFy"
    "Y2gocGF0LCBib2R5X3RleHQsIHJlLklHTk9SRUNBU0UpCiAgICAgICAgICAgIGlmIG00MDQ6CiAgICAgICAgICAgICAgICB0"
    "cmFjZV9mb3VuZCA9IHBhdAogICAgICAgICAgICAgICAgc3RhcnQgPSBtYXgobTQwNC5zdGFydCgpIC0gNDAsIDApCiAgICAg"
    "ICAgICAgICAgICB0cmFjZV9zbmlwcGV0ID0gYm9keV90ZXh0W3N0YXJ0Om00MDQuZW5kKCkgKyA2MF0ucmVwbGFjZSgiXG4i"
    "LCAiICIpLnN0cmlwKCkKICAgICAgICAgICAgICAgIGJyZWFrCiAgICBhZGQoZnVsbF91cmwsICJXQS1IRFItNDAwIiwgIkhU"
    "VFAgU2VjdXJpdHkgSGVhZGVycyIsICJWZXJib3NlIGVycm9yIG1lc3NhZ2VzIC8gc3RhY2sgdHJhY2VzIG9uIDR4eC81eHgi"
    "LAogICAgICAgICJNZWRpdW0iLCAiUDIiLCAiRkFJTCIgaWYgdHJhY2VfZm91bmQgZWxzZSAoIkVSUk9SIiBpZiByNDA0LmVy"
    "cm9yIGVsc2UgIlBBU1MiKSwKICAgICAgICAoZiJDT05GSVJNRUQgQlk6IHJlc3BvbnNlIGJvZHkgZm9yIHRoZSA0MDQgcHJv"
    "YmUgKHtwcm9iZV9wYXRofSkgbWF0Y2hlZCBrbm93biBlcnJvci1kaXNjbG9zdXJlIHBhdHRlcm4gIgogICAgICAgICBmIid7"
    "dHJhY2VfZm91bmR9JyAtIGV4Y2VycHQgYXJvdW5kIHRoZSBtYXRjaDogXCIuLi57dHJhY2Vfc25pcHBldH0uLi5cIiIgaWYg"
    "dHJhY2VfZm91bmQgZWxzZQogICAgICAgICAocjQwNC5lcnJvciBvciBmIk5vIGtub3duIHN0YWNrLXRyYWNlIHBhdHRlcm4g"
    "Zm91bmQgb24gNDA0IHByb2JlIChzdGF0dXMge3I0MDQuc3RhdHVzfSkuIikpKQoKICAgIHNlcnZlcl9oZHIgPSByLmhlYWRl"
    "cigiU2VydmVyIikKICAgIHhwYl9oZHIgPSByLmhlYWRlcigiWC1Qb3dlcmVkLUJ5IikKICAgIHNlcnZlcl9tYXRjaCA9IHJl"
    "LnNlYXJjaChyIlxkK1wuXGQrIiwgc2VydmVyX2hkcikgaWYgc2VydmVyX2hkciBlbHNlIE5vbmUKICAgIHhwYl9tYXRjaCA9"
    "IHJlLnNlYXJjaChyIlxkK1wuXGQrIiwgeHBiX2hkcikgaWYgeHBiX2hkciBlbHNlIE5vbmUKICAgIHZlcnNpb25fbGVhayA9"
    "IGJvb2woc2VydmVyX21hdGNoIG9yIHhwYl9tYXRjaCkKICAgIGlmIHZlcnNpb25fbGVhazoKICAgICAgICB3aGljaCA9IFtd"
    "CiAgICAgICAgaWYgc2VydmVyX21hdGNoOgogICAgICAgICAgICB3aGljaC5hcHBlbmQoZiJTZXJ2ZXI6ICd7c2VydmVyX2hk"
    "cn0nICh2ZXJzaW9uLWxvb2tpbmcgc3Vic3RyaW5nOiAne3NlcnZlcl9tYXRjaC5ncm91cCgwKX0nKSIpCiAgICAgICAgaWYg"
    "eHBiX21hdGNoOgogICAgICAgICAgICB3aGljaC5hcHBlbmQoZiJYLVBvd2VyZWQtQnk6ICd7eHBiX2hkcn0nICh2ZXJzaW9u"
    "LWxvb2tpbmcgc3Vic3RyaW5nOiAne3hwYl9tYXRjaC5ncm91cCgwKX0nKSIpCiAgICAgICAgZXZpZGVuY2U0MDEgPSAiQ09O"
    "RklSTUVEIEJZOiAiICsgIjsgIi5qb2luKHdoaWNoKQogICAgZWxzZToKICAgICAgICBldmlkZW5jZTQwMSA9IGYiU2VydmVy"
    "OiB7c2VydmVyX2hkciBvciAnbm9uZSd9LCBYLVBvd2VyZWQtQnk6IHt4cGJfaGRyIG9yICdub25lJ30iCiAgICBhZGQoZnVs"
    "bF91cmwsICJXQS1IRFItNDAxIiwgIkhUVFAgU2VjdXJpdHkgSGVhZGVycyIsICJTZXJ2ZXIgdmVyc2lvbiBkaXNjbG9zdXJl"
    "IGluIHJlc3BvbnNlIGhlYWRlcnMiLAogICAgICAgICJMb3ciLCAiUDMiLCAiRkFJTCIgaWYgdmVyc2lvbl9sZWFrIGVsc2Ug"
    "IlBBU1MiLCBldmlkZW5jZTQwMSArIGN1cmxfYmxvY2spCgogICAgcmV0dXJuIHIsIGN1cmxfYmxvY2sKCgojIC0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgMi4g"
    "U1NMIC8gVExTIC0gV0EtVExTLTQwMi4uNDA5IChiZXN0LWVmZm9ydDsgc2V2ZXJhbCBhcmUgTUFOVUFMIGJ5IGRlc2lnbiwK"
    "IyAgICBzZWUgbW9kdWxlIGRvY3N0cmluZyAtIGEgcmVhbCBncmFkZSBuZWVkcyB0ZXN0c3NsLnNoL3NzbHl6ZS9TU0wgTGFi"
    "cykKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLQoKZGVmIF9vcGVuc3NsX2F2YWlsYWJsZSgpOgogICAgdHJ5OgogICAgICAgIHN1YnByb2Nlc3MucnVuKFsib3Bl"
    "bnNzbCIsICJ2ZXJzaW9uIl0sIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRpbWVvdXQ9NSkKICAgICAgICByZXR1cm4gVHJ1ZQog"
    "ICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgY2hlY2tfdGxzKGZ1bGxfdXJsLCBhcmdz"
    "KToKICAgIHAgPSB1cmxwYXJzZShmdWxsX3VybCkKICAgIGlmIHAuc2NoZW1lICE9ICJodHRwcyI6CiAgICAgICAgZm9yIGNp"
    "ZCwgbmFtZSwgc2V2LCBwcmkgaW4gWwogICAgICAgICAgICAoIldBLVRMUy00MDIiLCAiU1NML1RMUyBzY2FuIC0gZ3JhZGUg"
    "YW5kIGNpcGhlciBzdHJlbmd0aCIsICJIaWdoIiwgIlAxIiksCiAgICAgICAgICAgICgiV0EtVExTLTQwMyIsICJTU0x2Miwg"
    "U1NMdjMsIFRMU3YxLjAgZGlzYWJsZWQiLCAiSGlnaCIsICJQMSIpLAogICAgICAgICAgICAoIldBLVRMUy00MDQiLCAiTm8g"
    "d2VhayBjaXBoZXIgc3VpdGVzIChSQzQsIERFUywgTlVMTCwgRVhQT1JUKSIsICJIaWdoIiwgIlAxIiksCiAgICAgICAgICAg"
    "ICgiV0EtVExTLTQwNSIsICJDZXJ0aWZpY2F0ZSBrZXkgc3RyZW5ndGggPj0gMjA0OC1iaXQgUlNBIC8gMjU2LWJpdCBFQ0Mi"
    "LCAiTWVkaXVtIiwgIlAyIiksCiAgICAgICAgICAgICgiV0EtVExTLTQwNiIsICJDZXJ0aWZpY2F0ZSB1c2VzIFNIQS0yNTYr"
    "IHNpZ25hdHVyZSBhbGdvcml0aG0iLCAiTWVkaXVtIiwgIlAyIiksCiAgICAgICAgICAgICgiV0EtVExTLTQwNyIsICJDZXJ0"
    "aWZpY2F0ZSBjaGFpbiBjb21wbGV0ZSAtIG5vIG1pc3NpbmcgaW50ZXJtZWRpYXRlcyIsICJNZWRpdW0iLCAiUDIiKSwKICAg"
    "ICAgICAgICAgKCJXQS1UTFMtNDA4IiwgIkhTVFMgcHJlbG9hZCBsaXN0IGNvbmZpZ3VyZWQiLCAiTWVkaXVtIiwgIlAyIiks"
    "CiAgICAgICAgICAgICgiV0EtVExTLTQwOSIsICJXZWJTb2NrZXQgZW5kcG9pbnRzIHVzZSBXU1Mgbm90IFdTIiwgIkhpZ2gi"
    "LCAiUDEiKSwKICAgICAgICBdOgogICAgICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgIlNTTCAvIFRMUyIsIG5hbWUsIHNl"
    "diwgcHJpLCAiSU5GTyIsICJVUkwgaXMgbm90IEhUVFBTIC0gVExTIGNoZWNrcyBza2lwcGVkLiIpCiAgICAgICAgcmV0dXJu"
    "CgogICAgaG9zdCA9IHAuaG9zdG5hbWUKICAgIHBvcnQgPSBwLnBvcnQgb3IgNDQzCgogICAgc3NsX2NsaSA9IE5vbmUgaWYg"
    "Z2V0YXR0cihhcmdzLCAibm9fY2xpX3Rvb2xzIiwgRmFsc2UpIGVsc2UgcnVuX3NzbF9jbGlfc2NhbigKICAgICAgICBob3N0"
    "LCBwb3J0LCB0aW1lb3V0PW1heChhcmdzLnRpbWVvdXQsIDQ1KSkKICAgIGlmIHNzbF9jbGk6CiAgICAgICAgc3NsX3Rvb2ws"
    "IHNzbF9jbWQsIHNzbF9vdXRwdXQgPSBzc2xfY2xpCiAgICAgICAgc3NsX2Jsb2NrID0gX2Zvcm1hdF9jbWRfYmxvY2soc3Ns"
    "X2NtZCwgc3NsX291dHB1dCkKICAgICAgICBwYXJzZWQgPSBfcGFyc2Vfc3NsX2NsaV9vdXRwdXQoc3NsX291dHB1dCkKICAg"
    "ICAgICB3ZWFrX2NpcGhlcnMgPSBwYXJzZWRbIndlYWtfY2lwaGVycyJdCiAgICAgICAgbGVhc3Rfc3RyZW5ndGggPSBwYXJz"
    "ZWRbImxlYXN0X3N0cmVuZ3RoIl0KICAgICAgICByYW5fYnV0X2VtcHR5ID0gbm90IHNzbF9vdXRwdXQuc3RyaXAoKSBvciBz"
    "c2xfb3V0cHV0Lmxvd2VyKCkuc3RhcnRzd2l0aCgiKCIpCgogICAgICAgIGlmIGxlYXN0X3N0cmVuZ3RoOgogICAgICAgICAg"
    "ICBncmFkZV9yZXN1bHQgPSAiRkFJTCIgaWYgbGVhc3Rfc3RyZW5ndGgubG93ZXIoKSBpbiAoIndlYWsiLCAiaW5zZWN1cmUi"
    "KSBlbHNlICJQQVNTIgogICAgICAgICAgICBncmFkZV9ldmlkZW5jZSA9IGYie3NzbF90b29sfSBsZWFzdCBjaXBoZXIgc3Ry"
    "ZW5ndGg6IHtsZWFzdF9zdHJlbmd0aH0uIgogICAgICAgIGVsaWYgd2Vha19jaXBoZXJzOgogICAgICAgICAgICBncmFkZV9y"
    "ZXN1bHQgPSAiRkFJTCIKICAgICAgICAgICAgZ3JhZGVfZXZpZGVuY2UgPSBmIntzc2xfdG9vbH0gb3V0cHV0IGZsYWdzIHdl"
    "YWsgY2lwaGVyIGluZGljYXRvcihzKTogeycsICcuam9pbih3ZWFrX2NpcGhlcnMpfS4iCiAgICAgICAgZWxpZiByYW5fYnV0"
    "X2VtcHR5OgogICAgICAgICAgICBncmFkZV9yZXN1bHQgPSAiSU5GTyIKICAgICAgICAgICAgZ3JhZGVfZXZpZGVuY2UgPSBm"
    "Intzc2xfdG9vbH0gcmFuIGJ1dCBwcm9kdWNlZCBubyBjb25jbHVzaXZlIGNpcGhlci1zdHJlbmd0aCBvdXRwdXQgLSByZXZp"
    "ZXcgcmF3IG91dHB1dCBiZWxvdy4iCiAgICAgICAgZWxzZToKICAgICAgICAgICAgZ3JhZGVfcmVzdWx0ID0gIlBBU1MiCiAg"
    "ICAgICAgICAgIGdyYWRlX2V2aWRlbmNlID0gZiJ7c3NsX3Rvb2x9IHJhbiBhbmQgZm91bmQgbm8gd2Vhay1jaXBoZXIgaW5k"
    "aWNhdG9ycyBpbiBpdHMgb3V0cHV0IC0gcmV2aWV3IHJhdyBvdXRwdXQgYmVsb3cgdG8gY29uZmlybS4iCiAgICAgICAgYWRk"
    "KGZ1bGxfdXJsLCAiV0EtVExTLTQwMiIsICJTU0wgLyBUTFMiLCAiU1NML1RMUyBzY2FuIC0gZ3JhZGUgYW5kIGNpcGhlciBz"
    "dHJlbmd0aCIsCiAgICAgICAgICAgICJIaWdoIiwgIlAxIiwgZ3JhZGVfcmVzdWx0LCBncmFkZV9ldmlkZW5jZSArIHNzbF9i"
    "bG9jaykKCiAgICAgICAgY2lwaGVyX3Jlc3VsdCA9ICJGQUlMIiBpZiB3ZWFrX2NpcGhlcnMgZWxzZSAoIklORk8iIGlmIHJh"
    "bl9idXRfZW1wdHkgZWxzZSAiUEFTUyIpCiAgICAgICAgY2lwaGVyX2V2aWRlbmNlID0gKGYiV2VhayBjaXBoZXIgaW5kaWNh"
    "dG9yKHMpIGZvdW5kIGJ5IHtzc2xfdG9vbH06IHsnLCAnLmpvaW4od2Vha19jaXBoZXJzKX0uIgogICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgaWYgd2Vha19jaXBoZXJzIGVsc2UgZiJObyBSQzQvREVTLzNERVMvTlVMTC9FWFBPUlQvTUQ1L2Fub24g"
    "aW5kaWNhdG9ycyBmb3VuZCBpbiB7c3NsX3Rvb2x9IG91dHB1dC4iKQogICAgICAgIGFkZChmdWxsX3VybCwgIldBLVRMUy00"
    "MDQiLCAiU1NMIC8gVExTIiwgIk5vIHdlYWsgY2lwaGVyIHN1aXRlcyAoUkM0LCBERVMsIE5VTEwsIEVYUE9SVCkiLAogICAg"
    "ICAgICAgICAiSGlnaCIsICJQMSIsIGNpcGhlcl9yZXN1bHQsIGNpcGhlcl9ldmlkZW5jZSArIHNzbF9ibG9jaykKICAgIGVs"
    "c2U6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtVExTLTQwMiIsICJTU0wgLyBUTFMiLCAiU1NML1RMUyBzY2FuIC0gZ3Jh"
    "ZGUgYW5kIGNpcGhlciBzdHJlbmd0aCIsCiAgICAgICAgICAgICJIaWdoIiwgIlAxIiwgIk1BTlVBTCIsCiAgICAgICAgICAg"
    "IGYiTm8gU1NMIENMSSBzY2FubmVyIChubWFwL3NzbHl6ZS9zc2xzY2FuL3Rlc3Rzc2wuc2gpIGZvdW5kIG9uIFBBVEguIEEg"
    "cmVhbCBBLUYgZ3JhZGUgbmVlZHMgb25lIC0gcnVuOiAiCiAgICAgICAgICAgIGYibm1hcCAtLXNjcmlwdCBzc2wtZW51bS1j"
    "aXBoZXJzIC1wIHtwb3J0fSB7aG9zdH0gIE9SICB0ZXN0c3NsLnNoIHtob3N0fTp7cG9ydH0gIE9SIGNoZWNrICIKICAgICAg"
    "ICAgICAgZiJodHRwczovL3d3dy5zc2xsYWJzLmNvbS9zc2x0ZXN0L2FuYWx5emUuaHRtbD9kPXtob3N0fSIpCiAgICAgICAg"
    "YWRkKGZ1bGxfdXJsLCAiV0EtVExTLTQwNCIsICJTU0wgLyBUTFMiLCAiTm8gd2VhayBjaXBoZXIgc3VpdGVzIChSQzQsIERF"
    "UywgTlVMTCwgRVhQT1JUKSIsCiAgICAgICAgICAgICJIaWdoIiwgIlAxIiwgIk1BTlVBTCIsCiAgICAgICAgICAgIGYiTm8g"
    "U1NMIENMSSBzY2FubmVyIGZvdW5kIG9uIFBBVEguIFJ1bjogbm1hcCAtLXNjcmlwdCBzc2wtZW51bS1jaXBoZXJzIC1wIHtw"
    "b3J0fSB7aG9zdH0gIE9SICB0ZXN0c3NsLnNoIHtob3N0fTp7cG9ydH0iKQoKICAgIG9sZF9wcm90b2NvbHMgPSB7fQogICAg"
    "Zm9yIG5hbWUsIHZlciBpbiBbKCJTU0x2MyIsIGdldGF0dHIoc3NsLlRMU1ZlcnNpb24sICJTU0x2MyIsIE5vbmUpKSwKICAg"
    "ICAgICAgICAgICAgICAgICAgICAoIlRMU3YxLjAiLCBzc2wuVExTVmVyc2lvbi5UTFN2MSksCiAgICAgICAgICAgICAgICAg"
    "ICAgICAgKCJUTFN2MS4xIiwgc3NsLlRMU1ZlcnNpb24uVExTdjFfMSldOgogICAgICAgIGlmIHZlciBpcyBOb25lOgogICAg"
    "ICAgICAgICBvbGRfcHJvdG9jb2xzW25hbWVdID0gIm5vdCBzdXBwb3J0ZWQgYnkgbG9jYWwgT3BlblNTTCBidWlsZCAtIGNh"
    "bid0IHRlc3QiCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgdHJ5OgogICAgICAgICAgICBjdHggPSBzc2wuU1NMQ29u"
    "dGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAgICAgICAgICAgY3R4LmNoZWNrX2hvc3RuYW1lID0gRmFsc2UKICAg"
    "ICAgICAgICAgY3R4LnZlcmlmeV9tb2RlID0gc3NsLkNFUlRfTk9ORQogICAgICAgICAgICAjIERlbGliZXJhdGVseSBzZXR0"
    "aW5nIG1pbi9tYXggdmVyc2lvbiB0byBTU0x2My9UTFN2MS4wL1RMU3YxLjEKICAgICAgICAgICAgIyBpcyBleGFjdGx5IHdo"
    "YXQgdGhpcyBwcm9iZSBuZWVkcyAod2UgV0FOVCB0byB0cnkgY29ubmVjdGluZwogICAgICAgICAgICAjIHdpdGggdGhlIG9s"
    "ZCwgd2VhayBwcm90b2NvbCB0byBzZWUgaWYgdGhlIHNlcnZlciBzdGlsbAogICAgICAgICAgICAjIGFjY2VwdHMgaXQpIC0g"
    "YnV0IHJlY2VudCBQeXRob24vT3BlblNTTCBidWlsZHMgcmFpc2UgYQogICAgICAgICAgICAjIERlcHJlY2F0aW9uV2Fybmlu"
    "ZyBvbiB0aGUgYXNzaWdubWVudCBpdHNlbGYganVzdCBmb3IKICAgICAgICAgICAgIyByZWZlcmVuY2luZyBzc2wuVExTVmVy"
    "c2lvbi5TU0x2MyBhdCBhbGwuIFRoYXQncyBhIHdhcm5pbmcKICAgICAgICAgICAgIyBhYm91dCBPVVIgdXNlIG9mIGEgZGVw"
    "cmVjYXRlZCBQeXRob24gQVBJLCBub3QgYSBmaW5kaW5nCiAgICAgICAgICAgICMgYWJvdXQgdGhlIHNjYW5uZWQgdGFyZ2V0"
    "IC0gc3VwcHJlc3NlZCBoZXJlIHNvIGl0IGRvZXNuJ3QgZ2V0CiAgICAgICAgICAgICMgbWlzdGFrZW4gZm9yIG9uZSAoYXNr"
    "ZWQgZGlyZWN0bHk6ICJpbiBweXRob24gaSBjYW4gc2VlCiAgICAgICAgICAgICMgZGVwcmVjYXRpb24gd2FybmluZyAuLi4g"
    "aXMgdGlzIGlzIGZpbmRpbmdzIG9yIHdhcm5pbmc/IikuCiAgICAgICAgICAgIHdpdGggd2FybmluZ3MuY2F0Y2hfd2Fybmlu"
    "Z3MoKToKICAgICAgICAgICAgICAgIHdhcm5pbmdzLnNpbXBsZWZpbHRlcigiaWdub3JlIiwgRGVwcmVjYXRpb25XYXJuaW5n"
    "KQogICAgICAgICAgICAgICAgY3R4Lm1pbmltdW1fdmVyc2lvbiA9IHZlcgogICAgICAgICAgICAgICAgY3R4Lm1heGltdW1f"
    "dmVyc2lvbiA9IHZlcgogICAgICAgICAgICB3aXRoIHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoaG9zdCwgcG9ydCksIHRp"
    "bWVvdXQ9YXJncy50aW1lb3V0KSBhcyBzb2NrOgogICAgICAgICAgICAgICAgd2l0aCBjdHgud3JhcF9zb2NrZXQoc29jaywg"
    "c2VydmVyX2hvc3RuYW1lPWhvc3QpIGFzIHNzb2NrOgogICAgICAgICAgICAgICAgICAgIHNzb2NrLnZlcnNpb24oKQogICAg"
    "ICAgICAgICBvbGRfcHJvdG9jb2xzW25hbWVdID0gIkFDQ0VQVEVEIGJ5IHNlcnZlciAod2VhaykiCiAgICAgICAgZXhjZXB0"
    "IHNzbC5TU0xFcnJvcjoKICAgICAgICAgICAgb2xkX3Byb3RvY29sc1tuYW1lXSA9ICJyZWplY3RlZCBieSBzZXJ2ZXIgKGdv"
    "b2QpIgogICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgICAgICBvbGRfcHJvdG9jb2xzW25hbWVdID0gIm5vdCBz"
    "dXBwb3J0ZWQgYnkgbG9jYWwgT3BlblNTTCBidWlsZCAtIGNhbid0IHRlc3QiCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBh"
    "cyBlOgogICAgICAgICAgICBvbGRfcHJvdG9jb2xzW25hbWVdID0gZiJjb3VsZCBub3QgdGVzdCAoe2V9KSIKCiAgICBhbnlf"
    "YWNjZXB0ZWQgPSBhbnkoIkFDQ0VQVEVEIiBpbiB2IGZvciB2IGluIG9sZF9wcm90b2NvbHMudmFsdWVzKCkpCiAgICBhbnlf"
    "dW50ZXN0YWJsZSA9IGFueSgiY2FuJ3QgdGVzdCIgaW4gdiBmb3IgdiBpbiBvbGRfcHJvdG9jb2xzLnZhbHVlcygpKQogICAg"
    "cmVzdWx0ID0gIkZBSUwiIGlmIGFueV9hY2NlcHRlZCBlbHNlICgiSU5GTyIgaWYgYW55X3VudGVzdGFibGUgYW5kIG5vdCBh"
    "bnlfYWNjZXB0ZWQgZWxzZSAiUEFTUyIpCiAgICBhZGQoZnVsbF91cmwsICJXQS1UTFMtNDAzIiwgIlNTTCAvIFRMUyIsICJT"
    "U0x2MiwgU1NMdjMsIFRMU3YxLjAgZGlzYWJsZWQiLAogICAgICAgICJIaWdoIiwgIlAxIiwgcmVzdWx0LCAiOyAiLmpvaW4o"
    "ZiJ7a306IHt2fSIgZm9yIGssIHYgaW4gb2xkX3Byb3RvY29scy5pdGVtcygpKSkKCiAgICAjIE5PVEU6IFdBLVRMUy00MDQg"
    "KHdlYWsgY2lwaGVyIHN1aXRlcykgaXMgYWxyZWFkeSBmdWxseSBoYW5kbGVkIGFib3ZlLAogICAgIyBpbnNpZGUgdGhlIGBp"
    "ZiBzc2xfY2xpOiAuLi4gZWxzZTogLi4uYCBibG9jayByaWdodCBhZnRlcgogICAgIyBydW5fc3NsX2NsaV9zY2FuKCkgLSBl"
    "aXRoZXIgYSByZWFsIFBBU1MvRkFJTC9JTkZPIGZyb20gd2hpY2hldmVyIFNTTAogICAgIyBDTEkgdG9vbCByYW4sIG9yIGEg"
    "TUFOVUFMIGZhbGxiYWNrIHdpdGggdGhlIGV4YWN0IGNvbW1hbmQgdG8gcnVuIGlmCiAgICAjIG5vbmUgaXMgaW5zdGFsbGVk"
    "LiBBIHNlY29uZCwgdW5jb25kaXRpb25hbCBhZGQoLi4uLCAiV0EtVExTLTQwNCIsCiAgICAjIC4uLiwgIk1BTlVBTCIsIC4u"
    "LikgdXNlZCB0byBzaXQgcmlnaHQgaGVyZSBhbmQgc2lsZW50bHkgT1ZFUldSSVRFCiAgICAjIHRoYXQgcmVhbCByZXN1bHQg"
    "ZXZlcnkgc2luZ2xlIHRpbWUgKFJFU1VMVFMgaXMgYW4gYXBwZW5kLW9ubHkgbGlzdCAtCiAgICAjIHNlZSBhZGQoKSdzIG93"
    "biBkZWZpbml0aW9uIC0gc28gdGhpcyByYW4gcmVnYXJkbGVzcyBvZiB3aGV0aGVyIHRoZQogICAgIyBibG9jayBhYm92ZSBh"
    "bHJlYWR5IHByb2R1Y2VkIGEgcmVhbCBQQVNTL0ZBSUwpLCBtZWFuaW5nIFdBLVRMUy00MDQKICAgICMgY291bGQgbmV2ZXIg"
    "c2hvdyBhbnl0aGluZyBidXQgTUFOVUFMIGV2ZW4gd2hlbiBubWFwL3NzbHl6ZS9zc2xzY2FuLwogICAgIyB0ZXN0c3NsLnNo"
    "IHdhcyBpbnN0YWxsZWQgYW5kIHJhbiBzdWNjZXNzZnVsbHkuIFJlbW92ZWQuCgogICAgY2VydF90ZXh0ID0gTm9uZQogICAg"
    "aWYgX29wZW5zc2xfYXZhaWxhYmxlKCk6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBzX2NsaWVudCA9IHN1YnByb2Nlc3Mu"
    "cnVuKAogICAgICAgICAgICAgICAgWyJvcGVuc3NsIiwgInNfY2xpZW50IiwgIi1jb25uZWN0IiwgZiJ7aG9zdH06e3BvcnR9"
    "IiwgIi1zZXJ2ZXJuYW1lIiwgaG9zdF0sCiAgICAgICAgICAgICAgICBpbnB1dD1iIiIsIGNhcHR1cmVfb3V0cHV0PVRydWUs"
    "IHRpbWVvdXQ9YXJncy50aW1lb3V0KQogICAgICAgICAgICBwZW0gPSBzX2NsaWVudC5zdGRvdXQKICAgICAgICAgICAgeDUw"
    "OSA9IHN1YnByb2Nlc3MucnVuKFsib3BlbnNzbCIsICJ4NTA5IiwgIi1ub291dCIsICItdGV4dCJdLCBpbnB1dD1wZW0sCiAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FwdHVyZV9vdXRwdXQ9VHJ1ZSwgdGltZW91dD1hcmdzLnRpbWVv"
    "dXQpCiAgICAgICAgICAgIGNlcnRfdGV4dCA9IHg1MDkuc3Rkb3V0LmRlY29kZSgidXRmLTgiLCBlcnJvcnM9InJlcGxhY2Ui"
    "KQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIGNlcnRfdGV4dCA9IE5vbmUKCiAgICBpZiBjZXJ0X3Rl"
    "eHQ6CiAgICAgICAga20gPSByZS5zZWFyY2gociJQdWJsaWMtS2V5OlxzKlwoKFxkKylccypiaXRcKSIsIGNlcnRfdGV4dCkK"
    "ICAgICAgICBrZXlfYml0cyA9IGludChrbS5ncm91cCgxKSkgaWYga20gZWxzZSBOb25lCiAgICAgICAgaXNfZWMgPSAiaWQt"
    "ZWNQdWJsaWNLZXkiIGluIGNlcnRfdGV4dCBvciAiRUNEU0EiIGluIGNlcnRfdGV4dAogICAgICAgIG1pbl9vayA9IChrZXlf"
    "Yml0cyBhbmQgKChpc19lYyBhbmQga2V5X2JpdHMgPj0gMjU2KSBvciAobm90IGlzX2VjIGFuZCBrZXlfYml0cyA+PSAyMDQ4"
    "KSkpCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtVExTLTQwNSIsICJTU0wgLyBUTFMiLCAiQ2VydGlmaWNhdGUga2V5IHN0"
    "cmVuZ3RoID49IDIwNDgtYml0IFJTQSAvIDI1Ni1iaXQgRUNDIiwKICAgICAgICAgICAgIk1lZGl1bSIsICJQMiIsICJQQVNT"
    "IiBpZiBtaW5fb2sgZWxzZSAiRkFJTCIsCiAgICAgICAgICAgIGYiS2V5IHR5cGU6IHsnRUMnIGlmIGlzX2VjIGVsc2UgJ1JT"
    "QS9vdGhlcid9LCBzaXplOiB7a2V5X2JpdHMgb3IgJ3Vua25vd24nfSBiaXRzIikKCiAgICAgICAgc2lnbSA9IHJlLnNlYXJj"
    "aChyIlNpZ25hdHVyZSBBbGdvcml0aG06XHMqKFxTKykiLCBjZXJ0X3RleHQpCiAgICAgICAgc2lnX2FsZyA9IHNpZ20uZ3Jv"
    "dXAoMSkgaWYgc2lnbSBlbHNlICJ1bmtub3duIgogICAgICAgIHdlYWtfc2lnID0gYW55KHcgaW4gc2lnX2FsZy5sb3dlcigp"
    "IGZvciB3IGluIFsibWQ1IiwgInNoYTEiXSkKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1UTFMtNDA2IiwgIlNTTCAvIFRM"
    "UyIsICJDZXJ0aWZpY2F0ZSB1c2VzIFNIQS0yNTYrIHNpZ25hdHVyZSBhbGdvcml0aG0iLAogICAgICAgICAgICAiTWVkaXVt"
    "IiwgIlAyIiwgIkZBSUwiIGlmIHdlYWtfc2lnIGVsc2UgIlBBU1MiLCBmIlNpZ25hdHVyZSBBbGdvcml0aG06IHtzaWdfYWxn"
    "fSIpCiAgICBlbHNlOgogICAgICAgIGZvciBjaWQsIG5hbWUgaW4gWygiV0EtVExTLTQwNSIsICJDZXJ0aWZpY2F0ZSBrZXkg"
    "c3RyZW5ndGggPj0gMjA0OC1iaXQgUlNBIC8gMjU2LWJpdCBFQ0MiKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKCJX"
    "QS1UTFMtNDA2IiwgIkNlcnRpZmljYXRlIHVzZXMgU0hBLTI1Nisgc2lnbmF0dXJlIGFsZ29yaXRobSIpXToKICAgICAgICAg"
    "ICAgYWRkKGZ1bGxfdXJsLCBjaWQsICJTU0wgLyBUTFMiLCBuYW1lLCAiTWVkaXVtIiwgIlAyIiwgIklORk8iLAogICAgICAg"
    "ICAgICAgICAgIkxvY2FsICdvcGVuc3NsJyBDTEkgbm90IGF2YWlsYWJsZS9mYWlsZWQgLSBjYW4ndCBwYXJzZSBjZXJ0aWZp"
    "Y2F0ZSBkZXRhaWxzLiAiCiAgICAgICAgICAgICAgICBmIlJ1biBtYW51YWxseTogb3BlbnNzbCBzX2NsaWVudCAtY29ubmVj"
    "dCB7aG9zdH06e3BvcnR9IC1zZXJ2ZXJuYW1lIHtob3N0fSB8IG9wZW5zc2wgeDUwOSAtbm9vdXQgLXRleHQiKQoKICAgIHRy"
    "eToKICAgICAgICBjdHggPSBzc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dCgpCiAgICAgICAgaWYgYXJncy5pbnNlY3VyZToK"
    "ICAgICAgICAgICAgY3R4LmNoZWNrX2hvc3RuYW1lID0gRmFsc2UKICAgICAgICAgICAgY3R4LnZlcmlmeV9tb2RlID0gc3Ns"
    "LkNFUlRfTk9ORQogICAgICAgIHdpdGggc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChob3N0LCBwb3J0KSwgdGltZW91dD1h"
    "cmdzLnRpbWVvdXQpIGFzIHNvY2s6CiAgICAgICAgICAgIHdpdGggY3R4LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0"
    "bmFtZT1ob3N0KSBhcyBzc29jazoKICAgICAgICAgICAgICAgIGRlcl9jaGFpbiA9IE5vbmUKICAgICAgICAgICAgICAgIHRy"
    "eToKICAgICAgICAgICAgICAgICAgICBkZXJfY2hhaW4gPSBzc29jay5zZXNzaW9uLmdldCgicGVlcl9jZXJ0aWZpY2F0ZV9j"
    "aGFpbiIpCiAgICAgICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICAgICAgICAgIHBhc3MKICAgICAg"
    "ICBhZGQoZnVsbF91cmwsICJXQS1UTFMtNDA3IiwgIlNTTCAvIFRMUyIsICJDZXJ0aWZpY2F0ZSBjaGFpbiBjb21wbGV0ZSAt"
    "IG5vIG1pc3NpbmcgaW50ZXJtZWRpYXRlcyIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIsCiAgICAgICAg"
    "ICAgICJIYW5kc2hha2UgY29tcGxldGVkIHdpdGggZGVmYXVsdCB0cnVzdCBzdG9yZSB2YWxpZGF0aW9uIChjaGFpbiByZXNv"
    "bHZlcykgLSAiICsKICAgICAgICAgICAgKCJpbnNlY3VyZSBtb2RlIHdhcyBvbiwgc28gdGhpcyBkb2Vzbid0IGNvbmZpcm0g"
    "dHJ1c3QuIiBpZiBhcmdzLmluc2VjdXJlIGVsc2UKICAgICAgICAgICAgICJjZXJ0aWZpY2F0ZSBjaGFpbiBpcyB0cnVzdGVk"
    "IGJ5IHRoaXMgbWFjaGluZSdzIENBIGJ1bmRsZS4iKSkKICAgIGV4Y2VwdCBzc2wuU1NMQ2VydFZlcmlmaWNhdGlvbkVycm9y"
    "IGFzIGU6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtVExTLTQwNyIsICJTU0wgLyBUTFMiLCAiQ2VydGlmaWNhdGUgY2hh"
    "aW4gY29tcGxldGUgLSBubyBtaXNzaW5nIGludGVybWVkaWF0ZXMiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZB"
    "SUwiLCBmIkNlcnRpZmljYXRlIHZlcmlmaWNhdGlvbiBmYWlsZWQ6IHtlfSIpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6"
    "CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtVExTLTQwNyIsICJTU0wgLyBUTFMiLCAiQ2VydGlmaWNhdGUgY2hhaW4gY29t"
    "cGxldGUgLSBubyBtaXNzaW5nIGludGVybWVkaWF0ZXMiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkVSUk9SIiwg"
    "c3RyKGUpKQoKICAgIGhzdHNfaGVhZGVyID0gIiIKICAgIHIgPSByYXdfcmVxdWVzdChmdWxsX3VybCwgIkdFVCIsIHRpbWVv"
    "dXQ9YXJncy50aW1lb3V0LCBpbnNlY3VyZT1hcmdzLmluc2VjdXJlKQogICAgaWYgbm90IHIuZXJyb3I6CiAgICAgICAgaHN0"
    "c19oZWFkZXIgPSByLmhlYWRlcigiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSIpCiAgICBwcmVsb2FkX2ludGVudCA9ICJw"
    "cmVsb2FkIiBpbiBoc3RzX2hlYWRlci5sb3dlcigpCiAgICBwcmVsb2FkX2xpc3RlZCA9IE5vbmUKICAgIHRyeToKICAgICAg"
    "ICBhcGkgPSByYXdfcmVxdWVzdChmImh0dHBzOi8vaHN0c3ByZWxvYWQub3JnL2FwaS92Mi9zdGF0dXM/ZG9tYWluPXtob3N0"
    "fSIsICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCkKICAgICAgICBpZiBub3QgYXBpLmVycm9yIGFuZCBhcGkuc3RhdHVz"
    "ID09IDIwMDoKICAgICAgICAgICAgZGF0YSA9IGpzb24ubG9hZHMoYXBpLnRleHQoKSkKICAgICAgICAgICAgcHJlbG9hZF9s"
    "aXN0ZWQgPSBkYXRhLmdldCgic3RhdHVzIikKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcHJlbG9hZF9saXN0ZWQg"
    "PSBOb25lCiAgICBldmlkZW5jZSA9IGYiSFNUUyBoZWFkZXIgaW5jbHVkZXMgJ3ByZWxvYWQnOiB7cHJlbG9hZF9pbnRlbnR9"
    "LiIKICAgIGlmIHByZWxvYWRfbGlzdGVkOgogICAgICAgIGV2aWRlbmNlICs9IGYiIGhzdHNwcmVsb2FkLm9yZyBzdGF0dXM6"
    "IHtwcmVsb2FkX2xpc3RlZH0uIgogICAgICAgIHJlc3VsdCA9ICJQQVNTIiBpZiBwcmVsb2FkX2xpc3RlZCA9PSAicHJlbG9h"
    "ZGVkIiBlbHNlICJGQUlMIgogICAgZWxzZToKICAgICAgICBldmlkZW5jZSArPSAiIENvdWxkIG5vdCByZWFjaCBoc3RzcHJl"
    "bG9hZC5vcmcgQVBJIHRvIGNvbmZpcm0gYWN0dWFsIGxpc3QgbWVtYmVyc2hpcC4iCiAgICAgICAgcmVzdWx0ID0gIklORk8i"
    "IGlmIHByZWxvYWRfaW50ZW50IGVsc2UgIkZBSUwiCiAgICBhZGQoZnVsbF91cmwsICJXQS1UTFMtNDA4IiwgIlNTTCAvIFRM"
    "UyIsICJIU1RTIHByZWxvYWQgbGlzdCBjb25maWd1cmVkIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgcmVzdWx0LCBldmlk"
    "ZW5jZSkKCiAgICBhZGQoZnVsbF91cmwsICJXQS1UTFMtNDA5IiwgIlNTTCAvIFRMUyIsICJXZWJTb2NrZXQgZW5kcG9pbnRz"
    "IHVzZSBXU1Mgbm90IFdTIiwKICAgICAgICAiSGlnaCIsICJQMSIsICJNQU5VQUwiLAogICAgICAgICJObyB3ZWJzb2NrZXQg"
    "ZW5kcG9pbnQgaXMga25vd24gZnJvbSBhIHBsYWluIFVSTCAtIGlkZW50aWZ5IHdzOi8vIHZzIHdzczovLyB1c2FnZSB2aWEg"
    "YnJvd3NlciAiCiAgICAgICAgImRldiB0b29scyAvIEJ1cnAgV2ViU29ja2V0cyBoaXN0b3J5IHdoaWxlIHVzaW5nIHRoZSBh"
    "cHAsIHRoZW4gdmVyaWZ5IG1hbnVhbGx5LiIpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDMuIENsaWNramFja2luZyAtIFdBLUNTLTE2MS4uMTY1CiMg"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0KCmRlZiBjaGVja19jbGlja2phY2tpbmcoZnVsbF91cmwsIGhlYWRlcnNfcmVzdWx0KToKICAgIGlmIGhlYWRlcnNfcmVz"
    "dWx0LmVycm9yOgogICAgICAgIGZvciBjaWQsIG5hbWUgaW4gWwogICAgICAgICAgICAoIldBLUNTLTE2MSIsICJDbGlja2ph"
    "Y2tpbmcgLSBiYXNpYyBVSSByZWRyZXNzIGF0dGFjayAoaWZyYW1lIG92ZXJsYXkpIiksCiAgICAgICAgICAgICgiV0EtQ1Mt"
    "MTYyIiwgIkNsaWNramFja2luZyAtIGZvcm0gcHJlLWZpbGwgYXR0YWNrIiksCiAgICAgICAgICAgICgiV0EtQ1MtMTYzIiwg"
    "IkNsaWNramFja2luZyAtIGZyYW1lLWJ1c3Rpbmcgc2NyaXB0IGJ5cGFzcyIpLAogICAgICAgICAgICAoIldBLUNTLTE2NCIs"
    "ICJDbGlja2phY2tpbmcgLSBtdWx0aXN0ZXAgYXR0YWNrIChjb25maXJtICsgY2xpY2spIiksCiAgICAgICAgICAgICgiV0Et"
    "Q1MtMTY1IiwgIkNsaWNramFja2luZyAtIGRyYWctYW5kLWRyb3AgVUkgYXR0YWNrIiksCiAgICAgICAgXToKICAgICAgICAg"
    "ICAgYWRkKGZ1bGxfdXJsLCBjaWQsICJDbGlja2phY2tpbmciLCBuYW1lLCAiTWVkaXVtIiwgIlAyIiwgIkVSUk9SIiwgaGVh"
    "ZGVyc19yZXN1bHQuZXJyb3IpCiAgICAgICAgcmV0dXJuCgogICAgeGZvID0gaGVhZGVyc19yZXN1bHQuaGVhZGVyKCJYLUZy"
    "YW1lLU9wdGlvbnMiKQogICAgY3NwID0gaGVhZGVyc19yZXN1bHQuaGVhZGVyKCJDb250ZW50LVNlY3VyaXR5LVBvbGljeSIp"
    "CiAgICBwcm90ZWN0ZWQgPSAoeGZvLnN0cmlwKCkudXBwZXIoKSBpbiAoIkRFTlkiLCAiU0FNRU9SSUdJTiIpKSBvciAoImZy"
    "YW1lLWFuY2VzdG9ycyIgaW4gY3NwLmxvd2VyKCkpCiAgICBhZGQoZnVsbF91cmwsICJXQS1DUy0xNjEiLCAiQ2xpY2tqYWNr"
    "aW5nIiwgIkNsaWNramFja2luZyAtIGJhc2ljIFVJIHJlZHJlc3MgYXR0YWNrIChpZnJhbWUgb3ZlcmxheSkiLAogICAgICAg"
    "ICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIgaWYgcHJvdGVjdGVkIGVsc2UgIkZBSUwiLAogICAgICAgIGYiWC1GcmFtZS1PcHRp"
    "b25zOiB7eGZvIG9yICdtaXNzaW5nJ30sIENTUCBmcmFtZS1hbmNlc3RvcnMgcHJlc2VudDogeydmcmFtZS1hbmNlc3RvcnMn"
    "IGluIGNzcC5sb3dlcigpfS4gIiArCiAgICAgICAgKCJQYWdlIGNhbiBsaWtlbHkgYmUgZnJhbWVkIC0gYnVpbGQgYW4gaWZy"
    "YW1lIFBvQyB0byBjb25maXJtIGV4cGxvaXRhYmlsaXR5LiIgaWYgbm90IHByb3RlY3RlZCBlbHNlCiAgICAgICAgICJGcmFt"
    "aW5nIGhlYWRlcnMgcHJlc2VudCAtIHBhZ2UgaXMgbGlrZWx5IHByb3RlY3RlZC4iKSkKCiAgICBmb3IgY2lkLCBuYW1lIGlu"
    "IFsKICAgICAgICAoIldBLUNTLTE2MiIsICJDbGlja2phY2tpbmcgLSBmb3JtIHByZS1maWxsIGF0dGFjayIpLAogICAgICAg"
    "ICgiV0EtQ1MtMTYzIiwgIkNsaWNramFja2luZyAtIGZyYW1lLWJ1c3Rpbmcgc2NyaXB0IGJ5cGFzcyIpLAogICAgICAgICgi"
    "V0EtQ1MtMTY0IiwgIkNsaWNramFja2luZyAtIG11bHRpc3RlcCBhdHRhY2sgKGNvbmZpcm0gKyBjbGljaykiKSwKICAgICAg"
    "ICAoIldBLUNTLTE2NSIsICJDbGlja2phY2tpbmcgLSBkcmFnLWFuZC1kcm9wIFVJIGF0dGFjayIpLAogICAgXToKICAgICAg"
    "ICBhZGQoZnVsbF91cmwsIGNpZCwgIkNsaWNramFja2luZyIsIG5hbWUsICJNZWRpdW0iLCAiUDIiLCAiTUFOVUFMIiwKICAg"
    "ICAgICAgICAgIk5lZWRzIGFuIGFjdHVhbCBQb0MgSFRNTCBwYWdlICsgYnJvd3NlciBpbnRlcmFjdGlvbiB0byB2ZXJpZnkg"
    "LSBub3QgdGVzdGFibGUgZnJvbSBoZWFkZXJzIGFsb25lLiIpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDQuIENPUlMgLSBXQS1DUy0xNTguLjE2MAoj"
    "IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tCgpkZWYgY2hlY2tfY29ycyhmdWxsX3VybCwgYXJncyk6CiAgICBldmlsX29yaWdpbiA9IGYiaHR0cHM6Ly9ldmlsLWNv"
    "cnMtdGVzdC17cmFuZF90b2tlbig2KX0uZXhhbXBsZSIKICAgIHIxID0gcmF3X3JlcXVlc3QoZnVsbF91cmwsICJHRVQiLCBl"
    "eHRyYV9oZWFkZXJzPXsiT3JpZ2luIjogZXZpbF9vcmlnaW59LAogICAgICAgICAgICAgICAgICAgICAgdGltZW91dD1hcmdz"
    "LnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICBpZiByMS5lcnJvcjoKICAgICAgICBmb3IgY2lkLCBuYW1l"
    "IGluIFsoIldBLUNTLTE1OCIsICJDT1JTIC0gbWlzY29uZmlnOiB3aWxkY2FyZC9yZWZsZWN0ZWQgb3JpZ2luIHRydXN0cyBh"
    "dHRhY2tlciIpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAoIldBLUNTLTE1OSIsICJDT1JTIC0gbnVsbCBvcmlnaW4g"
    "dHJ1c3RlZCAoc2FuZGJveCBpZnJhbWUgYnlwYXNzKSIpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAoIldBLUNTLTE2"
    "MCIsICJDT1JTIC0gaW50cmFuZXQgcGl2b3QgdmlhIHRydXN0ZWQgd2hpdGVsaXN0ZWQgb3JpZ2luIildOgogICAgICAgICAg"
    "ICBhZGQoZnVsbF91cmwsIGNpZCwgIkNPUlMiLCBuYW1lLCAiSGlnaCIsICJQMSIsICJFUlJPUiIsIHIxLmVycm9yKQogICAg"
    "ICAgIHJldHVybgoKICAgIGFjYW8gPSByMS5oZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbiIpCiAgICBhY2Fj"
    "ID0gcjEuaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1DcmVkZW50aWFscyIpCiAgICByZWZsZWN0ZWQgPSBhY2FvID09"
    "IGV2aWxfb3JpZ2luCiAgICB3aWxkY2FyZF93aXRoX2NyZWRzID0gYWNhbyA9PSAiKiIgYW5kIGFjYWMubG93ZXIoKSA9PSAi"
    "dHJ1ZSIKICAgIGZhaWwxID0gcmVmbGVjdGVkIG9yIHdpbGRjYXJkX3dpdGhfY3JlZHMKICAgIGFkZChmdWxsX3VybCwgIldB"
    "LUNTLTE1OCIsICJDT1JTIiwgIkNPUlMgLSBtaXNjb25maWc6IHdpbGRjYXJkL3JlZmxlY3RlZCBvcmlnaW4gdHJ1c3RzIGF0"
    "dGFja2VyIiwKICAgICAgICAiSGlnaCIsICJQMSIsICJGQUlMIiBpZiBmYWlsMSBlbHNlICJQQVNTIiwKICAgICAgICBmIlNl"
    "bnQgT3JpZ2luOiB7ZXZpbF9vcmlnaW59IC0+IEFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbjoge2FjYW8gb3IgJ25vbmUn"
    "fSwgIgogICAgICAgIGYiQWNjZXNzLUNvbnRyb2wtQWxsb3ctQ3JlZGVudGlhbHM6IHthY2FjIG9yICdub25lJ30uIiArCiAg"
    "ICAgICAgKCIgQXJiaXRyYXJ5IG9yaWdpbiBpcyByZWZsZWN0ZWQvdHJ1c3RlZCAtIGxpa2VseSBleHBsb2l0YWJsZS4iIGlm"
    "IGZhaWwxIGVsc2UgIiIpKQoKICAgIHIyID0gcmF3X3JlcXVlc3QoZnVsbF91cmwsICJHRVQiLCBleHRyYV9oZWFkZXJzPXsi"
    "T3JpZ2luIjogIm51bGwifSwKICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQ9YXJncy50aW1lb3V0LCBpbnNlY3VyZT1h"
    "cmdzLmluc2VjdXJlKQogICAgYWNhb19udWxsID0gcjIuaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4iKSBp"
    "ZiBub3QgcjIuZXJyb3IgZWxzZSAiIgogICAgbnVsbF90cnVzdGVkID0gYWNhb19udWxsLnN0cmlwKCkgPT0gIm51bGwiCiAg"
    "ICBhZGQoZnVsbF91cmwsICJXQS1DUy0xNTkiLCAiQ09SUyIsICJDT1JTIC0gbnVsbCBvcmlnaW4gdHJ1c3RlZCAoc2FuZGJv"
    "eCBpZnJhbWUgYnlwYXNzKSIsCiAgICAgICAgIkhpZ2giLCAiUDEiLCAiRkFJTCIgaWYgbnVsbF90cnVzdGVkIGVsc2UgIlBB"
    "U1MiLAogICAgICAgIGYiU2VudCBPcmlnaW46IG51bGwgLT4gQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luOiB7YWNhb19u"
    "dWxsIG9yICdub25lJ30uIiArCiAgICAgICAgKCIgJ251bGwnIG9yaWdpbiBpcyB0cnVzdGVkIC0gZXhwbG9pdGFibGUgdmlh"
    "IHNhbmRib3hlZCBpZnJhbWUvZGF0YTogVVJJLiIgaWYgbnVsbF90cnVzdGVkIGVsc2UgIiIpKQoKICAgIGFkZChmdWxsX3Vy"
    "bCwgIldBLUNTLTE2MCIsICJDT1JTIiwgIkNPUlMgLSBpbnRyYW5ldCBwaXZvdCB2aWEgdHJ1c3RlZCB3aGl0ZWxpc3RlZCBv"
    "cmlnaW4iLAogICAgICAgICJIaWdoIiwgIlAxIiwgIk1BTlVBTCIsCiAgICAgICAgIk5lZWRzIHRoZSBhcHAncyBhY3R1YWwg"
    "d2hpdGVsaXN0ZWQtb3JpZ2luIGxpc3QgKGUuZy4gaW50ZXJuYWwgc3ViZG9tYWlucykgdG8gdGVzdCAtICIKICAgICAgICAi"
    "Y2FuJ3QgYmUgZ3Vlc3NlZCBnZW5lcmljYWxseS4gUmV2aWV3IHRoZSBDT1JTIGFsbG93LWxpc3Qgc291cmNlL2NvbmZpZyBt"
    "YW51YWxseS4iKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0KIyA1LiBJbmZvcm1hdGlvbiBHYXRoZXJpbmcgLSBXQS1PVEctMjczLi4yODIKIyAtLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVm"
    "IGNoZWNrX2luZm9ybWF0aW9uX2dhdGhlcmluZyhmdWxsX3VybCwgaGVhZGVyc19yZXN1bHQsIGFyZ3MpOgogICAgYmFzZSA9"
    "IGRpcl9vZihmdWxsX3VybCkKCiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjczIiwgIkluZm9ybWF0aW9uIEdhdGhlcmlu"
    "ZyIsICJDb25kdWN0IHNlYXJjaCBlbmdpbmUgcmVjb24gKEdvb2dsZSBkb3JrcywgU2hvZGFuKSIsCiAgICAgICAgIkluZm8i"
    "LCAiUDMiLCAiTUFOVUFMIiwgIk5lZWRzIGV4dGVybmFsIE9TSU5UL3NlYXJjaC1lbmdpbmUvU2hvZGFuIHF1ZXJpZXMgLSBu"
    "b3QgdGVzdGFibGUgZnJvbSB0aGUgdGFyZ2V0IGRpcmVjdGx5LiIpCgogICAgc2VydmVyX2hkciA9IGhlYWRlcnNfcmVzdWx0"
    "LmhlYWRlcigiU2VydmVyIikgaWYgbm90IGhlYWRlcnNfcmVzdWx0LmVycm9yIGVsc2UgIiIKICAgIGFkZChmdWxsX3VybCwg"
    "IldBLU9URy0yNzQiLCAiSW5mb3JtYXRpb24gR2F0aGVyaW5nIiwgIkZpbmdlcnByaW50IHdlYiBzZXJ2ZXIgKFNlcnZlciBo"
    "ZWFkZXIsIGVycm9yIHBhZ2VzKSIsCiAgICAgICAgIkxvdyIsICJQMyIsICJJTkZPIiwgZiJTZXJ2ZXIgaGVhZGVyOiB7c2Vy"
    "dmVyX2hkciBvciAnbm90IGRpc2Nsb3NlZCd9LiIpCgogICAgcm9ib3RzID0gcmF3X3JlcXVlc3Qoam9pbl90YXJnZXQoYmFz"
    "ZSwgIi9yb2JvdHMudHh0IiksICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkK"
    "ICAgIHNpdGVtYXAgPSByYXdfcmVxdWVzdChqb2luX3RhcmdldChiYXNlLCAiL3NpdGVtYXAueG1sIiksICJHRVQiLCB0aW1l"
    "b3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIGRpc2FsbG93X2xpbmVzID0gW10KICAgIGlm"
    "IG5vdCByb2JvdHMuZXJyb3IgYW5kIHJvYm90cy5zdGF0dXMgPT0gMjAwOgogICAgICAgIGRpc2FsbG93X2xpbmVzID0gW2wu"
    "c3RyaXAoKSBmb3IgbCBpbiByb2JvdHMudGV4dCgpLnNwbGl0bGluZXMoKSBpZiBsLnN0cmlwKCkubG93ZXIoKS5zdGFydHN3"
    "aXRoKCJkaXNhbGxvdyIpXQogICAgc2Vuc2l0aXZlX2hpbnQgPSBhbnkocmUuc2VhcmNoKHIiYWRtaW58YmFja3VwfGNvbmZp"
    "Z3xwcml2YXRlfGludGVybmFsfFwuZ2l0fHN0YWdpbmciLCBsLCByZS5JKSBmb3IgbCBpbiBkaXNhbGxvd19saW5lcykKICAg"
    "IGFkZChmdWxsX3VybCwgIldBLU9URy0yNzUiLCAiSW5mb3JtYXRpb24gR2F0aGVyaW5nIiwgIlJldmlldyB3ZWJzZXJ2ZXIg"
    "bWV0YWZpbGVzIChyb2JvdHMudHh0LCBzaXRlbWFwLnhtbCkiLAogICAgICAgICJMb3ciLCAiUDMiLCAiRkFJTCIgaWYgc2Vu"
    "c2l0aXZlX2hpbnQgZWxzZSAiSU5GTyIsCiAgICAgICAgZiJyb2JvdHMudHh0OiB7JzIwMCwgJyArIHN0cihsZW4oZGlzYWxs"
    "b3dfbGluZXMpKSArICcgRGlzYWxsb3cgZW50cmllcycgaWYgbm90IHJvYm90cy5lcnJvciBhbmQgcm9ib3RzLnN0YXR1cyA9"
    "PSAyMDAgZWxzZSAnbm90IGZvdW5kL2Vycm9yJ30iCiAgICAgICAgZiJ7JyAoJyArICc7ICcuam9pbihkaXNhbGxvd19saW5l"
    "c1s6OF0pICsgJyknIGlmIGRpc2FsbG93X2xpbmVzIGVsc2UgJyd9LiAiCiAgICAgICAgZiJzaXRlbWFwLnhtbDogeycyMDAn"
    "IGlmIG5vdCBzaXRlbWFwLmVycm9yIGFuZCBzaXRlbWFwLnN0YXR1cyA9PSAyMDAgZWxzZSAnbm90IGZvdW5kL2Vycm9yJ30u"
    "IiArCiAgICAgICAgKCIgcm9ib3RzLnR4dCBEaXNhbGxvdyBsaXN0IGl0c2VsZiBoaW50cyBhdCBzZW5zaXRpdmUgcGF0aHMg"
    "LSByZXZpZXcgdGhlbSBkaXJlY3RseS4iIGlmIHNlbnNpdGl2ZV9oaW50IGVsc2UgIiIpKQoKICAgIGZvciBjaWQsIG5hbWUg"
    "aW4gWygiV0EtT1RHLTI3NiIsICJFbnVtZXJhdGUgYXBwbGljYXRpb24gZW50cnkgcG9pbnRzIChhbGwgcGFyYW1zL2Zvcm1z"
    "KSIpLAogICAgICAgICAgICAgICAgICAgICAgICgiV0EtT1RHLTI3NyIsICJNYXAgZXhlY3V0aW9uIHBhdGhzIHRocm91Z2gg"
    "YXBwbGljYXRpb24iKV06CiAgICAgICAgYWRkKGZ1bGxfdXJsLCBjaWQsICJJbmZvcm1hdGlvbiBHYXRoZXJpbmciLCBuYW1l"
    "LCAiSW5mbyIsICJQMyIsICJNQU5VQUwiLAogICAgICAgICAgICAiTmVlZHMgZnVsbCBjcmF3bGluZy9zcGlkZXJpbmcgKEJ1"
    "cnAgU3BpZGVyLCBrYXRhbmEsIGhha3Jhd2xlcikgYWNyb3NzIHRoZSB3aG9sZSBhcHAgLSBhIHNpbmdsZS1wYWdlIGZldGNo"
    "IGlzbid0IHJlcHJlc2VudGF0aXZlLiIpCgogICAgYm9keV90ZXh0ID0gaGVhZGVyc19yZXN1bHQudGV4dCgpIGlmIG5vdCBo"
    "ZWFkZXJzX3Jlc3VsdC5lcnJvciBlbHNlICIiCiAgICB4cGIgPSBoZWFkZXJzX3Jlc3VsdC5oZWFkZXIoIlgtUG93ZXJlZC1C"
    "eSIpIGlmIG5vdCBoZWFkZXJzX3Jlc3VsdC5lcnJvciBlbHNlICIiCiAgICBjb29raWVzX3JhdyA9IGhlYWRlcnNfcmVzdWx0"
    "LmhlYWRlcnMgaWYgbm90IGhlYWRlcnNfcmVzdWx0LmVycm9yIGVsc2Uge30KICAgIGNvb2tpZV9uYW1lcyA9IFtdCiAgICBm"
    "b3IgaywgdiBpbiBjb29raWVzX3Jhdy5pdGVtcygpOgogICAgICAgIGlmIGsubG93ZXIoKSA9PSAic2V0LWNvb2tpZSI6CiAg"
    "ICAgICAgICAgIG0gPSByZS5tYXRjaChyIihbXj1dKyk9IiwgdikKICAgICAgICAgICAgaWYgbToKICAgICAgICAgICAgICAg"
    "IGNvb2tpZV9uYW1lcy5hcHBlbmQobS5ncm91cCgxKSkKICAgIGZ3X2hpbnRzID0gW10KICAgIGlmIHhwYjoKICAgICAgICBm"
    "d19oaW50cy5hcHBlbmQoZiJYLVBvd2VyZWQtQnk6IHt4cGJ9IikKICAgIGZvciBjbiBpbiBjb29raWVfbmFtZXM6CiAgICAg"
    "ICAgaWYgY24udXBwZXIoKSBpbiAoIlBIUFNFU1NJRCIsKToKICAgICAgICAgICAgZndfaGludHMuYXBwZW5kKCJQSFAgKFBI"
    "UFNFU1NJRCBjb29raWUpIikKICAgICAgICBlbGlmIGNuLnVwcGVyKCkgaW4gKCJKU0VTU0lPTklEIiwpOgogICAgICAgICAg"
    "ICBmd19oaW50cy5hcHBlbmQoIkphdmEvSlNQIChKU0VTU0lPTklEIGNvb2tpZSkiKQogICAgICAgIGVsaWYgImxhcmF2ZWxf"
    "c2Vzc2lvbiIgaW4gY24ubG93ZXIoKToKICAgICAgICAgICAgZndfaGludHMuYXBwZW5kKCJMYXJhdmVsIChsYXJhdmVsX3Nl"
    "c3Npb24gY29va2llKSIpCiAgICAgICAgZWxpZiAiZGphbmdvIiBpbiBjbi5sb3dlcigpIG9yICJjc3JmdG9rZW4iIGluIGNu"
    "Lmxvd2VyKCk6CiAgICAgICAgICAgIGZ3X2hpbnRzLmFwcGVuZCgiRGphbmdvIChkamFuZ28vY3NyZnRva2VuIGNvb2tpZSki"
    "KQogICAgZ2VuX21hdGNoID0gcmUuc2VhcmNoKHInPG1ldGFbXj5dK25hbWU9WyJcJ11nZW5lcmF0b3JbIlwnXVtePl0rY29u"
    "dGVudD1bIlwnXShbXiJcJ10rKScsIGJvZHlfdGV4dCwgcmUuSSkKICAgIGlmIGdlbl9tYXRjaDoKICAgICAgICBmd19oaW50"
    "cy5hcHBlbmQoZiJtZXRhIGdlbmVyYXRvciB0YWc6IHtnZW5fbWF0Y2guZ3JvdXAoMSl9IikKICAgIGFkZChmdWxsX3VybCwg"
    "IldBLU9URy0yNzgiLCAiSW5mb3JtYXRpb24gR2F0aGVyaW5nIiwgIkZpbmdlcnByaW50IHdlYiBhcHBsaWNhdGlvbiBmcmFt"
    "ZXdvcmsiLAogICAgICAgICJMb3ciLCAiUDMiLCAiSU5GTyIsICI7ICIuam9pbihmd19oaW50cykgaWYgZndfaGludHMgZWxz"
    "ZSAiTm8gb2J2aW91cyBmcmFtZXdvcmsgZmluZ2VycHJpbnQgZm91bmQgaW4gaGVhZGVycy9jb29raWVzL2hvbWVwYWdlLiIp"
    "CgogICAgY2RuX2hpbnRzID0gW10KICAgIGlmIG5vdCBoZWFkZXJzX3Jlc3VsdC5lcnJvcjoKICAgICAgICBmb3IgaGssIGh2"
    "IGluIGhlYWRlcnNfcmVzdWx0LmhlYWRlcnMuaXRlbXMoKToKICAgICAgICAgICAgaGtfbCA9IGhrLmxvd2VyKCkKICAgICAg"
    "ICAgICAgaWYgaGtfbCBpbiBDRE5fV0FGX0hFQURFUl9ISU5UUzoKICAgICAgICAgICAgICAgIGZvciBuZWVkbGUsIGxhYmVs"
    "IGluIENETl9XQUZfSEVBREVSX0hJTlRTW2hrX2xdLml0ZW1zKCk6CiAgICAgICAgICAgICAgICAgICAgaWYgbmVlZGxlID09"
    "ICIiIG9yIG5lZWRsZSBpbiBodi5sb3dlcigpOgogICAgICAgICAgICAgICAgICAgICAgICBjZG5faGludHMuYXBwZW5kKGYi"
    "e2xhYmVsfSAodmlhIHtoa306IHtodls6NjBdfSkiKQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTI3OSIsICJJbmZvcm1h"
    "dGlvbiBHYXRoZXJpbmciLCAiTWFwIGFwcGxpY2F0aW9uIGFyY2hpdGVjdHVyZSAoQ0ROLCBXQUYsIExCLCBwcm94eSBsYXll"
    "cnMpIiwKICAgICAgICAiSW5mbyIsICJQMyIsICJJTkZPIiwgIjsgIi5qb2luKGNkbl9oaW50cykgaWYgY2RuX2hpbnRzIGVs"
    "c2UgIk5vIENETi9XQUYvcHJveHkgaGVhZGVyIGhpbnRzIGRldGVjdGVkIG9uIHRoaXMgcmVzcG9uc2UuIikKCiAgICBkZXBf"
    "aGl0cyA9IFtdCiAgICBmb3IgcGF0aCBpbiBERVBFTkRFTkNZX1BST0JFUzoKICAgICAgICByciA9IHJhd19yZXF1ZXN0KGpv"
    "aW5fdGFyZ2V0KGJhc2UsIHBhdGgpLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1"
    "cmUpCiAgICAgICAgaWYgbm90IHJyLmVycm9yIGFuZCByci5zdGF0dXMgPT0gMjAwOgogICAgICAgICAgICBkZXBfaGl0cy5h"
    "cHBlbmQocGF0aCkKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODAiLCAiSW5mb3JtYXRpb24gR2F0aGVyaW5nIiwgIklk"
    "ZW50aWZ5IGFwcGxpY2F0aW9uIGRlcGVuZGVuY2llcyAocGFja2FnZS5qc29uLCBHZW1maWxlLCBwb20pIiwKICAgICAgICAi"
    "TG93IiwgIlAzIiwgIkZBSUwiIGlmIGRlcF9oaXRzIGVsc2UgIlBBU1MiLAogICAgICAgIGYiUHVibGljbHkgYWNjZXNzaWJs"
    "ZSBkZXBlbmRlbmN5IG1hbmlmZXN0KHMpOiB7JywgJy5qb2luKGRlcF9oaXRzKX0iIGlmIGRlcF9oaXRzIGVsc2UKICAgICAg"
    "ICBmIk5vbmUgb2YgdGhlIHByb2JlZCBtYW5pZmVzdCBwYXRocyAoeycsICcuam9pbihERVBFTkRFTkNZX1BST0JFUyl9KSBh"
    "cmUgcHVibGljbHkgYWNjZXNzaWJsZSBhdCB0aGUgc2l0ZSByb290LiIpCgogICAgZW1haWxzID0gc29ydGVkKHNldChyZS5m"
    "aW5kYWxsKHIiW2EtekEtWjAtOS5fJSstXStAW2EtekEtWjAtOS4tXStcLlthLXpBLVpdezIsfSIsIGJvZHlfdGV4dCkpKVs6"
    "MTBdCiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjgxIiwgIkluZm9ybWF0aW9uIEdhdGhlcmluZyIsICJIYXJ2ZXN0IGVt"
    "YWlscywgdXNlcm5hbWVzLCBwaG9uZSBudW1iZXJzIGZyb20gYXBwIiwKICAgICAgICAiSW5mbyIsICJQMyIsICJJTkZPIiBp"
    "ZiBlbWFpbHMgZWxzZSAiTUFOVUFMIiwKICAgICAgICAoZiJFbWFpbCBhZGRyZXNzKGVzKSBmb3VuZCBvbiB0aGlzIHNpbmds"
    "ZSBwYWdlOiB7JywgJy5qb2luKGVtYWlscyl9LiAiCiAgICAgICAgICJUaGlzIGlzIG9ubHkgYSBzcG90LWNoZWNrIG9mIG9u"
    "ZSBwYWdlLCBub3QgYSBmdWxsIGhhcnZlc3QuIiBpZiBlbWFpbHMgZWxzZQogICAgICAgICAiTm9uZSBmb3VuZCBvbiB0aGlz"
    "IHNpbmdsZSBwYWdlIC0gYSBmdWxsIGhhcnZlc3QgbmVlZHMgY3Jhd2xpbmcgdGhlIHdob2xlIGFwcC4iKSkKCiAgICBidWNr"
    "ZXRfaGl0cyA9IHNvcnRlZChzZXQobSBmb3IgcGF0IGluIENMT1VEX0JVQ0tFVF9QQVRURVJOUyBmb3IgbSBpbiByZS5maW5k"
    "YWxsKHBhdCwgYm9keV90ZXh0LCByZS5JKSkpWzoxMF0KICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODIiLCAiSW5mb3Jt"
    "YXRpb24gR2F0aGVyaW5nIiwgIklkZW50aWZ5IGNsb3VkIHN0b3JhZ2UgYnVja2V0cyAoUzMsIEdDUywgQXp1cmUgQmxvYiki"
    "LAogICAgICAgICJIaWdoIiwgIlAxIiwgIklORk8iIGlmIGJ1Y2tldF9oaXRzIGVsc2UgIlBBU1MiLAogICAgICAgIChmIkNs"
    "b3VkIHN0b3JhZ2UgcmVmZXJlbmNlKHMpIGZvdW5kIG9uIHRoaXMgcGFnZTogeycsICcuam9pbihidWNrZXRfaGl0cyl9IC0g"
    "Y2hlY2sgZWFjaCBtYW51YWxseSBmb3IgIgogICAgICAgICAicHVibGljIHJlYWQvd3JpdGUvbGlzdCBhY2Nlc3MuIiBpZiBi"
    "dWNrZXRfaGl0cyBlbHNlICJObyBjbG91ZCBzdG9yYWdlIGJ1Y2tldCBVUkxzIHJlZmVyZW5jZWQgb24gdGhpcyBzaW5nbGUg"
    "cGFnZS4iKSkKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tCiMgNi4gQ29uZmlndXJhdGlvbiBUZXN0aW5nIC0gV0EtT1RHLTI4My4uMjk0CiMgLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBf"
    "cG9ydF9zY2FuKGhvc3QsIHBvcnRzLCB0aW1lb3V0PTIuMCk6CiAgICBvcGVuX3BvcnRzID0gW10KICAgIGZvciBwb3J0IGlu"
    "IHBvcnRzOgogICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKGhvc3QsIHBv"
    "cnQpLCB0aW1lb3V0PXRpbWVvdXQpOgogICAgICAgICAgICAgICAgb3Blbl9wb3J0cy5hcHBlbmQocG9ydCkKICAgICAgICBl"
    "eGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBwYXNzCiAgICByZXR1cm4gb3Blbl9wb3J0cwoKCmRlZiBjaGVja19jb25m"
    "aWd1cmF0aW9uKGZ1bGxfdXJsLCBoZWFkZXJzX3Jlc3VsdCwgaGRyX2N1cmxfYmxvY2ssIGFyZ3MpOgogICAgYmFzZSA9IGRp"
    "cl9vZihmdWxsX3VybCkKICAgIGhvc3QgPSB1cmxwYXJzZShmdWxsX3VybCkuaG9zdG5hbWUKCiAgICBpZiBhcmdzLnBvcnRf"
    "c2NhbjoKICAgICAgICBvcGVuX3BvcnRzID0gX3BvcnRfc2Nhbihob3N0LCBDT01NT05fQURNSU5fUE9SVFMsIHRpbWVvdXQ9"
    "bWluKGFyZ3MudGltZW91dCwgMykpCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTI4MyIsICJDb25maWd1cmF0aW9u"
    "IFRlc3RpbmciLCAiVGVzdCBuZXR3b3JrL2luZnJhc3RydWN0dXJlIGNvbmZpZyAoZXhwb3NlZCBhZG1pbiBwb3J0cykiLAog"
    "ICAgICAgICAgICAiSGlnaCIsICJQMSIsICJGQUlMIiBpZiBvcGVuX3BvcnRzIGVsc2UgIlBBU1MiLAogICAgICAgICAgICBm"
    "IkNvbW1vbiBhZG1pbi9EQiBwb3J0cyBwcm9iZWQgKHsnLCAnLmpvaW4obWFwKHN0ciwgQ09NTU9OX0FETUlOX1BPUlRTKSl9"
    "KS4gIgogICAgICAgICAgICBmIk9wZW46IHsnLCAnLmpvaW4obWFwKHN0ciwgb3Blbl9wb3J0cykpIGlmIG9wZW5fcG9ydHMg"
    "ZWxzZSAnbm9uZSd9LiIpCiAgICBlbHNlOgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODMiLCAiQ29uZmlndXJh"
    "dGlvbiBUZXN0aW5nIiwgIlRlc3QgbmV0d29yay9pbmZyYXN0cnVjdHVyZSBjb25maWcgKGV4cG9zZWQgYWRtaW4gcG9ydHMp"
    "IiwKICAgICAgICAgICAgIkhpZ2giLCAiUDEiLCAiTUFOVUFMIiwgIlNraXBwZWQgYnkgZGVmYXVsdCAobm9pc2llciBzY2Fu"
    "KS4gUmUtcnVuIHdpdGggLS1wb3J0LXNjYW4sIG9yIHVzZSBubWFwIGRpcmVjdGx5LiIpCgogICAgYWRkKGZ1bGxfdXJsLCAi"
    "V0EtT1RHLTI4NCIsICJDb25maWd1cmF0aW9uIFRlc3RpbmciLCAiVGVzdCBhcHBsaWNhdGlvbiBwbGF0Zm9ybSBjb25maWd1"
    "cmF0aW9uIChkZWZhdWx0IGNyZWRzKSIsCiAgICAgICAgIkhpZ2giLCAiUDEiLCAiTUFOVUFMIiwgIk5lZWRzIGEga25vd24g"
    "bG9naW4gZW5kcG9pbnQgKyBjcmVkZW50aWFsIGxpc3QgLSB1c2UgaHlkcmEvbWFudWFsIHRlc3RpbmcgYWdhaW5zdCB0aGUg"
    "YWN0dWFsIGxvZ2luIGZvcm0uIikKCiAgICBiYWtfaGl0cyA9IFtdCiAgICBmb3IgcGF0aCBpbiBCQUNLVVBfRVhUX1BST0JF"
    "UzoKICAgICAgICByciA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgpLCAiR0VUIiwgdGltZW91dD1hcmdz"
    "LnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICAgICAgaWYgbm90IHJyLmVycm9yIGFuZCByci5zdGF0dXMg"
    "PT0gMjAwOgogICAgICAgICAgICBiYWtfaGl0cy5hcHBlbmQocGF0aCkKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODUi"
    "LCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlRlc3QgZmlsZSBleHRlbnNpb24gaGFuZGxpbmcgKC5iYWsgLm9sZCAub3Jp"
    "ZyAuc3dwKSIsCiAgICAgICAgIkhpZ2giLCAiUDEiLCAiRkFJTCIgaWYgYmFrX2hpdHMgZWxzZSAiUEFTUyIsCiAgICAgICAg"
    "ZiJBY2Nlc3NpYmxlOiB7JywgJy5qb2luKGJha19oaXRzKX0iIGlmIGJha19oaXRzIGVsc2UgZiJOb25lIG9mIHsnLCAnLmpv"
    "aW4oQkFDS1VQX0VYVF9QUk9CRVMpfSBhY2Nlc3NpYmxlIGF0IHNpdGUgcm9vdC4iKQoKICAgIGJhY2t1cF9oaXRzID0gW10K"
    "ICAgIGZvciBwYXRoIGluIEJBQ0tVUF9GSUxFX1BST0JFUzoKICAgICAgICByciA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0"
    "KGJhc2UsIHBhdGgpLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICAg"
    "ICAgaWYgbm90IHJyLmVycm9yIGFuZCByci5zdGF0dXMgPT0gMjAwOgogICAgICAgICAgICBiYWNrdXBfaGl0cy5hcHBlbmQo"
    "cGF0aCkKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODYiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlJldmlldyBi"
    "YWNrdXAgYW5kIHVucmVmZXJlbmNlZCBmaWxlcyIsCiAgICAgICAgIkhpZ2giLCAiUDEiLCAiRkFJTCIgaWYgYmFja3VwX2hp"
    "dHMgZWxzZSAiUEFTUyIsCiAgICAgICAgZiJBY2Nlc3NpYmxlOiB7JywgJy5qb2luKGJhY2t1cF9oaXRzKX0iIGlmIGJhY2t1"
    "cF9oaXRzIGVsc2UgZiJOb25lIG9mIHsnLCAnLmpvaW4oQkFDS1VQX0ZJTEVfUFJPQkVTKX0gYWNjZXNzaWJsZSBhdCBzaXRl"
    "IHJvb3QuIikKCiAgICBhZG1pbl9oaXRzID0gW10KICAgIGZvciBwYXRoIGluIEFETUlOX1BBVEhfUFJPQkVTOgogICAgICAg"
    "IHJyID0gcmF3X3JlcXVlc3Qoam9pbl90YXJnZXQoYmFzZSwgcGF0aCksICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwg"
    "aW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgICAgICBpZiBub3QgcnIuZXJyb3IgYW5kIHJyLnN0YXR1cyA9PSAyMDA6CiAg"
    "ICAgICAgICAgIGFkbWluX2hpdHMuYXBwZW5kKGYie3BhdGh9ICgyMDAgLSBwdWJsaWNseSByZWFjaGFibGUpIikKICAgICAg"
    "ICBlbGlmIG5vdCByci5lcnJvciBhbmQgcnIuc3RhdHVzIGluICg0MDEsIDQwMyk6CiAgICAgICAgICAgIGFkbWluX2hpdHMu"
    "YXBwZW5kKGYie3BhdGh9ICh7cnIuc3RhdHVzfSAtIGV4aXN0cywgYXBwZWFycyBwcm90ZWN0ZWQpIikKICAgIGFkZChmdWxs"
    "X3VybCwgIldBLU9URy0yODciLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIkVudW1lcmF0ZSBpbmZyYXN0cnVjdHVyZSBh"
    "bmQgYWRtaW4gaW50ZXJmYWNlcyIsCiAgICAgICAgIkNyaXRpY2FsIiwgIlAxIiwgIkZBSUwiIGlmIGFueSgiMjAwIiBpbiBo"
    "IGZvciBoIGluIGFkbWluX2hpdHMpIGVsc2UgKCJJTkZPIiBpZiBhZG1pbl9oaXRzIGVsc2UgIlBBU1MiKSwKICAgICAgICAi"
    "OyAiLmpvaW4oYWRtaW5faGl0cykgaWYgYWRtaW5faGl0cyBlbHNlIGYiTm9uZSBvZiB7JywgJy5qb2luKEFETUlOX1BBVEhf"
    "UFJPQkVTKX0gcmVzcG9uZGVkIGF0IHNpdGUgcm9vdC4iKQoKICAgIHJvcHRzID0gcmF3X3JlcXVlc3QoYmFzZSwgIk9QVElP"
    "TlMiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIGFsbG93ID0gcm9wdHMuaGVh"
    "ZGVyKCJBbGxvdyIpIGlmIG5vdCByb3B0cy5lcnJvciBlbHNlICIiCiAgICByaXNreV9tZXRob2RzID0gW20gZm9yIG0gaW4g"
    "WyJQVVQiLCAiREVMRVRFIiwgIlRSQUNFIiwgIkNPTk5FQ1QiXSBpZiBtIGluIGFsbG93LnVwcGVyKCldCiAgICBhZGQoZnVs"
    "bF91cmwsICJXQS1PVEctMjg4IiwgIkNvbmZpZ3VyYXRpb24gVGVzdGluZyIsICJUZXN0IEhUVFAgbWV0aG9kcyAoUFVUL0RF"
    "TEVURS9PUFRJT05TL1RSQUNFKSIsCiAgICAgICAgIk1lZGl1bSIsICJQMiIsICJGQUlMIiBpZiByaXNreV9tZXRob2RzIGVs"
    "c2UgKCJFUlJPUiIgaWYgcm9wdHMuZXJyb3IgZWxzZSAiUEFTUyIpLAogICAgICAgIChyb3B0cy5lcnJvciBvciBmIk9QVElP"
    "TlMge2Jhc2V9IC0+IEFsbG93OiB7YWxsb3cgb3IgJ25vdCBkaXNjbG9zZWQnfS4iICsKICAgICAgICAgKGYiIFJpc2t5IG1l"
    "dGhvZChzKSBhZHZlcnRpc2VkOiB7JywgJy5qb2luKHJpc2t5X21ldGhvZHMpfSAtIHZlcmlmeSBlYWNoIGlzIGFjdHVhbGx5"
    "IHVzYWJsZS4iIGlmIHJpc2t5X21ldGhvZHMgZWxzZSAiIikpKQoKICAgICMgUmVwb3J0ZWQgZGlyZWN0bHksIHdpdGggYSBz"
    "Y3JlZW5zaG90OiAib3V0cHV0IGlzIG5vdCBhIGNvbW1hbmQgbGluZQogICAgIyBvciByZXF1ZXN0IHJlc3BvbnNlIGJhc2Vz"
    "IGl0IGp1c3QgYSBzdGF0ZW1lbnQgcGxlYXNlIGZpeCIgLSB0aGlzIGFuZAogICAgIyBXQS1PVEctMjk0IGJlbG93IHJlLXJl"
    "YWQgdGhlIFNBTUUgcmVzcG9uc2UgY2hlY2tfc2VjdXJpdHlfaGVhZGVycygpCiAgICAjIGFscmVhZHkgZmV0Y2hlZCAoV0Et"
    "T1RHLTI4OS8yOTQgYXJlIHRoZSBPV0FTUCBUZXN0aW5nIEd1aWRlIElEcyBmb3IKICAgICMgdGhlIGlkZW50aWNhbCBIU1RT"
    "L0NTUCBoZWFkZXIgY2hlY2tzIFdBLUhEUi0zOTUvMzkyIGNvdmVyIHVuZGVyIHRoZQogICAgIyBtYXN0ZXIgY2hlY2tsaXN0"
    "J3Mgb3duIElEIHNjaGVtZSAtIG5vIG5lZWQgdG8gcmUtcmVxdWVzdCB0aGUgcGFnZSksCiAgICAjIGJ1dCB1c2VkIHRvIG9u"
    "bHkgcHJpbnQgYSBiYXJlICIoc2FtZSBjaGVjayBhcyBXQS1IRFItMzk1KSIgc2VudGVuY2UKICAgICMgaW5zdGVhZCBvZiB0"
    "aGUgcmVhbCBjdXJsIGNvbW1hbmQgKyByZXNwb25zZSB0aGF0IGNoZWNrX3NlY3VyaXR5X2hlYWRlcnMoKQogICAgIyBhbHJl"
    "YWR5IGNhcHR1cmVkIGZvciB0aGF0IGV4YWN0IHJlcXVlc3QuIGhkcl9jdXJsX2Jsb2NrICh0aHJlYWRlZCBpbgogICAgIyBm"
    "cm9tIHJ1bl9mdWxsX3N1aXRlLCBzb3VyY2VkIGZyb20gY2hlY2tfc2VjdXJpdHlfaGVhZGVycygpJ3MgcmV0dXJuCiAgICAj"
    "IHZhbHVlKSBpcyB0aGF0IHNhbWUgcmVhbCBldmlkZW5jZSBibG9jaywgcmV1c2VkIGhlcmUgYXQgemVybyBleHRyYQogICAg"
    "IyByZXF1ZXN0IGNvc3QgaW5zdGVhZCBvZiBzaGVsbGluZyBvdXQgdG8gY3VybCBhIHNlY29uZCB0aW1lLgogICAgaHN0c19m"
    "b3JfMjg5ID0gaGVhZGVyc19yZXN1bHQuaGVhZGVyKCJTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5IikgaWYgbm90IGhlYWRl"
    "cnNfcmVzdWx0LmVycm9yIGVsc2UgIiIKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODkiLCAiQ29uZmlndXJhdGlvbiBU"
    "ZXN0aW5nIiwgIlRlc3QgSFRUUCBTdHJpY3QgVHJhbnNwb3J0IFNlY3VyaXR5IChIU1RTIHByZXNlbnQ/KSIsCiAgICAgICAg"
    "Ik1lZGl1bSIsICJQMiIsICJQQVNTIiBpZiBoc3RzX2Zvcl8yODkgZWxzZSAiRkFJTCIsCiAgICAgICAgKGYiU3RyaWN0LVRy"
    "YW5zcG9ydC1TZWN1cml0eToge2hzdHNfZm9yXzI4OX0iIGlmIGhzdHNfZm9yXzI4OSBlbHNlCiAgICAgICAgICJDT05GSVJN"
    "RUQgQlk6IG5vIFN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkgaGVhZGVyIHByZXNlbnQgaW4gdGhlIHJlc3BvbnNlIGhlYWRl"
    "cnMgYmVsb3cuIikgKyBoZHJfY3VybF9ibG9jaykKCiAgICBjZHhtbCA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2Us"
    "ICIvY3Jvc3Nkb21haW4ueG1sIiksICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3Vy"
    "ZSkKICAgIGNhcCA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsICIvY2xpZW50YWNjZXNzcG9saWN5LnhtbCIpLCAi"
    "R0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICBmaW5kaW5ncyA9IFtdCiAg"
    "ICBpZiBub3QgY2R4bWwuZXJyb3IgYW5kIGNkeG1sLnN0YXR1cyA9PSAyMDA6CiAgICAgICAgd2lkZV9vcGVuID0gImRvbWFp"
    "bj1cIipcIiIgaW4gY2R4bWwudGV4dCgpIG9yICJkb21haW49JyonIiBpbiBjZHhtbC50ZXh0KCkKICAgICAgICBmaW5kaW5n"
    "cy5hcHBlbmQoZiJjcm9zc2RvbWFpbi54bWwgcHJlc2VudHsnIHdpdGggd2lsZGNhcmQgZG9tYWluIChGQUlMKScgaWYgd2lk"
    "ZV9vcGVuIGVsc2UgJyd9IikKICAgIGlmIG5vdCBjYXAuZXJyb3IgYW5kIGNhcC5zdGF0dXMgPT0gMjAwOgogICAgICAgIHdp"
    "ZGVfb3BlbjIgPSAiZG9tYWluPVwiKlwiIiBpbiBjYXAudGV4dCgpIG9yICJkb21haW49JyonIiBpbiBjYXAudGV4dCgpCiAg"
    "ICAgICAgZmluZGluZ3MuYXBwZW5kKGYiY2xpZW50YWNjZXNzcG9saWN5LnhtbCBwcmVzZW50eycgd2l0aCB3aWxkY2FyZCBk"
    "b21haW4gKEZBSUwpJyBpZiB3aWRlX29wZW4yIGVsc2UgJyd9IikKICAgIGFueV93aWxkY2FyZCA9IGFueSgid2lsZGNhcmQi"
    "IGluIGYgZm9yIGYgaW4gZmluZGluZ3MpCiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjkwIiwgIkNvbmZpZ3VyYXRpb24g"
    "VGVzdGluZyIsICJUZXN0IFJJQSBjcm9zcyBkb21haW4gcG9saWN5IChjcm9zc2RvbWFpbi54bWwgLyBjbGllbnRhY2Nlc3Nw"
    "b2xpY3kpIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiIGlmIGFueV93aWxkY2FyZCBlbHNlICgiSU5GTyIgaWYg"
    "ZmluZGluZ3MgZWxzZSAiUEFTUyIpLAogICAgICAgICI7ICIuam9pbihmaW5kaW5ncykgaWYgZmluZGluZ3MgZWxzZSAiTmVp"
    "dGhlciBjcm9zc2RvbWFpbi54bWwgbm9yIGNsaWVudGFjY2Vzc3BvbGljeS54bWwgZm91bmQgLSBub3QgYXBwbGljYWJsZS4i"
    "KQoKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yOTEiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlRlc3QgZmlsZSBw"
    "ZXJtaXNzaW9ucyBvbiB3ZWIgc2VydmVyIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIk1BTlVBTCIsCiAgICAgICAgIk5v"
    "dCB0ZXN0YWJsZSByZW1vdGVseSB3aXRoIGNlcnRhaW50eSAtIHNlZSB0aGUgLmdpdC8uc3ZuLy5EU19TdG9yZSBleHBvc3Vy"
    "ZSBjaGVjayAoV0EtU1MtMDU5KSBmb3IgYSByZWxhdGVkICIKICAgICAgICAiYXV0b21hdGVkIHNpZ25hbCwgYnV0IGZ1bGwg"
    "ZmlsZS1wZXJtaXNzaW9uIHJldmlldyBuZWVkcyBzZXJ2ZXIgYWNjZXNzIG9yIGEgZGVkaWNhdGVkIG1pc2NvbmZpZyBzY2Fu"
    "bmVyLiIpCgogICAgY25hbWVfaW5mbyA9IF9yZXNvbHZlX2NuYW1lKGhvc3QpCiAgICBkYW5nbGluZ19oaW50ID0gTm9uZQog"
    "ICAgaWYgY25hbWVfaW5mbyBhbmQgY25hbWVfaW5mb1sxXSBpcyBOb25lOgogICAgICAgIGZvciBzdmMgaW4gWyJnaXRodWIu"
    "aW8iLCAiaGVyb2t1YXBwLmNvbSIsICJzMy5hbWF6b25hd3MuY29tIiwgImF6dXJld2Vic2l0ZXMubmV0IiwgImNsb3VkZnJv"
    "bnQubmV0IiwKICAgICAgICAgICAgICAgICAgICAidHJhZmZpY21hbmFnZXIubmV0IiwgInJlYWR0aGVkb2NzLmlvIiwgInJl"
    "YWRtZS5pbyJdOgogICAgICAgICAgICBpZiBzdmMgaW4gY25hbWVfaW5mb1swXToKICAgICAgICAgICAgICAgIGRhbmdsaW5n"
    "X2hpbnQgPSBzdmMKICAgICAgICAgICAgICAgIGJyZWFrCiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjkyIiwgIkNvbmZp"
    "Z3VyYXRpb24gVGVzdGluZyIsICJUZXN0IHN1YmRvbWFpbiB0YWtlb3ZlciIsCiAgICAgICAgIkhpZ2giLCAiUDEiLAogICAg"
    "ICAgICJGQUlMIiBpZiBkYW5nbGluZ19oaW50IGVsc2UgKCJNQU5VQUwiIGlmIG5vdCBjbmFtZV9pbmZvIGVsc2UgIlBBU1Mi"
    "KSwKICAgICAgICAoZiJDTkFNRSAtPiB7Y25hbWVfaW5mb1swXX0sIHJlc29sdmVzOiB7J25vIChOWERPTUFJTi91bnJlc29s"
    "dmFibGUpJyBpZiBjbmFtZV9pbmZvIGFuZCBjbmFtZV9pbmZvWzFdIGlzIE5vbmUgZWxzZSAneWVzJ30uIgogICAgICAgICAr"
    "IChmIiBQb2ludHMgYXQgYSBrbm93biB0YWtlb3Zlci1wcm9uZSBzZXJ2aWNlICh7ZGFuZ2xpbmdfaGludH0pIGFuZCBkb2Vz"
    "bid0IHJlc29sdmUgLSBpbnZlc3RpZ2F0ZSBtYW51YWxseS4iIGlmIGRhbmdsaW5nX2hpbnQgZWxzZSAiIikpCiAgICAgICAg"
    "aWYgY25hbWVfaW5mbyBlbHNlICJObyBDTkFNRSBmb3VuZCBmb3IgdGhpcyBob3N0IChuc2xvb2t1cCB1bmF2YWlsYWJsZSBv"
    "ciBob3N0IGhhcyBubyBDTkFNRSkgLSBmdWxsIHN1YmRvbWFpbiAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAiZW51"
    "bWVyYXRpb24gYWNyb3NzIHRoZSB3aG9sZSBkb21haW4gc3RpbGwgbmVlZHMgYSBkZWRpY2F0ZWQgdG9vbCAoc3ViZmluZGVy"
    "L2FtYXNzICsgZG5zeCkuIikKCiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjkzIiwgIkNvbmZpZ3VyYXRpb24gVGVzdGlu"
    "ZyIsICJUZXN0IGNsb3VkIHN0b3JhZ2UgcGVybWlzc2lvbnMgKHB1YmxpYyBidWNrZXRzL2Jsb2JzKSIsCiAgICAgICAgIkhp"
    "Z2giLCAiUDEiLCAiTUFOVUFMIiwKICAgICAgICAiU2VlIFdBLU9URy0yODIgZm9yIGJ1Y2tldHMgcmVmZXJlbmNlZCBieSB0"
    "aGlzIHBhZ2UgLSBjaGVjayBlYWNoIHdpdGggYSBIRUFEL0dFVC9saXN0IHJlcXVlc3QgbWFudWFsbHkgb3IgdmlhICIKICAg"
    "ICAgICAiYSBidWNrZXQtcGVybWlzc2lvbiB0b29sIChzM3NjYW5uZXIpLiBDYW4ndCBiZSB0ZXN0ZWQgZ2VuZXJpY2FsbHkg"
    "d2l0aG91dCBhIGJ1Y2tldCBuYW1lLiIpCgogICAgY3NwX2Zvcl8yOTQgPSBoZWFkZXJzX3Jlc3VsdC5oZWFkZXIoIkNvbnRl"
    "bnQtU2VjdXJpdHktUG9saWN5IikgaWYgbm90IGhlYWRlcnNfcmVzdWx0LmVycm9yIGVsc2UgIiIKICAgIGlmIG5vdCBjc3Bf"
    "Zm9yXzI5NDoKICAgICAgICBjc3AyOTRfcmVzdWx0LCBjc3AyOTRfZXZpZGVuY2UgPSAiRkFJTCIsICgKICAgICAgICAgICAg"
    "IkNPTkZJUk1FRCBCWTogbm8gQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgaGVhZGVyIHByZXNlbnQgaW4gdGhlIHJlc3BvbnNl"
    "IGhlYWRlcnMgYmVsb3cuIikKICAgIGVsaWYgInVuc2FmZS1pbmxpbmUiIGluIGNzcF9mb3JfMjk0OgogICAgICAgIGNzcDI5"
    "NF9yZXN1bHQsIGNzcDI5NF9ldmlkZW5jZSA9ICJGQUlMIiwgKAogICAgICAgICAgICBmIkNPTkZJUk1FRCBCWTogQ1NQIGNv"
    "bnRhaW5zICd1bnNhZmUtaW5saW5lJyAtIGZ1bGwgaGVhZGVyIHZhbHVlOiB7Y3NwX2Zvcl8yOTRbOjMwMF19IikKICAgIGVs"
    "c2U6CiAgICAgICAgY3NwMjk0X3Jlc3VsdCwgY3NwMjk0X2V2aWRlbmNlID0gIlBBU1MiLCBmIkNTUDoge2NzcF9mb3JfMjk0"
    "WzozMDBdfSIKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yOTQiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlRlc3Qg"
    "Y29udGVudCBzZWN1cml0eSBwb2xpY3kgKENTUCBoZWFkZXIgYW5hbHlzaXMpIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwg"
    "Y3NwMjk0X3Jlc3VsdCwgY3NwMjk0X2V2aWRlbmNlICsgaGRyX2N1cmxfYmxvY2spCgoKZGVmIF9yZXNvbHZlX2NuYW1lKGhv"
    "c3QpOgogICAgIiIiUmV0dXJucyAoY25hbWVfdGFyZ2V0LCByZXNvbHZlZF9pcF9vcl9Ob25lKSB1c2luZyBuc2xvb2t1cCwg"
    "b3IgTm9uZSBpZiB1bmF2YWlsYWJsZS4iIiIKICAgIHRyeToKICAgICAgICBvdXQgPSBzdWJwcm9jZXNzLnJ1bihbIm5zbG9v"
    "a3VwIiwgIi10eXBlPUNOQU1FIiwgaG9zdF0sIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRpbWVvdXQ9NSwKICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgdGV4dD1UcnVlKS5zdGRvdXQKICAgICAgICBtID0gcmUuc2VhcmNoKHIiY2Fub25pY2FsIG5h"
    "bWUgPSAoXFMrKVwuPyIsIG91dCkKICAgICAgICBpZiBub3QgbToKICAgICAgICAgICAgcmV0dXJuIE5vbmUKICAgICAgICBj"
    "bmFtZSA9IG0uZ3JvdXAoMSkucnN0cmlwKCIuIikKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNvY2tldC5nZXRob3N0Ynlu"
    "YW1lKGNuYW1lKQogICAgICAgICAgICByZXR1cm4gKGNuYW1lLCBUcnVlKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAg"
    "ICAgICAgICAgIHJldHVybiAoY25hbWUsIE5vbmUpCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiBOb25l"
    "CgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLQojIDcuIFNlc3Npb24gTWFuYWdlbWVudCBUZXN0aW5nIC0gV0EtT1RHLTMxNS4uMzIzCiMgLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBjaGVj"
    "a19zZXNzaW9uX21hbmFnZW1lbnQoZnVsbF91cmwsIGhlYWRlcnNfcmVzdWx0LCBhcmdzKToKICAgIGlmIGhlYWRlcnNfcmVz"
    "dWx0LmVycm9yOgogICAgICAgIGZvciBjaWQsIG5hbWUgaW4gWwogICAgICAgICAgICAoIldBLU9URy0zMTUiLCAiVGVzdCBz"
    "ZXNzaW9uIG1hbmFnZW1lbnQgc2NoZW1hICh0b2tlbiBhbmFseXNpcykiKSwKICAgICAgICAgICAgKCJXQS1PVEctMzE2Iiwg"
    "IlRlc3QgY29va2llIGF0dHJpYnV0ZXMgKFNlY3VyZSwgSHR0cE9ubHksIFNhbWVTaXRlLCBQYXRoKSIpLAogICAgICAgICAg"
    "ICAoIldBLU9URy0zMTciLCAiVGVzdCBzZXNzaW9uIGZpeGF0aW9uICh0b2tlbiByZWN5Y2xlZCBhZnRlciBsb2dpbikiKSwK"
    "ICAgICAgICAgICAgKCJXQS1PVEctMzE4IiwgIlRlc3QgZXhwb3NlZCBzZXNzaW9uIHZhcmlhYmxlcyAoaW4gVVJMLCBsb2dz"
    "KSIpLAogICAgICAgICAgICAoIldBLU9URy0zMTkiLCAiVGVzdCBDU1JGIHByb3RlY3Rpb24gKHRva2VuIHZhbGlkYXRpb24s"
    "IFNhbWVTaXRlKSIpLAogICAgICAgICAgICAoIldBLU9URy0zMjAiLCAiVGVzdCBsb2dvdXQgZnVuY3Rpb25hbGl0eSAoc2Vy"
    "dmVyLXNpZGUgc2Vzc2lvbiBpbnZhbGlkYXRpb24pIiksCiAgICAgICAgICAgICgiV0EtT1RHLTMyMSIsICJUZXN0IHNlc3Np"
    "b24gdGltZW91dCAoaWRsZSArIGFic29sdXRlKSIpLAogICAgICAgICAgICAoIldBLU9URy0zMjIiLCAiVGVzdCBzZXNzaW9u"
    "IHB1enpsaW5nIC8gb3ZlcmxvYWRpbmciKSwKICAgICAgICAgICAgKCJXQS1PVEctMzIzIiwgIlRlc3Qgc2Vzc2lvbiBoaWph"
    "Y2tpbmcgKHRva2VuIHRoZWZ0IHZpYSBYU1MvTWl0TSkiKSwKICAgICAgICBdOgogICAgICAgICAgICBhZGQoZnVsbF91cmws"
    "IGNpZCwgIlNlc3Npb24gTWFuYWdlbWVudCBUZXN0aW5nIiwgbmFtZSwgIkhpZ2giLCAiUDEiLCAiRVJST1IiLCBoZWFkZXJz"
    "X3Jlc3VsdC5lcnJvcikKICAgICAgICByZXR1cm4KCiAgICAjIFJlYWwgIiQgY3VybCAuLi4iIGNvbW1hbmQgKyB0aGUgYWN0"
    "dWFsIFNldC1Db29raWUgaGVhZGVyKHMpIGl0IGdvdAogICAgIyBiYWNrLCBhdHRhY2hlZCBhcyBldmlkZW5jZSBmb3IgdGhl"
    "IHR3byBjaGVja3MgYmVsb3cgdGhhdCBhcmUKICAgICMgREVSSVZFRCBmcm9tIHRob3NlIGhlYWRlcnMgKFdBLU9URy0zMTUv"
    "MzE2KSAtIGZpeGVkIGFmdGVyIGJlaW5nCiAgICAjIHJlcG9ydGVkIGRpcmVjdGx5LCB3aXRoIGEgc2NyZWVuc2hvdCBzaG93"
    "aW5nIGEgVnVsbmVyYWJsZSBjb29raWUtCiAgICAjIGF0dHJpYnV0ZXMgZmluZGluZyB3aXRoIG5vIG91dHB1dCBjYXB0dXJl"
    "ZDogIm4gbyBvdXQgcHV0IGNhcHR1cmVkCiAgICAjIHlvdSBjYW4gdXNlIGN1cmwgaGVkZXJzIGNvbW1hbmQgdG8gY29sbGVj"
    "dCB0aGUgY29va2llcyBvdXR1dCIuCiAgICAjIFByZXZpb3VzbHkgdGhpcyBmdW5jdGlvbiBvbmx5IGV2ZXIgcmV1c2VkIGBo"
    "ZWFkZXJzX3Jlc3VsdGAgKHRoZQogICAgIyBQeXRob24taW50ZXJuYWwgSHR0cFJlc3VsdCBvYmplY3QgZnJvbSBjaGVja19z"
    "ZWN1cml0eV9oZWFkZXJzKCkpIHRvCiAgICAjIERFQ0lERSB0aGUgUEFTUy9GQUlMIHZlcmRpY3QsIGJ1dCBuZXZlciByYW4v"
    "YXR0YWNoZWQgdGhlIGFjdHVhbCBjdXJsCiAgICAjIGNvbW1hbmQrb3V0cHV0IHRoZSBvdGhlciBIVFRQLWhlYWRlciBjaGVj"
    "a3MgKFdBLUhEUi0zOTIgZXRjLikgc2hvdwogICAgIyBhcyBldmlkZW5jZSAtIHNvIGEgY29va2llLWF0dHJpYnV0ZXMgRkFJ"
    "TCBoYWQgbm8gcmVwcm9kdWNpYmxlCiAgICAjIGNvbW1hbmQgYSByZXZpZXdlciBjb3VsZCByZS1ydW4gdG8gc2VlIHRoZSBy"
    "ZWFsIFNldC1Db29raWUgdmFsdWUocykKICAgICMgdGhlbXNlbHZlcywganVzdCB0aGUgZGVyaXZlZCAiWCBtaXNzaW5nIFNl"
    "Y3VyZS9IdHRwT25seSIgc2VudGVuY2UuCiAgICBjdXJsX3Jlc3VsdCA9IE5vbmUgaWYgZ2V0YXR0cihhcmdzLCAibm9fY2xp"
    "X3Rvb2xzIiwgRmFsc2UpIGVsc2UgcnVuX2N1cmxfaGVhZGVycygKICAgICAgICBmdWxsX3VybCwgdGltZW91dD1hcmdzLnRp"
    "bWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICBjdXJsX2Jsb2NrID0gX2Zvcm1hdF9jbWRfYmxvY2soY3VybF9y"
    "ZXN1bHRbMF0sIGN1cmxfcmVzdWx0WzFdKSBpZiBjdXJsX3Jlc3VsdCBlbHNlICIiCgogICAgc2V0X2Nvb2tpZXMgPSBbdiBm"
    "b3IgaywgdiBpbiBoZWFkZXJzX3Jlc3VsdC5oZWFkZXJzLml0ZW1zKCkgaWYgay5sb3dlcigpID09ICJzZXQtY29va2llIl0K"
    "ICAgIGNvb2tpZV9uYW1lcyA9IFtyZS5tYXRjaChyIihbXj1dKyk9IiwgYykuZ3JvdXAoMSkgZm9yIGMgaW4gc2V0X2Nvb2tp"
    "ZXMgaWYgcmUubWF0Y2gociIoW149XSspPSIsIGMpXQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxNSIsICJTZXNzaW9u"
    "IE1hbmFnZW1lbnQgVGVzdGluZyIsICJUZXN0IHNlc3Npb24gbWFuYWdlbWVudCBzY2hlbWEgKHRva2VuIGFuYWx5c2lzKSIs"
    "CiAgICAgICAgIkhpZ2giLCAiUDEiLCAiSU5GTyIgaWYgY29va2llX25hbWVzIGVsc2UgIk1BTlVBTCIsCiAgICAgICAgKGYi"
    "Q29va2llKHMpIHNlZW4gb24gdGhpcyByZXNwb25zZTogeycsICcuam9pbihjb29raWVfbmFtZXMpfS4gRnVsbCBlbnRyb3B5"
    "L3ByZWRpY3RhYmlsaXR5IGFuYWx5c2lzIG5lZWRzICIKICAgICAgICAgIm11bHRpcGxlIHNhbXBsZXMgYWNyb3NzIHNlc3Np"
    "b25zIC0gb3V0IG9mIHNjb3BlIGZvciBhIHNpbmdsZSByZXF1ZXN0LiIgaWYgY29va2llX25hbWVzIGVsc2UKICAgICAgICAg"
    "Ik5vIFNldC1Db29raWUgb24gdGhpcyByZXNwb25zZSAtIHNlc3Npb24gbWF5IGJlIGlzc3VlZCBhZnRlciBsb2dpbjsgcmUt"
    "cnVuIHRoaXMgY2hlY2sgb24gYW4gYXV0aGVudGljYXRlZCBwYWdlLiIpCiAgICAgICAgKyBjdXJsX2Jsb2NrKQoKICAgIGlm"
    "IHNldF9jb29raWVzOgogICAgICAgIGlzc3VlcyA9IFtdCiAgICAgICAgaXNfaHR0cHMgPSBmdWxsX3VybC5zdGFydHN3aXRo"
    "KCJodHRwcyIpCiAgICAgICAgZm9yIGMgaW4gc2V0X2Nvb2tpZXM6CiAgICAgICAgICAgIG5hbWUgPSByZS5tYXRjaChyIihb"
    "Xj1dKyk9IiwgYykuZ3JvdXAoMSkKICAgICAgICAgICAgbWlzc2luZyA9IFtdCiAgICAgICAgICAgIGlmIGlzX2h0dHBzIGFu"
    "ZCAic2VjdXJlIiBub3QgaW4gYy5sb3dlcigpOgogICAgICAgICAgICAgICAgbWlzc2luZy5hcHBlbmQoIlNlY3VyZSIpCiAg"
    "ICAgICAgICAgIGlmICJodHRwb25seSIgbm90IGluIGMubG93ZXIoKToKICAgICAgICAgICAgICAgIG1pc3NpbmcuYXBwZW5k"
    "KCJIdHRwT25seSIpCiAgICAgICAgICAgIGlmICJzYW1lc2l0ZSIgbm90IGluIGMubG93ZXIoKToKICAgICAgICAgICAgICAg"
    "IG1pc3NpbmcuYXBwZW5kKCJTYW1lU2l0ZSIpCiAgICAgICAgICAgIGlmIG1pc3Npbmc6CiAgICAgICAgICAgICAgICBpc3N1"
    "ZXMuYXBwZW5kKGYie25hbWV9IG1pc3NpbmcgeycvJy5qb2luKG1pc3NpbmcpfSIpCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAi"
    "V0EtT1RHLTMxNiIsICJTZXNzaW9uIE1hbmFnZW1lbnQgVGVzdGluZyIsICJUZXN0IGNvb2tpZSBhdHRyaWJ1dGVzIChTZWN1"
    "cmUsIEh0dHBPbmx5LCBTYW1lU2l0ZSwgUGF0aCkiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiIGlmIGlz"
    "c3VlcyBlbHNlICJQQVNTIiwKICAgICAgICAgICAgKCI7ICIuam9pbihpc3N1ZXMpIGlmIGlzc3VlcyBlbHNlIGYiQWxsIGNv"
    "b2tpZShzKSAoeycsICcuam9pbihjb29raWVfbmFtZXMpfSkgaGF2ZSBTZWN1cmUvSHR0cE9ubHkvU2FtZVNpdGUgc2V0IGFw"
    "cHJvcHJpYXRlbHkuIikKICAgICAgICAgICAgKyBjdXJsX2Jsb2NrKQogICAgZWxzZToKICAgICAgICBhZGQoZnVsbF91cmws"
    "ICJXQS1PVEctMzE2IiwgIlNlc3Npb24gTWFuYWdlbWVudCBUZXN0aW5nIiwgIlRlc3QgY29va2llIGF0dHJpYnV0ZXMgKFNl"
    "Y3VyZSwgSHR0cE9ubHksIFNhbWVTaXRlLCBQYXRoKSIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiSU5GTyIsICJO"
    "byBjb29raWVzIHNldCBvbiB0aGlzIHJlc3BvbnNlIHRvIGV2YWx1YXRlLiIgKyBjdXJsX2Jsb2NrKQoKICAgIGFkZChmdWxs"
    "X3VybCwgIldBLU9URy0zMTciLCAiU2Vzc2lvbiBNYW5hZ2VtZW50IFRlc3RpbmciLCAiVGVzdCBzZXNzaW9uIGZpeGF0aW9u"
    "ICh0b2tlbiByZWN5Y2xlZCBhZnRlciBsb2dpbikiLAogICAgICAgICJIaWdoIiwgIlAxIiwgIk1BTlVBTCIsICJOZWVkcyBh"
    "biBhdXRoZW50aWNhdGVkIGxvZ2luIGZsb3cgKGNhcHR1cmUgcHJlLWxvZ2luIHZzIHBvc3QtbG9naW4gc2Vzc2lvbiB0b2tl"
    "bikgLSBub3QgdGVzdGFibGUgZnJvbSBhIHNpbmdsZSB1bmF1dGhlbnRpY2F0ZWQgcmVxdWVzdC4iKQoKICAgIHBhcnNlZCA9"
    "IHVybHBhcnNlKGZ1bGxfdXJsKQogICAgc2Vzc2lvbl9pbl91cmwgPSBib29sKHJlLnNlYXJjaChyIihzaWR8c2Vzc2lvbnx0"
    "b2tlbnxwaHBzZXNzaWR8anNlc3Npb25pZCk9IiwgcGFyc2VkLnF1ZXJ5LCByZS5JKSkKICAgIGFkZChmdWxsX3VybCwgIldB"
    "LU9URy0zMTgiLCAiU2Vzc2lvbiBNYW5hZ2VtZW50IFRlc3RpbmciLCAiVGVzdCBleHBvc2VkIHNlc3Npb24gdmFyaWFibGVz"
    "IChpbiBVUkwsIGxvZ3MpIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiIGlmIHNlc3Npb25faW5fdXJsIGVsc2Ug"
    "IlBBU1MiLAogICAgICAgIGYiUXVlcnkgc3RyaW5nOiB7cGFyc2VkLnF1ZXJ5IG9yICcobm9uZSknfS4iICsKICAgICAgICAo"
    "IiBTZXNzaW9uLWxpa2UgcGFyYW1ldGVyIG5hbWUgZm91bmQgaW4gdGhlIFVSTCAtIHNlc3Npb24gdG9rZW5zIGluIFVSTHMg"
    "bGVhayB2aWEgbG9ncy9yZWZlcnJlci9oaXN0b3J5LiIgaWYgc2Vzc2lvbl9pbl91cmwgZWxzZSAiIikpCgogICAgYm9keV90"
    "ZXh0ID0gaGVhZGVyc19yZXN1bHQudGV4dCgpCiAgICBmb3JtcyA9IHJlLmZpbmRhbGwociI8Zm9ybVxiW14+XSo+KC4qPyk8"
    "L2Zvcm0+IiwgYm9keV90ZXh0LCByZS5JIHwgcmUuUykKICAgIGlmIGZvcm1zOgogICAgICAgIHRva2VuX3BhdHRlcm4gPSBy"
    "ZS5jb21waWxlKHInbmFtZT1bIlwnXVteIlwnXSooY3NyZnx0b2tlbnxhdXRoZW50aWNpdHkpW14iXCddKlsiXCddJywgcmUu"
    "SSkKICAgICAgICBmb3Jtc19taXNzaW5nX3Rva2VuID0gc3VtKDEgZm9yIGYgaW4gZm9ybXMgaWYgbm90IHRva2VuX3BhdHRl"
    "cm4uc2VhcmNoKGYpKQogICAgICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0zMTkiLCAiU2Vzc2lvbiBNYW5hZ2VtZW50IFRl"
    "c3RpbmciLCAiVGVzdCBDU1JGIHByb3RlY3Rpb24gKHRva2VuIHZhbGlkYXRpb24sIFNhbWVTaXRlKSIsCiAgICAgICAgICAg"
    "ICJIaWdoIiwgIlAxIiwgIkZBSUwiIGlmIGZvcm1zX21pc3NpbmdfdG9rZW4gZWxzZSAiUEFTUyIsCiAgICAgICAgICAgIGYi"
    "e2xlbihmb3Jtcyl9IDxmb3JtPiB0YWcocykgZm91bmQgb24gdGhpcyBwYWdlLCB7Zm9ybXNfbWlzc2luZ190b2tlbn0gd2l0"
    "aCBubyBvYnZpb3VzIENTUkYvdG9rZW4gaGlkZGVuICIKICAgICAgICAgICAgImZpZWxkIGJ5IG5hbWUuIFRoaXMgaXMgYSBu"
    "YW1pbmcgaGV1cmlzdGljIG9ubHkgLSBhIGZvcm0gY2FuIHN0aWxsIGJlIHByb3RlY3RlZCB2aWEgU2FtZVNpdGUgY29va2ll"
    "cyBvciBhICIKICAgICAgICAgICAgImN1c3RvbSBoZWFkZXIgY2hlY2tlZCBzZXJ2ZXItc2lkZTsgdmVyaWZ5IG1hbnVhbGx5"
    "IGJlZm9yZSByZXBvcnRpbmcuIikKICAgIGVsc2U6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxOSIsICJTZXNz"
    "aW9uIE1hbmFnZW1lbnQgVGVzdGluZyIsICJUZXN0IENTUkYgcHJvdGVjdGlvbiAodG9rZW4gdmFsaWRhdGlvbiwgU2FtZVNp"
    "dGUpIiwKICAgICAgICAgICAgIkhpZ2giLCAiUDEiLCAiSU5GTyIsICJObyA8Zm9ybT4gdGFncyBmb3VuZCBvbiB0aGlzIHBh"
    "Z2UgdG8gaW5zcGVjdC4iKQoKICAgIGZvciBjaWQsIG5hbWUgaW4gWwogICAgICAgICgiV0EtT1RHLTMyMCIsICJUZXN0IGxv"
    "Z291dCBmdW5jdGlvbmFsaXR5IChzZXJ2ZXItc2lkZSBzZXNzaW9uIGludmFsaWRhdGlvbikiKSwKICAgICAgICAoIldBLU9U"
    "Ry0zMjEiLCAiVGVzdCBzZXNzaW9uIHRpbWVvdXQgKGlkbGUgKyBhYnNvbHV0ZSkiKSwKICAgICAgICAoIldBLU9URy0zMjIi"
    "LCAiVGVzdCBzZXNzaW9uIHB1enpsaW5nIC8gb3ZlcmxvYWRpbmciKSwKICAgICAgICAoIldBLU9URy0zMjMiLCAiVGVzdCBz"
    "ZXNzaW9uIGhpamFja2luZyAodG9rZW4gdGhlZnQgdmlhIFhTUy9NaXRNKSIpLAogICAgXToKICAgICAgICBhZGQoZnVsbF91"
    "cmwsIGNpZCwgIlNlc3Npb24gTWFuYWdlbWVudCBUZXN0aW5nIiwgbmFtZSwgIkhpZ2giLCAiUDEiLCAiTUFOVUFMIiwKICAg"
    "ICAgICAgICAgIk5lZWRzIGFuIGF1dGhlbnRpY2F0ZWQgc2Vzc2lvbiBhbmQgYSBtdWx0aS1zdGVwIGludGVyYWN0aW9uIG92"
    "ZXIgdGltZSAtIG5vdCB0ZXN0YWJsZSBmcm9tIGEgc2luZ2xlIHVuYXV0aGVudGljYXRlZCByZXF1ZXN0LiIpCgoKIyAtLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoj"
    "IDdiLiBDbGllbnQtU2lkZSBUZXN0aW5nIC0gV0EtT1RHLTM2NiAoc3RhdGljIGFuYWx5c2lzIG9ubHkgLSBubyBicm93c2Vy"
    "IEpTCiMgICAgIGV4ZWN1dGlvbiwgc28gdGhpcyBpcyBhdXRvbWF0YWJsZSB3aXRob3V0IGV2ZXIgbmVlZGluZyBhIGxvZ2lu"
    "OiAibmV2ZXIKIyAgICAgdGFrZSB0aGUgY3JlZGV0aWxzIGFsc28gdG8gbmF2aWdhdGUgaW5zaWRlIikKIyAtLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKX1NFTlNJ"
    "VElWRV9LRVlfUEFUVEVSTiA9IHJlLmNvbXBpbGUoCiAgICByIih0b2tlbnxqd3R8YXV0aHxzZXNzaW9ufHBhc3N3b3JkfHBh"
    "c3N3ZHxzZWNyZXR8YXBpa2V5fGFwaV9rZXl8c3NufGNyZWRpdGNhcmR8Y2FyZF8/bnVtYmVyfFxicGluXGIpIiwKICAgIHJl"
    "LklHTk9SRUNBU0UpCl9TVE9SQUdFX0NBTExfUEFUVEVSTiA9IHJlLmNvbXBpbGUoCiAgICByIlxiKD86bG9jYWxTdG9yYWdl"
    "fHNlc3Npb25TdG9yYWdlKVxzKlwuXHMqc2V0SXRlbVxzKlwoXHMqKFsnXCJdKSguKj8pXDEiLCByZS5JR05PUkVDQVNFKQpf"
    "U1RPUkFHRV9VU0FHRV9QQVRURVJOID0gcmUuY29tcGlsZShyIlxiKD86bG9jYWxTdG9yYWdlfHNlc3Npb25TdG9yYWdlKVxi"
    "IiwgcmUuSUdOT1JFQ0FTRSkKCgpkZWYgY2hlY2tfY2xpZW50X3N0b3JhZ2UoZnVsbF91cmwsIGhlYWRlcnNfcmVzdWx0LCBh"
    "cmdzKToKICAgICIiIldBLU9URy0zNjYgLSBUZXN0IGxvY2FsIHN0b3JhZ2UgLyBzZXNzaW9uU3RvcmFnZSBmb3Igc2Vuc2l0"
    "aXZlIGRhdGEuCiAgICBTY2FucyB0aGUgcGFnZSdzIGlubGluZSA8c2NyaXB0PiBibG9ja3MgYW5kIHNhbWUtb3JpZ2luIGV4"
    "dGVybmFsIEpTIGl0CiAgICBsaW5rcyB0byBmb3IgbG9jYWxTdG9yYWdlL3Nlc3Npb25TdG9yYWdlLnNldEl0ZW0oKSBjYWxs"
    "cywgZmxhZ2dpbmcKICAgIHNlbnNpdGl2ZS1sb29raW5nIGtleSBuYW1lcyAodG9rZW4vc2Vzc2lvbi9hdXRoL3Bhc3N3b3Jk"
    "Ly4uLikuIENhbid0CiAgICBzZWUgc3RvcmFnZSB3cml0dGVuIG9ubHkgYWZ0ZXIgbG9naW4gb3IgYnkgb2JmdXNjYXRlZC9i"
    "dW5kbGVkIGNvZGUgLQogICAgdGhvc2UgY2FzZXMgZmFsbCBiYWNrIHRvIE1BTlVBTC9JTkZPIHJhdGhlciB0aGFuIGEgZmFs"
    "c2UgUEFTUy4iIiIKICAgIGlmIGhlYWRlcnNfcmVzdWx0LmVycm9yOgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0z"
    "NjYiLCAiQ2xpZW50LVNpZGUgVGVzdGluZyIsICJUZXN0IGxvY2FsIHN0b3JhZ2UgLyBzZXNzaW9uU3RvcmFnZSBmb3Igc2Vu"
    "c2l0aXZlIGRhdGEiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkVSUk9SIiwgaGVhZGVyc19yZXN1bHQuZXJyb3Ip"
    "CiAgICAgICAgcmV0dXJuCgogICAgYm9keV90ZXh0ID0gaGVhZGVyc19yZXN1bHQudGV4dCgpCiAgICBjb21iaW5lZF90ZXh0"
    "ID0gYm9keV90ZXh0CiAgICBjb21iaW5lZF9zb3VyY2VzID0gWyJwYWdlIEhUTUwvaW5saW5lIHNjcmlwdHMiXQoKICAgIHNj"
    "cmlwdF9zcmNzID0gcmUuZmluZGFsbChyJzxzY3JpcHRbXj5dK3NyYz1bIlwnXShbXiJcJ10rKVsiXCddJywgYm9keV90ZXh0"
    "LCByZS5JR05PUkVDQVNFKQogICAgcGFnZV9ob3N0ID0gdXJscGFyc2UoZnVsbF91cmwpLmhvc3RuYW1lCiAgICBmZXRjaGVk"
    "ID0gMAogICAgZm9yIHNyYyBpbiBzY3JpcHRfc3JjczoKICAgICAgICBpZiBmZXRjaGVkID49IDU6CiAgICAgICAgICAgIGJy"
    "ZWFrCiAgICAgICAganNfdXJsID0gdXJsam9pbihmdWxsX3VybCwgc3JjKQogICAgICAgIGlmIHVybHBhcnNlKGpzX3VybCku"
    "aG9zdG5hbWUgIT0gcGFnZV9ob3N0OgogICAgICAgICAgICBjb250aW51ZSAgIyBzYW1lLW9yaWdpbiBvbmx5IC0gbm8gcmVh"
    "c29uIHRvIHB1bGwgdGhpcmQtcGFydHkvQ0ROIEpTIGZvciB0aGlzIGhldXJpc3RpYwogICAgICAgIHJfanMgPSByYXdfcmVx"
    "dWVzdChqc191cmwsICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgICAg"
    "ICBmZXRjaGVkICs9IDEKICAgICAgICBpZiBub3Qgcl9qcy5lcnJvciBhbmQgcl9qcy5zdGF0dXMgYW5kIHJfanMuc3RhdHVz"
    "IDwgNDAwOgogICAgICAgICAgICBjb21iaW5lZF90ZXh0ICs9ICJcbiIgKyByX2pzLnRleHQoKQogICAgICAgICAgICBjb21i"
    "aW5lZF9zb3VyY2VzLmFwcGVuZChqc191cmwpCgogICAgbWF0Y2hlcyA9IF9TVE9SQUdFX0NBTExfUEFUVEVSTi5maW5kYWxs"
    "KGNvbWJpbmVkX3RleHQpCiAgICBrZXlzX2ZvdW5kID0gW21bMV0gZm9yIG0gaW4gbWF0Y2hlc10KICAgIHNlbnNpdGl2ZV9r"
    "ZXlzID0gc29ydGVkKHNldChrIGZvciBrIGluIGtleXNfZm91bmQgaWYgX1NFTlNJVElWRV9LRVlfUEFUVEVSTi5zZWFyY2go"
    "aykpKQogICAgYW55X3VzYWdlID0gYm9vbChfU1RPUkFHRV9VU0FHRV9QQVRURVJOLnNlYXJjaChjb21iaW5lZF90ZXh0KSkK"
    "ICAgIHNvdXJjZXNfc3RyID0gIiwgIi5qb2luKGNvbWJpbmVkX3NvdXJjZXMpCgogICAgaWYgc2Vuc2l0aXZlX2tleXM6CiAg"
    "ICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTM2NiIsICJDbGllbnQtU2lkZSBUZXN0aW5nIiwgIlRlc3QgbG9jYWwgc3Rv"
    "cmFnZSAvIHNlc3Npb25TdG9yYWdlIGZvciBzZW5zaXRpdmUgZGF0YSIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAi"
    "RkFJTCIsCiAgICAgICAgICAgIGYibG9jYWxTdG9yYWdlL3Nlc3Npb25TdG9yYWdlLnNldEl0ZW0oKSBjYWxsKHMpIHdpdGgg"
    "c2Vuc2l0aXZlLWxvb2tpbmcga2V5IG5hbWUocykgZm91bmQ6ICIKICAgICAgICAgICAgZiJ7JywgJy5qb2luKHNlbnNpdGl2"
    "ZV9rZXlzKX0uIFNjYW5uZWQ6IHtzb3VyY2VzX3N0cn0uIENvbmZpcm0gaW4gYnJvd3NlciBEZXZUb29scyA+IEFwcGxpY2F0"
    "aW9uID4gIgogICAgICAgICAgICAiU3RvcmFnZSB0aGF0IHRoZSBWQUxVRSAobm90IGp1c3QgdGhlIGtleSBuYW1lKSBhY3R1"
    "YWxseSBob2xkcyBzZW5zaXRpdmUgZGF0YSBiZWZvcmUgcmVwb3J0aW5nLiIpCiAgICBlbGlmIGtleXNfZm91bmQ6CiAgICAg"
    "ICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTM2NiIsICJDbGllbnQtU2lkZSBUZXN0aW5nIiwgIlRlc3QgbG9jYWwgc3RvcmFn"
    "ZSAvIHNlc3Npb25TdG9yYWdlIGZvciBzZW5zaXRpdmUgZGF0YSIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiSU5G"
    "TyIsCiAgICAgICAgICAgIGYibG9jYWxTdG9yYWdlL3Nlc3Npb25TdG9yYWdlLnNldEl0ZW0oKSBjYWxsKHMpIGZvdW5kIGJ1"
    "dCBrZXkgbmFtZShzKSBkb24ndCBtYXRjaCBjb21tb24gc2Vuc2l0aXZlICIKICAgICAgICAgICAgZiJwYXR0ZXJuczogeycs"
    "ICcuam9pbihzb3J0ZWQoc2V0KGtleXNfZm91bmQpKVs6MTVdKX0uIFNjYW5uZWQ6IHtzb3VyY2VzX3N0cn0uIFN0YXRpYyBr"
    "ZXktbmFtZSAiCiAgICAgICAgICAgICJtYXRjaGluZyBvbmx5IC0gdmVyaWZ5IGFjdHVhbCBzdG9yZWQgdmFsdWVzIG1hbnVh"
    "bGx5LiIpCiAgICBlbGlmIGFueV91c2FnZToKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMzY2IiwgIkNsaWVudC1T"
    "aWRlIFRlc3RpbmciLCAiVGVzdCBsb2NhbCBzdG9yYWdlIC8gc2Vzc2lvblN0b3JhZ2UgZm9yIHNlbnNpdGl2ZSBkYXRhIiwK"
    "ICAgICAgICAgICAgIk1lZGl1bSIsICJQMiIsICJNQU5VQUwiLAogICAgICAgICAgICBmImxvY2FsU3RvcmFnZS9zZXNzaW9u"
    "U3RvcmFnZSBBUEkgaXMgcmVmZXJlbmNlZCBpbiBzY2FubmVkIHNvdXJjZSAoe3NvdXJjZXNfc3RyfSkgYnV0IHdpdGggYSBk"
    "eW5hbWljLyIKICAgICAgICAgICAgIm5vbi1saXRlcmFsIGtleSBuYW1lIHRoaXMgc3RhdGljIHNjYW4gY2FuJ3QgcmVhZCAt"
    "IGluc3BlY3QgdmlhIGJyb3dzZXIgRGV2VG9vbHMgPiBBcHBsaWNhdGlvbiA+ICIKICAgICAgICAgICAgIlN0b3JhZ2Ugd2hp"
    "bGUgdXNpbmcgdGhlIGFwcCB0byBzZWUgd2hhdCdzIGFjdHVhbGx5IHN0b3JlZC4iKQogICAgZWxzZToKICAgICAgICBhZGQo"
    "ZnVsbF91cmwsICJXQS1PVEctMzY2IiwgIkNsaWVudC1TaWRlIFRlc3RpbmciLCAiVGVzdCBsb2NhbCBzdG9yYWdlIC8gc2Vz"
    "c2lvblN0b3JhZ2UgZm9yIHNlbnNpdGl2ZSBkYXRhIiwKICAgICAgICAgICAgIk1lZGl1bSIsICJQMiIsICJJTkZPIiwKICAg"
    "ICAgICAgICAgZiJObyBsb2NhbFN0b3JhZ2Uvc2Vzc2lvblN0b3JhZ2UgdXNhZ2UgZm91bmQgaW4gdGhpcyBzaW5nbGUgdW5h"
    "dXRoZW50aWNhdGVkIHBhZ2UncyBzdGF0aWMgSFRNTC9pbmxpbmUgIgogICAgICAgICAgICBmInNjcmlwdHN7Zicgb3Ige2Zl"
    "dGNoZWR9IHNhbWUtb3JpZ2luIGV4dGVybmFsIEpTIGZpbGUocyknIGlmIGZldGNoZWQgZWxzZSAnJ30uIFN0YXRpYyBhbmFs"
    "eXNpcyBvZiBvbmUgIgogICAgICAgICAgICAidW5hdXRoZW50aWNhdGVkIHBhZ2Ugb25seSAtIHVzYWdlIGFkZGVkIGFmdGVy"
    "IGxvZ2luLCBpbiBidW5kbGVkL21pbmlmaWVkL29iZnVzY2F0ZWQgSlMsIG9yIG9uIG90aGVyICIKICAgICAgICAgICAgInBh"
    "Z2VzIGNhbid0IGJlIHJ1bGVkIG91dCB0aGlzIHdheS4gVmVyaWZ5IHZpYSBicm93c2VyIERldlRvb2xzIGR1cmluZyBtYW51"
    "YWwgdGVzdGluZyBmb3IgZnVsbCBjb3ZlcmFnZS4iKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KIyA4LiBFbWFpbCBTZWN1cml0eSAtIFdBLU1BSUwtNDEw"
    "Li40MTMKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLQoKZGVmIF9uc2xvb2t1cF90eHQobmFtZSk6CiAgICB0cnk6CiAgICAgICAgb3V0ID0gc3VicHJvY2Vzcy5y"
    "dW4oWyJuc2xvb2t1cCIsICItdHlwZT1UWFQiLCBuYW1lXSwgY2FwdHVyZV9vdXRwdXQ9VHJ1ZSwgdGltZW91dD02LCB0ZXh0"
    "PVRydWUpLnN0ZG91dAogICAgICAgIHJldHVybiByZS5maW5kYWxsKHInIihbXiJdKikiJywgb3V0KQogICAgZXhjZXB0IEV4"
    "Y2VwdGlvbjoKICAgICAgICByZXR1cm4gTm9uZQoKCmRlZiBjaGVja19lbWFpbF9zZWN1cml0eShmdWxsX3VybCwgYXJncyk6"
    "CiAgICBob3N0ID0gdXJscGFyc2UoZnVsbF91cmwpLmhvc3RuYW1lCiAgICBpZiBub3QgaG9zdDoKICAgICAgICByZXR1cm4K"
    "ICAgIHR4dHMgPSBfbnNsb29rdXBfdHh0KGhvc3QpCiAgICBpZiB0eHRzIGlzIE5vbmU6CiAgICAgICAgZm9yIGNpZCwgbmFt"
    "ZSBpbiBbKCJXQS1NQUlMLTQxMCIsICJTUEYgcmVjb3JkIHByZXNlbnQgYW5kIHVzZXMgaGFyZCBmYWlsICgtYWxsKSIpLAog"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAoIldBLU1BSUwtNDExIiwgIkRNQVJDIHBvbGljeSBjb25maWd1cmVkIChyZWpl"
    "Y3Qgb3IgcXVhcmFudGluZSkiKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKCJXQS1NQUlMLTQxMiIsICJES0lNIHNp"
    "Z25pbmcgY29uZmlndXJlZCBhbmQgdmFsaWQiKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKCJXQS1NQUlMLTQxMyIs"
    "ICJFbWFpbCBzcG9vZmluZyBwb3NzaWJsZSBpZiBTUEYvRE1BUkMgYWJzZW50IG9yIHdlYWsiKV06CiAgICAgICAgICAgIGFk"
    "ZChmdWxsX3VybCwgY2lkLCAiRW1haWwgU2VjdXJpdHkiLCBuYW1lLCAiTWVkaXVtIiwgIlAyIiwgIklORk8iLAogICAgICAg"
    "ICAgICAgICAgIiduc2xvb2t1cCcgbm90IGF2YWlsYWJsZSBvbiB0aGlzIG1hY2hpbmUgLSBjYW4ndCBxdWVyeSBETlMgVFhU"
    "IHJlY29yZHMuIFJ1biBtYW51YWxseTogIgogICAgICAgICAgICAgICAgZiJuc2xvb2t1cCAtdHlwZT1UWFQge2hvc3R9ICBh"
    "bmQgIG5zbG9va3VwIC10eXBlPVRYVCBfZG1hcmMue2hvc3R9IikKICAgICAgICByZXR1cm4KCiAgICBzcGYgPSBuZXh0KCh0"
    "IGZvciB0IGluIHR4dHMgaWYgdC5sb3dlcigpLnN0YXJ0c3dpdGgoInY9c3BmMSIpKSwgTm9uZSkKICAgIHNwZl9oYXJkX2Zh"
    "aWwgPSBib29sKHNwZiBhbmQgIi1hbGwiIGluIHNwZikKICAgIGFkZChmdWxsX3VybCwgIldBLU1BSUwtNDEwIiwgIkVtYWls"
    "IFNlY3VyaXR5IiwgIlNQRiByZWNvcmQgcHJlc2VudCBhbmQgdXNlcyBoYXJkIGZhaWwgKC1hbGwpIiwKICAgICAgICAiTWVk"
    "aXVtIiwgIlAyIiwgIlBBU1MiIGlmIHNwZl9oYXJkX2ZhaWwgZWxzZSAoIkZBSUwiIGlmIHNwZiBlbHNlICJGQUlMIiksCiAg"
    "ICAgICAgZiJTUEY6IHtzcGYgb3IgJ25vIHY9c3BmMSBUWFQgcmVjb3JkIGZvdW5kJ30uIiArCiAgICAgICAgKCIiIGlmIHNw"
    "Zl9oYXJkX2ZhaWwgZWxzZSAoIiBVc2VzIHNvZnQtZmFpbC9uZXV0cmFsL3Bhc3MgaW5zdGVhZCBvZiAtYWxsLiIgaWYgc3Bm"
    "IGVsc2UgIiBObyBTUEYgcmVjb3JkIGF0IGFsbC4iKSkpCgogICAgZG1hcmNfdHh0cyA9IF9uc2xvb2t1cF90eHQoZiJfZG1h"
    "cmMue2hvc3R9Iikgb3IgW10KICAgIGRtYXJjID0gbmV4dCgodCBmb3IgdCBpbiBkbWFyY190eHRzIGlmIHQubG93ZXIoKS5z"
    "dGFydHN3aXRoKCJ2PWRtYXJjMSIpKSwgTm9uZSkKICAgIHBtID0gcmUuc2VhcmNoKHIicD0oXHcrKSIsIGRtYXJjKSBpZiBk"
    "bWFyYyBlbHNlIE5vbmUKICAgIHBvbGljeSA9IHBtLmdyb3VwKDEpLmxvd2VyKCkgaWYgcG0gZWxzZSBOb25lCiAgICBkbWFy"
    "Y19vayA9IHBvbGljeSBpbiAoInJlamVjdCIsICJxdWFyYW50aW5lIikKICAgIGFkZChmdWxsX3VybCwgIldBLU1BSUwtNDEx"
    "IiwgIkVtYWlsIFNlY3VyaXR5IiwgIkRNQVJDIHBvbGljeSBjb25maWd1cmVkIChyZWplY3Qgb3IgcXVhcmFudGluZSkiLAog"
    "ICAgICAgICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIgaWYgZG1hcmNfb2sgZWxzZSAiRkFJTCIsCiAgICAgICAgZiJETUFSQzog"
    "e2RtYXJjIG9yICdubyB2PURNQVJDMSBUWFQgcmVjb3JkIGZvdW5kIGF0IF9kbWFyYy4nICsgaG9zdH0uIiArCiAgICAgICAg"
    "KGYiIFBvbGljeTogcD17cG9saWN5fS4iIGlmIHBvbGljeSBlbHNlICIiKSkKCiAgICBka2ltX2ZvdW5kID0gTm9uZQogICAg"
    "c2VsZWN0b3JzX3RvX3RyeSA9IGxpc3QoQ09NTU9OX0RLSU1fU0VMRUNUT1JTKSArIGxpc3QoYXJncy5ka2ltX3NlbGVjdG9y"
    "IG9yIFtdKQogICAgZm9yIHNlbCBpbiBzZWxlY3RvcnNfdG9fdHJ5OgogICAgICAgIGRraW1fdHh0cyA9IF9uc2xvb2t1cF90"
    "eHQoZiJ7c2VsfS5fZG9tYWlua2V5Lntob3N0fSIpIG9yIFtdCiAgICAgICAgaWYgYW55KHQubG93ZXIoKS5zdGFydHN3aXRo"
    "KCJ2PWRraW0xIikgb3IgInA9IiBpbiB0Lmxvd2VyKCkgZm9yIHQgaW4gZGtpbV90eHRzKToKICAgICAgICAgICAgZGtpbV9m"
    "b3VuZCA9IHNlbAogICAgICAgICAgICBicmVhawogICAgYWRkKGZ1bGxfdXJsLCAiV0EtTUFJTC00MTIiLCAiRW1haWwgU2Vj"
    "dXJpdHkiLCAiREtJTSBzaWduaW5nIGNvbmZpZ3VyZWQgYW5kIHZhbGlkIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIlBB"
    "U1MiIGlmIGRraW1fZm91bmQgZWxzZSAiTUFOVUFMIiwKICAgICAgICAoZiJGb3VuZCBhIERLSU0gcmVjb3JkIHVuZGVyIHNl"
    "bGVjdG9yICd7ZGtpbV9mb3VuZH0nLiIgaWYgZGtpbV9mb3VuZCBlbHNlCiAgICAgICAgIGYiTm8gREtJTSByZWNvcmQgZm91"
    "bmQgdW5kZXIgY29tbW9uIHNlbGVjdG9ycyAoeycsICcuam9pbihzZWxlY3RvcnNfdG9fdHJ5KX0pLiBES0lNIHNlbGVjdG9y"
    "cyBhcmUgIgogICAgICAgICAicHJvdmlkZXItc3BlY2lmaWMgYW5kIG5vdCBndWVzc2FibGUgaW4gZ2VuZXJhbCAtIGNvbmZp"
    "cm0gdGhlIHJlYWwgc2VsZWN0b3IgKGNoZWNrIGEgcmF3IGVtYWlsJ3MgIgogICAgICAgICAiREtJTS1TaWduYXR1cmUgaGVh"
    "ZGVyKSBhbmQgcmUtY2hlY2sgd2l0aCAtLWRraW0tc2VsZWN0b3IgPG5hbWU+LiIpKQoKICAgIHNwb29mX3Jpc2sgPSAobm90"
    "IHNwZl9oYXJkX2ZhaWwpIGFuZCAobm90IGRtYXJjX29rKQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtTUFJTC00MTMiLCAiRW1h"
    "aWwgU2VjdXJpdHkiLCAiRW1haWwgc3Bvb2ZpbmcgcG9zc2libGUgaWYgU1BGL0RNQVJDIGFic2VudCBvciB3ZWFrIiwKICAg"
    "ICAgICAiSGlnaCIsICJQMSIsICJGQUlMIiBpZiBzcG9vZl9yaXNrIGVsc2UgIlBBU1MiLAogICAgICAgIGYiRGVyaXZlZCBm"
    "cm9tIFNQRiAoaGFyZCBmYWlsOiB7c3BmX2hhcmRfZmFpbH0pIGFuZCBETUFSQyAocG9saWN5OiB7cG9saWN5IG9yICdub25l"
    "J30pIGFib3ZlLiIgKwogICAgICAgICgiIEJvdGggYXJlIHdlYWsvYWJzZW50IC0gc3Bvb2ZlZCBtYWlsIGFzIHRoaXMgZG9t"
    "YWluIGlzIHBsYXVzaWJsZTsgdmVyaWZ5IHdpdGggYSB0b29sIGxpa2UgbWFpbHNwb29mL3NwZi1yZWNvcmQuY29tLiIgaWYg"
    "c3Bvb2ZfcmlzayBlbHNlICIiKSkKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgOS4gSW5mb3JtYXRpb24gRGlzY2xvc3VyZSAtIFdBLVNTLTA1NS4uMDU5"
    "IChyZXVzZXMgc2V2ZXJhbCBjaGVja3MgYWJvdmUpCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBjaGVja19pbmZvcm1hdGlvbl9kaXNjbG9zdXJlKGZ1"
    "bGxfdXJsLCBoZWFkZXJzX3Jlc3VsdCwgYXJncywgaGRyNDAwX2V2aWRlbmNlLCBoZHI0MDFfZXZpZGVuY2UsIG90ZzI4Nl9l"
    "dmlkZW5jZSk6CiAgICBiYXNlID0gZGlyX29mKGZ1bGxfdXJsKQoKICAgIHRyYWNlX2ZhaWwgPSAiRkFJTCIgaW4gW3JbInJl"
    "c3VsdCJdIGZvciByIGluIFJFU1VMVFMgaWYgclsiaWQiXSA9PSAiV0EtSERSLTQwMCIgYW5kIHJbInVybCJdID09IGZ1bGxf"
    "dXJsXQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtU1MtMDU1IiwgIkluZm9ybWF0aW9uIERpc2Nsb3N1cmUiLCAiSW5mb3JtYXRp"
    "b24gZGlzY2xvc3VyZSBpbiBlcnJvciBtZXNzYWdlcyAoc3RhY2sgdHJhY2UpIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwg"
    "IkZBSUwiIGlmIHRyYWNlX2ZhaWwgZWxzZSAiUEFTUyIsCiAgICAgICAgIihzYW1lIHVuZGVybHlpbmcgY2hlY2sgYXMgV0Et"
    "SERSLTQwMCkgIiArIGhkcjQwMF9ldmlkZW5jZSkKCiAgICBkYmdfaGl0cyA9IFtdCiAgICBmb3IgcGF0aCBpbiBERUJVR19Q"
    "QUdFUzoKICAgICAgICByciA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgpLCAiR0VUIiwgdGltZW91dD1h"
    "cmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICAgICAgaWYgbm90IHJyLmVycm9yIGFuZCByci5zdGF0"
    "dXMgPT0gMjAwOgogICAgICAgICAgICBkYmdfaGl0cy5hcHBlbmQocGF0aCkKICAgIGFkZChmdWxsX3VybCwgIldBLVNTLTA1"
    "NiIsICJJbmZvcm1hdGlvbiBEaXNjbG9zdXJlIiwgIkluZm8gZGlzY2xvc3VyZSAtIGRlYnVnIHBhZ2UgKHBocGluZm8vcmFp"
    "bHMgZGVidWcpIiwKICAgICAgICAiSGlnaCIsICJQMSIsICJGQUlMIiBpZiBkYmdfaGl0cyBlbHNlICJQQVNTIiwKICAgICAg"
    "ICBmIkFjY2Vzc2libGU6IHsnLCAnLmpvaW4oZGJnX2hpdHMpfSIgaWYgZGJnX2hpdHMgZWxzZSBmIk5vbmUgb2YgeycsICcu"
    "am9pbihERUJVR19QQUdFUyl9IGFjY2Vzc2libGUgYXQgc2l0ZSByb290LiIpCgogICAgYmFja3VwX2ZhaWwgPSBhbnkoclsi"
    "cmVzdWx0Il0gPT0gIkZBSUwiIGZvciByIGluIFJFU1VMVFMgaWYgclsiaWQiXSBpbiAoIldBLU9URy0yODUiLCAiV0EtT1RH"
    "LTI4NiIpIGFuZCByWyJ1cmwiXSA9PSBmdWxsX3VybCkKICAgIGFkZChmdWxsX3VybCwgIldBLVNTLTA1NyIsICJJbmZvcm1h"
    "dGlvbiBEaXNjbG9zdXJlIiwgIkluZm8gZGlzY2xvc3VyZSAtIHNvdXJjZSBjb2RlIHZpYSBiYWNrdXAgZmlsZXMiLAogICAg"
    "ICAgICJIaWdoIiwgIlAxIiwgIkZBSUwiIGlmIGJhY2t1cF9mYWlsIGVsc2UgIlBBU1MiLAogICAgICAgICIoc2FtZSB1bmRl"
    "cmx5aW5nIHByb2JlcyBhcyBXQS1PVEctMjg1LzI4NikgIiArIG90ZzI4Nl9ldmlkZW5jZSkKCiAgICBhZGQoZnVsbF91cmws"
    "ICJXQS1TUy0wNTgiLCAiSW5mb3JtYXRpb24gRGlzY2xvc3VyZSIsICJJbmZvIGRpc2Nsb3N1cmUgLSB2ZXJzaW9uIHZpYSBy"
    "ZXNwb25zZSBoZWFkZXJzIiwKICAgICAgICAiTG93IiwgIlAzIiwKICAgICAgICBuZXh0KChyWyJyZXN1bHQiXSBmb3IgciBp"
    "biBSRVNVTFRTIGlmIHJbImlkIl0gPT0gIldBLUhEUi00MDEiIGFuZCByWyJ1cmwiXSA9PSBmdWxsX3VybCksICJJTkZPIiks"
    "CiAgICAgICAgIihzYW1lIHVuZGVybHlpbmcgY2hlY2sgYXMgV0EtSERSLTQwMSkgIiArIGhkcjQwMV9ldmlkZW5jZSkKCiAg"
    "ICBnaXRfaGl0cyA9IFtdCiAgICBmb3IgcGF0aCBpbiBHSVRfU1ZOX1BST0JFUzoKICAgICAgICByciA9IHJhd19yZXF1ZXN0"
    "KGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgpLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5z"
    "ZWN1cmUpCiAgICAgICAgaWYgbm90IHJyLmVycm9yIGFuZCByci5zdGF0dXMgPT0gMjAwOgogICAgICAgICAgICBnaXRfaGl0"
    "cy5hcHBlbmQocGF0aCkKICAgIGFkZChmdWxsX3VybCwgIldBLVNTLTA1OSIsICJJbmZvcm1hdGlvbiBEaXNjbG9zdXJlIiwg"
    "IkluZm8gZGlzY2xvc3VyZSAtIHNlbnNpdGl2ZSBkYXRhIGluIGdpdC9zdm4vLkRTX1N0b3JlIiwKICAgICAgICAiSGlnaCIs"
    "ICJQMSIsICJGQUlMIiBpZiBnaXRfaGl0cyBlbHNlICJQQVNTIiwKICAgICAgICBmIkFjY2Vzc2libGU6IHsnLCAnLmpvaW4o"
    "Z2l0X2hpdHMpfSAtIGNsb25lL2V4dHJhY3QgdGhlc2UgdG8gcmVjb3ZlciBzb3VyY2UgKGUuZy4gZ2l0LWR1bXBlciBmb3Ig"
    "Ly5naXQvKS4iIGlmIGdpdF9oaXRzCiAgICAgICAgZWxzZSBmIk5vbmUgb2YgeycsICcuam9pbihHSVRfU1ZOX1BST0JFUyl9"
    "IGFjY2Vzc2libGUgYXQgc2l0ZSByb290LiIpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDEwLiBIVFRQIEhvc3QgSGVhZGVyIEF0dGFja3MgLSBXQS1B"
    "RFYtMjE4Li4yMjQKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLQoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIEFjY2VzcyBDb250cm9sIC8gQXV0aG9yaXphdGlvbiAoMi1hY2NvdW50KSAtIFdB"
    "LU9URy0zMTIsIFdBLVNTLTA3MSwKIyBXQS1PVEctMzE0LiBPcHQtaW4gb25seSwgdmlhIC0tYWNjb3VudDEtY29va2llIC8g"
    "LS1hY2NvdW50Mi1jb29raWUgLQojIHRoaXMgc2NyaXB0IE5FVkVSIGxvZ3MgaW4sIGJydXRlLWZvcmNlcywgb3IgaGFydmVz"
    "dHMgY3JlZGVudGlhbHMgaXRzZWxmLgojIFJlcXVlc3RlZCBkaXJlY3RseTogIndoZXJlIGV2ZXIgcmVxdWlyZWQgdGhlIHR3"
    "byBhY2NvdW50IGFzayBhcyBpbnB1dAojIGZvciBjaGVjayAuLi4gbmV2ZXIgdGFrZSB0aGUgY3JlZGV0aWxzIGFsc28gdG8g"
    "bmF2aWdhdGUgaW5zaWRlIiAtIHNvCiMgdGhlc2UgZmxhZ3Mgb25seSBldmVyIGhvbGQgYSBzZXNzaW9uIGNvb2tpZSB0aGUg"
    "b3BlcmF0b3IgYWxyZWFkeSBoYXMKIyBmcm9tIGxvZ2dpbmcgaW4gdGhlbXNlbHZlczsgdGhlIGNvb2tpZSB2YWx1ZSBpdHNl"
    "bGYgaXMgbmV2ZXIgd3JpdHRlbiB0bwojIGV2aWRlbmNlL0pTT04vQ1NWL3NjcmVlbnNob3RzLCBvbmx5IHBhc3MvZmFpbCBj"
    "b21wYXJpc29uIGRhdGEgaXMuCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBfZmV0Y2hfd2l0aF9jb29raWUodXJsLCBjb29raWUsIHRpbWVvdXQsIGlu"
    "c2VjdXJlKToKICAgIGlmIG5vdCBjb29raWU6CiAgICAgICAgcmV0dXJuIHJhd19yZXF1ZXN0KHVybCwgIkdFVCIsIHRpbWVv"
    "dXQ9dGltZW91dCwgaW5zZWN1cmU9aW5zZWN1cmUpCiAgICByZXR1cm4gcmF3X3JlcXVlc3QodXJsLCAiR0VUIiwgZXh0cmFf"
    "aGVhZGVycz17IkNvb2tpZSI6IGNvb2tpZX0sIHRpbWVvdXQ9dGltZW91dCwgaW5zZWN1cmU9aW5zZWN1cmUpCgoKZGVmIF9y"
    "ZXNwX3NpZ25hdHVyZShyKToKICAgIGlmIG5vdCByIG9yIHIuZXJyb3I6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHJldHVy"
    "biAoci5zdGF0dXMsIGxlbihyLmJvZHkpLCBoYXNobGliLnNoYTI1NihyLmJvZHkpLmhleGRpZ2VzdCgpWzoxMl0pCgoKZGVm"
    "IGNoZWNrX2FjY2Vzc19jb250cm9sXzJmYShmdWxsX3VybCwgYXJncyk6CiAgICBhY2N0MV9jb29raWUgPSBnZXRhdHRyKGFy"
    "Z3MsICJhY2NvdW50MV9jb29raWUiLCBOb25lKQogICAgYWNjdDJfY29va2llID0gZ2V0YXR0cihhcmdzLCAiYWNjb3VudDJf"
    "Y29va2llIiwgTm9uZSkKICAgIGFjY3QxX2xhYmVsID0gZ2V0YXR0cihhcmdzLCAiYWNjb3VudDFfbGFiZWwiLCBOb25lKSBv"
    "ciAiQWNjb3VudCAxIgogICAgYWNjdDJfbGFiZWwgPSBnZXRhdHRyKGFyZ3MsICJhY2NvdW50Ml9sYWJlbCIsIE5vbmUpIG9y"
    "ICJBY2NvdW50IDIiCgogICAgaWYgbm90IGFjY3QxX2Nvb2tpZSBhbmQgbm90IGFjY3QyX2Nvb2tpZToKICAgICAgICBmb3Ig"
    "Y2lkLCBjYXQsIG5hbWUgaW4gWwogICAgICAgICAgICAoIldBLU9URy0zMTIiLCAiQXV0aG9yaXphdGlvbiBUZXN0aW5nIiwg"
    "IlRlc3QgYnlwYXNzaW5nIGF1dGhvcml6YXRpb24gc2NoZW1hIChmb3JjZSBicm93c2UpIiksCiAgICAgICAgICAgICgiV0Et"
    "U1MtMDcxIiwgIkFjY2VzcyBDb250cm9sIiwgIkhvcml6b250YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24gKGFjY2VzcyBhbm90"
    "aGVyIHVzZXIgZGF0YSkiKSwKICAgICAgICAgICAgKCJXQS1PVEctMzE0IiwgIkF1dGhvcml6YXRpb24gVGVzdGluZyIsICJU"
    "ZXN0IGluc2VjdXJlIGRpcmVjdCBvYmplY3QgcmVmZXJlbmNlcyAoSURPUikiKSwKICAgICAgICBdOgogICAgICAgICAgICBh"
    "ZGQoZnVsbF91cmwsIGNpZCwgY2F0LCBuYW1lLCAiQ3JpdGljYWwiLCAiUDEiLCAiTUFOVUFMIiwKICAgICAgICAgICAgICAg"
    "ICJOZWVkcyBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gdG8gdGVzdCAtIHJlLXJ1biB3aXRoIC0tY29va2llIFwic2Vzc2lv"
    "bmlkPS4uLlwiICh0aGlzIGFsc28gIgogICAgICAgICAgICAgICAgImF1dGhlbnRpY2F0ZXMgZXZlcnkgb3RoZXIgY2hlY2sg"
    "aW4gdGhlIHN1aXRlKSBhbmQgYWRkIC0tY29va2llMiBcInNlc3Npb25pZD0uLi5cIiAoYSBTRUNPTkQsICIKICAgICAgICAg"
    "ICAgICAgICJkaWZmZXJlbnQgYWNjb3VudCdzIG93biBzZXNzaW9uKSBmb3IgdGhlIHR3by1hY2NvdW50IElET1IvaG9yaXpv"
    "bnRhbC1lc2NhbGF0aW9uIGNoZWNrcy4gT25seSAiCiAgICAgICAgICAgICAgICAicGFzcyBhIHNlc3Npb24gY29va2llIFlP"
    "VSBhbHJlYWR5IG9idGFpbmVkIGJ5IGxvZ2dpbmcgaW4geW91cnNlbGYgLSB0aGlzIHNjcmlwdCBuZXZlciBhdHRlbXB0cyAi"
    "CiAgICAgICAgICAgICAgICAidG8gbG9nIGluLCBndWVzcywgb3IgaGFydmVzdCBjcmVkZW50aWFscy4iKQogICAgICAgIHJl"
    "dHVybgoKICAgIHVuYXV0aCA9IHJhd19yZXF1ZXN0KGZ1bGxfdXJsLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGlu"
    "c2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICBhY2N0MSA9IF9mZXRjaF93aXRoX2Nvb2tpZShmdWxsX3VybCwgYWNjdDFfY29v"
    "a2llLCBhcmdzLnRpbWVvdXQsIGFyZ3MuaW5zZWN1cmUpIGlmIGFjY3QxX2Nvb2tpZSBlbHNlIE5vbmUKCiAgICBpZiBhY2N0"
    "MV9jb29raWUgYW5kIGFjY3QxIGFuZCBub3QgYWNjdDEuZXJyb3IgYW5kIG5vdCB1bmF1dGguZXJyb3I6CiAgICAgICAgc2ln"
    "X3VuYXV0aCwgc2lnX2FjY3QxID0gX3Jlc3Bfc2lnbmF0dXJlKHVuYXV0aCksIF9yZXNwX3NpZ25hdHVyZShhY2N0MSkKICAg"
    "ICAgICBsb29rc19zYW1lID0gYm9vbChzaWdfdW5hdXRoIGFuZCBzaWdfYWNjdDEgYW5kIHNpZ191bmF1dGhbMTpdID09IHNp"
    "Z19hY2N0MVsxOl0pCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxMiIsICJBdXRob3JpemF0aW9uIFRlc3Rpbmci"
    "LCAiVGVzdCBieXBhc3NpbmcgYXV0aG9yaXphdGlvbiBzY2hlbWEgKGZvcmNlIGJyb3dzZSkiLAogICAgICAgICAgICAiQ3Jp"
    "dGljYWwiLCAiUDEiLCAiRkFJTCIgaWYgbG9va3Nfc2FtZSBlbHNlICJQQVNTIiwKICAgICAgICAgICAgZiJVbmF1dGhlbnRp"
    "Y2F0ZWQ6IEhUVFAge3VuYXV0aC5zdGF0dXN9LCB7bGVuKHVuYXV0aC5ib2R5KX0gYnl0ZXMuIFdpdGgge2FjY3QxX2xhYmVs"
    "fSBzZXNzaW9uOiAiCiAgICAgICAgICAgIGYiSFRUUCB7YWNjdDEuc3RhdHVzfSwge2xlbihhY2N0MS5ib2R5KX0gYnl0ZXMu"
    "IiArCiAgICAgICAgICAgIChmIiBCb3RoIHJlc3BvbnNlcyBhcmUgYnl0ZS1mb3ItYnl0ZSBpZGVudGljYWwgKHNhbWUgbGVu"
    "Z3RoK2hhc2gpIC0gaWYgdGhpcyBwYWdlIGlzIG1lYW50IHRvIHJlcXVpcmUgIgogICAgICAgICAgICAgZiJsb2dpbiwgaXQn"
    "cyByZWFjaGFibGUgd2l0aG91dCBvbmUuIiBpZiBsb29rc19zYW1lIGVsc2UKICAgICAgICAgICAgICIgUmVzcG9uc2VzIGRp"
    "ZmZlciBiZXR3ZWVuIHVuYXV0aGVudGljYXRlZCBhbmQgYXV0aGVudGljYXRlZCByZXF1ZXN0cyAtIHRoaXMgcGFnZSBkb2Vz"
    "IGFwcGVhciB0byAiCiAgICAgICAgICAgICAiZ2F0ZSBpdHMgY29udGVudCBvbiB0aGUgc2Vzc2lvbi4iKSkKICAgIGVsc2U6"
    "CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxMiIsICJBdXRob3JpemF0aW9uIFRlc3RpbmciLCAiVGVzdCBieXBh"
    "c3NpbmcgYXV0aG9yaXphdGlvbiBzY2hlbWEgKGZvcmNlIGJyb3dzZSkiLAogICAgICAgICAgICAiQ3JpdGljYWwiLCAiUDEi"
    "LCAiTUFOVUFMIiBpZiBub3QgYWNjdDFfY29va2llIGVsc2UgIkVSUk9SIiwKICAgICAgICAgICAgIk5lZWRzIC0tY29va2ll"
    "IHRvIGNvbXBhcmUgYWdhaW5zdCBhbiB1bmF1dGhlbnRpY2F0ZWQgcmVxdWVzdC4iIGlmIG5vdCBhY2N0MV9jb29raWUKICAg"
    "ICAgICAgICAgZWxzZSAoKHVuYXV0aC5lcnJvciBvciAoYWNjdDEuZXJyb3IgaWYgYWNjdDEgZWxzZSAiIikpIG9yICJDb3Vs"
    "ZCBub3QgY29tcGxldGUgYm90aCByZXF1ZXN0cy4iKSkKCiAgICBpZiBub3QgYWNjdDJfY29va2llOgogICAgICAgIGZvciBj"
    "aWQsIGNhdCwgbmFtZSBpbiBbCiAgICAgICAgICAgICgiV0EtU1MtMDcxIiwgIkFjY2VzcyBDb250cm9sIiwgIkhvcml6b250"
    "YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24gKGFjY2VzcyBhbm90aGVyIHVzZXIgZGF0YSkiKSwKICAgICAgICAgICAgKCJXQS1P"
    "VEctMzE0IiwgIkF1dGhvcml6YXRpb24gVGVzdGluZyIsICJUZXN0IGluc2VjdXJlIGRpcmVjdCBvYmplY3QgcmVmZXJlbmNl"
    "cyAoSURPUikiKSwKICAgICAgICBdOgogICAgICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgY2F0LCBuYW1lLCAiQ3JpdGlj"
    "YWwiLCAiUDEiLCAiTUFOVUFMIiwKICAgICAgICAgICAgICAgIGYiTmVlZHMgYSBTRUNPTkQgYWNjb3VudCdzIHNlc3Npb24g"
    "dG9vIC0gcmUtcnVuIHdpdGggLS1jb29raWUyIFwic2Vzc2lvbmlkPS4uLlwiIHRvIHRlc3QgIgogICAgICAgICAgICAgICAg"
    "ZiJ3aGV0aGVyIHthY2N0Ml9sYWJlbH0gY2FuIHNlZSB7YWNjdDFfbGFiZWx9J3MgY29udGVudCBhdCB0aGlzIHNhbWUgVVJM"
    "LiIpCiAgICAgICAgcmV0dXJuCgogICAgYWNjdDIgPSBfZmV0Y2hfd2l0aF9jb29raWUoZnVsbF91cmwsIGFjY3QyX2Nvb2tp"
    "ZSwgYXJncy50aW1lb3V0LCBhcmdzLmluc2VjdXJlKQogICAgaWYgYWNjdDEgaXMgTm9uZSBhbmQgYWNjdDFfY29va2llOgog"
    "ICAgICAgIGFjY3QxID0gX2ZldGNoX3dpdGhfY29va2llKGZ1bGxfdXJsLCBhY2N0MV9jb29raWUsIGFyZ3MudGltZW91dCwg"
    "YXJncy5pbnNlY3VyZSkKCiAgICBpZiBhY2N0MSBhbmQgYWNjdDIgYW5kIG5vdCBhY2N0MS5lcnJvciBhbmQgbm90IGFjY3Qy"
    "LmVycm9yOgogICAgICAgIHNpZzEsIHNpZzIgPSBfcmVzcF9zaWduYXR1cmUoYWNjdDEpLCBfcmVzcF9zaWduYXR1cmUoYWNj"
    "dDIpCiAgICAgICAgaWRlbnRpY2FsID0gYm9vbChzaWcxIGFuZCBzaWcyIGFuZCBzaWcxWzE6XSA9PSBzaWcyWzE6XSkKICAg"
    "ICAgICBldmlkZW5jZSA9IChmInthY2N0MV9sYWJlbH06IEhUVFAge2FjY3QxLnN0YXR1c30sIHtsZW4oYWNjdDEuYm9keSl9"
    "IGJ5dGVzLiAiCiAgICAgICAgICAgICAgICAgICAgZiJ7YWNjdDJfbGFiZWx9OiBIVFRQIHthY2N0Mi5zdGF0dXN9LCB7bGVu"
    "KGFjY3QyLmJvZHkpfSBieXRlcy4iKQogICAgICAgIGlmIGlkZW50aWNhbDoKICAgICAgICAgICAgcmVzdWx0ID0gIk1BTlVB"
    "TCIKICAgICAgICAgICAgZXZpZGVuY2UgKz0gKGYiIEJvdGggYWNjb3VudHMgc2VlIGJ5dGUtZm9yLWJ5dGUgaWRlbnRpY2Fs"
    "IGNvbnRlbnQgKHNhbWUgbGVuZ3RoK2hhc2gpIGF0IHRoaXMgZXhhY3QgIgogICAgICAgICAgICAgICAgICAgICAgICAgZiJV"
    "UkwuIElmIHRoaXMgVVJML3Jlc291cmNlIGlzIG1lYW50IHRvIGJlIHNwZWNpZmljIHRvIHthY2N0MV9sYWJlbH0gKGNvbnRh"
    "aW5zIGFuICIKICAgICAgICAgICAgICAgICAgICAgICAgIGYiYWNjb3VudC1zcGVjaWZpYyBJRCwgZmlsZW5hbWUsIG9yIHNp"
    "bWlsYXIgaW4gdGhlIHBhdGgvcXVlcnkpLCB0aGVuIHthY2N0Ml9sYWJlbH0gIgogICAgICAgICAgICAgICAgICAgICAgICAg"
    "InN1Y2Nlc3NmdWxseSB2aWV3aW5nIGl0IGlzIGEgc3Ryb25nIGhvcml6b250YWwtcHJpdmlsZWdlLWVzY2FsYXRpb24gLyBJ"
    "RE9SIGluZGljYXRvciAtICIKICAgICAgICAgICAgICAgICAgICAgICAgICJjb25maXJtIHRoZSByZXNvdXJjZSBJUyBhY2Nv"
    "dW50LXNwZWNpZmljIChub3QgYSBzaGFyZWQvcHVibGljIHBhZ2UpIGJlZm9yZSByZXBvcnRpbmcuIikKICAgICAgICBlbHNl"
    "OgogICAgICAgICAgICByZXN1bHQgPSAiUEFTUyIKICAgICAgICAgICAgZXZpZGVuY2UgKz0gIiBSZXNwb25zZXMgZGlmZmVy"
    "IGJldHdlZW4gdGhlIHR3byBhY2NvdW50cyAtIG5vIGV2aWRlbmNlIG9mIGNyb3NzLWFjY291bnQgYWNjZXNzIGF0IHRoaXMg"
    "VVJMLiIKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1TUy0wNzEiLCAiQWNjZXNzIENvbnRyb2wiLCAiSG9yaXpvbnRhbCBw"
    "cml2aWxlZ2UgZXNjYWxhdGlvbiAoYWNjZXNzIGFub3RoZXIgdXNlciBkYXRhKSIsCiAgICAgICAgICAgICJDcml0aWNhbCIs"
    "ICJQMSIsIHJlc3VsdCwgZXZpZGVuY2UpCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxNCIsICJBdXRob3JpemF0"
    "aW9uIFRlc3RpbmciLCAiVGVzdCBpbnNlY3VyZSBkaXJlY3Qgb2JqZWN0IHJlZmVyZW5jZXMgKElET1IpIiwKICAgICAgICAg"
    "ICAgIkNyaXRpY2FsIiwgIlAxIiwgcmVzdWx0LCBldmlkZW5jZSkKICAgIGVsc2U6CiAgICAgICAgZXJyID0gKChhY2N0MS5l"
    "cnJvciBpZiBhY2N0MSBhbmQgYWNjdDEuZXJyb3IgZWxzZSAiIikgb3IgKGFjY3QyLmVycm9yIGlmIGFjY3QyIGFuZCBhY2N0"
    "Mi5lcnJvciBlbHNlICIiKQogICAgICAgICAgICAgICBvciAiQ291bGQgbm90IGNvbXBsZXRlIGJvdGggYXV0aGVudGljYXRl"
    "ZCByZXF1ZXN0cy4iKQogICAgICAgIGZvciBjaWQsIGNhdCwgbmFtZSBpbiBbCiAgICAgICAgICAgICgiV0EtU1MtMDcxIiwg"
    "IkFjY2VzcyBDb250cm9sIiwgIkhvcml6b250YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24gKGFjY2VzcyBhbm90aGVyIHVzZXIg"
    "ZGF0YSkiKSwKICAgICAgICAgICAgKCJXQS1PVEctMzE0IiwgIkF1dGhvcml6YXRpb24gVGVzdGluZyIsICJUZXN0IGluc2Vj"
    "dXJlIGRpcmVjdCBvYmplY3QgcmVmZXJlbmNlcyAoSURPUikiKSwKICAgICAgICBdOgogICAgICAgICAgICBhZGQoZnVsbF91"
    "cmwsIGNpZCwgY2F0LCBuYW1lLCAiQ3JpdGljYWwiLCAiUDEiLCAiRVJST1IiLCBlcnIpCgoKZGVmIGNoZWNrX2hvc3RfaGVh"
    "ZGVyKGZ1bGxfdXJsLCBhcmdzKToKICAgIHRva2VuID0gZiJldmlsLWhvc3QtaGVhZGVyLXRlc3Qte3JhbmRfdG9rZW4oOCl9"
    "LmV4YW1wbGUiCiAgICByID0gcmF3X3JlcXVlc3QoZnVsbF91cmwsICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5z"
    "ZWN1cmU9YXJncy5pbnNlY3VyZSwgaG9zdF9vdmVycmlkZT10b2tlbikKICAgIGlkc19hbmRfbmFtZXMgPSBbCiAgICAgICAg"
    "KCJXQS1BRFYtMjE4IiwgIkhvc3QgaGVhZGVyIC0gcGFzc3dvcmQgcmVzZXQgcG9pc29uaW5nIiwKICAgICAgICAgIklmIGEg"
    "cGFzc3dvcmQtcmVzZXQgZW1haWwgaXMgZXZlciBzZW50LCBjb25maXJtIG1hbnVhbGx5IHdoZXRoZXIgdGhlIHJlc2V0IGxp"
    "bmsgdXNlcyB0aGUgSG9zdCBoZWFkZXIgdmFsdWUuIiksCiAgICAgICAgKCJXQS1BRFYtMjE5IiwgIkhvc3QgaGVhZGVyIC0g"
    "d2ViIGNhY2hlIHBvaXNvbmluZyB2aWEgSG9zdCIsCiAgICAgICAgICJJZiB0aGlzIGFwcCBzaXRzIGJlaGluZCBhIGNhY2hl"
    "LCBjb25maXJtIG1hbnVhbGx5IHdoZXRoZXIgYSBwb2lzb25lZCByZXNwb25zZSBnZXRzIGNhY2hlZCBhbmQgc2VydmVkIHRv"
    "IG90aGVyIHVzZXJzLiIpLAogICAgICAgICgiV0EtQURWLTIyMCIsICJIb3N0IGhlYWRlciAtIFNTUkYgdmlhIG1hbGZvcm1l"
    "ZCBIb3N0IGhlYWRlciIsCiAgICAgICAgICJUcnkgYSBtYWxmb3JtZWQvaW50ZXJuYWwgSG9zdCB2YWx1ZSAoZS5nLiAxNjku"
    "MjU0LjE2OS4yNTQpIGFuZCBjaGVjayBmb3IgYW55IHNlcnZlci1zaWRlIGZldGNoIGJlaGF2aW9yIG1hbnVhbGx5LiIpLAog"
    "ICAgICAgICgiV0EtQURWLTIyMSIsICJIb3N0IGhlYWRlciAtIGJ5cGFzcyBpbnRlcm5hbCBhdXRoZW50aWNhdGlvbiAobG9j"
    "YWxob3N0KSIsCiAgICAgICAgICJUcnkgJ0hvc3Q6IGxvY2FsaG9zdCcgc3BlY2lmaWNhbGx5IGFuZCBjaGVjayBmb3IgZGlm"
    "ZmVyZW50IChlLmcuIGFkbWluL2ludGVybmFsKSBiZWhhdmlvciBtYW51YWxseS4iKSwKICAgICAgICAoIldBLUFEVi0yMjIi"
    "LCAiSG9zdCBoZWFkZXIgLSByb3V0aW5nLWJhc2VkIFNTUkYgKGFtYmlndW91cyByZXF1ZXN0cykiLAogICAgICAgICAiTmVl"
    "ZHMgYSBsb2FkLWJhbGFuY2VyL3Byb3h5LWNoYWluLWF3YXJlIHRlc3QgKGR1cGxpY2F0ZSBIb3N0IGhlYWRlcnMsIG1pc21h"
    "dGNoZWQgSG9zdCB2cy4gcmVxdWVzdCBsaW5lKSAtIG1hbnVhbC9CdXJwLiIpLAogICAgICAgICgiV0EtQURWLTIyMyIsICJI"
    "b3N0IGhlYWRlciAtIFNTUkYgdmlhIGNvbm5lY3Rpb24gaGVhZGVyIiwKICAgICAgICAgIk5lZWRzIGEgQ29ubmVjdGlvbi9Y"
    "LUZvcndhcmRlZC0qIGhlYWRlciBtYW5pcHVsYXRpb24gdGVzdCBhZ2FpbnN0IGFuIGludGVybmFsIHRhcmdldCAtIG1hbnVh"
    "bC9CdXJwLiIpLAogICAgICAgICgiV0EtQURWLTIyNCIsICJIb3N0IGhlYWRlciAtIFgtSG9zdCAvIFgtRm9yd2FyZGVkLVNl"
    "cnZlciBvdmVycmlkZSIsCiAgICAgICAgICJUcnkgWC1Ib3N0IC8gWC1Gb3J3YXJkZWQtSG9zdCAvIFgtRm9yd2FyZGVkLVNl"
    "cnZlciBoZWFkZXJzIHNwZWNpZmljYWxseSBhbmQgY29tcGFyZSByZXNwb25zZXMgbWFudWFsbHkuIiksCiAgICBdCiAgICBp"
    "ZiByLmVycm9yOgogICAgICAgIGZvciBjaWQsIG5hbWUsIF8gaW4gaWRzX2FuZF9uYW1lczoKICAgICAgICAgICAgYWRkKGZ1"
    "bGxfdXJsLCBjaWQsICJIVFRQIEhvc3QgSGVhZGVyIEF0dGFja3MiLCBuYW1lLCAiSGlnaCIsICJQMSIsICJFUlJPUiIsIHIu"
    "ZXJyb3IpCiAgICAgICAgcmV0dXJuCgogICAgYm9keV90ZXh0ID0gci50ZXh0KCkKICAgIGxvYyA9IHIuaGVhZGVyKCJMb2Nh"
    "dGlvbiIpCiAgICByZWZsZWN0ZWRfaW5fYm9keSA9IHRva2VuIGluIGJvZHlfdGV4dAogICAgcmVmbGVjdGVkX2luX2xvY2F0"
    "aW9uID0gYm9vbChsb2MgYW5kIHRva2VuIGluIGxvYykKICAgIHJlZmxlY3RlZCA9IHJlZmxlY3RlZF9pbl9ib2R5IG9yIHJl"
    "ZmxlY3RlZF9pbl9sb2NhdGlvbgogICAgYmFzZV9ldmlkZW5jZSA9IChmIlNlbnQgSG9zdDoge3Rva2VufSB0byB7ZnVsbF91"
    "cmx9IC0+IHN0YXR1cyB7ci5zdGF0dXN9LCAiCiAgICAgICAgICAgICAgICAgICAgICBmInJlZmxlY3RlZCBpbiBib2R5OiB7"
    "cmVmbGVjdGVkX2luX2JvZHl9LCByZWZsZWN0ZWQgaW4gTG9jYXRpb24gaGVhZGVyOiB7cmVmbGVjdGVkX2luX2xvY2F0aW9u"
    "fS4iKQoKICAgIGN1cmxfcmVzdWx0ID0gTm9uZSBpZiBnZXRhdHRyKGFyZ3MsICJub19jbGlfdG9vbHMiLCBGYWxzZSkgZWxz"
    "ZSBydW5fY3VybF93aXRoX2hvc3RfaGVhZGVyKAogICAgICAgIGZ1bGxfdXJsLCB0b2tlbiwgdGltZW91dD1hcmdzLnRpbWVv"
    "dXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICBjdXJsX2Jsb2NrID0gX2Zvcm1hdF9jbWRfYmxvY2soY3VybF9yZXN1"
    "bHRbMF0sIGN1cmxfcmVzdWx0WzFdKSBpZiBjdXJsX3Jlc3VsdCBlbHNlICIiCgogICAgZm9yIGNpZCwgbmFtZSwgZXh0cmEg"
    "aW4gaWRzX2FuZF9uYW1lczoKICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgIkhUVFAgSG9zdCBIZWFkZXIgQXR0YWNrcyIs"
    "IG5hbWUsICJIaWdoIiBpZiBjaWQgIT0gIldBLUFEVi0yMjEiIGVsc2UgIkNyaXRpY2FsIiwgIlAxIiwKICAgICAgICAgICAg"
    "IkZBSUwiIGlmIHJlZmxlY3RlZCBlbHNlICJJTkZPIiwKICAgICAgICAgICAgKGJhc2VfZXZpZGVuY2UgKyAoIiBTZXJ2ZXIg"
    "dHJ1c3RzL3JlZmxlY3RzIGFuIGFyYml0cmFyeSBIb3N0IGhlYWRlciAtICIgKyBleHRyYSBpZiByZWZsZWN0ZWQgZWxzZQog"
    "ICAgICAgICAgICAgIiBCYXNpYyBzaW5nbGUtcmVxdWVzdCBwcm9iZSBkaWQgbm90IHNob3cgcmVmbGVjdGlvbiwgYnV0IHRo"
    "YXQgYWxvbmUgZG9lc24ndCBydWxlIHRoaXMgb3V0IC0gIiArIGV4dHJhKSkKICAgICAgICAgICAgKyBjdXJsX2Jsb2NrKQoK"
    "CiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0KIyBEcml2ZXIKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVmIHJlYWRfdXJsX2xpc3QocGF0aCk6CiAgICB1cmxzID0gW10KICAgIHdpdGggb3Bl"
    "bihwYXRoLCAiciIsIGVuY29kaW5nPSJ1dGYtOCIpIGFzIGY6CiAgICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAg"
    "bGluZSA9IGxpbmUuc3RyaXAoKQogICAgICAgICAgICBpZiBub3QgbGluZSBvciBsaW5lLnN0YXJ0c3dpdGgoIiMiKToKICAg"
    "ICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIHVybHMuYXBwZW5kKGxpbmUpCiAgICByZXR1cm4gdXJscwoKCiMg"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0KIyAtLWNyZWRzIC8gLS1jcmVkcy1maWxlIC0gYSBmcmllbmRsaWVyIHdheSB0byBoYW5kIHRoaXMgc2NyaXB0IGFjY291"
    "bnQgMS8yCiMgZm9yIGNoZWNrX2FjY2Vzc19jb250cm9sXzJmYSgpIHRoYW4gdHlwaW5nIC0tY29va2llLy0tY29va2llMiBi"
    "eSBoYW5kLgojCiMgU2luY2UgdGhpcyBzY3JpcHQgbmV2ZXIgbG9ncyBpbiAoc2VlIGJlbG93KSwgYSBwYXNzd29yZCBpcyBO"
    "T1QgbmVlZGVkIGFuZAojIGlzIE5PVCByZWFkIGZyb20gdGhlc2UgZW50cmllcyBhdCBhbGwgLSB0eXBpbmcgb25lIGlzIHdh"
    "c3RlZCBlZmZvcnQuCiMgVGhyZWUgZm9ybXMgYXJlIGFjY2VwdGVkIHBlciBsaW5lL2VudHJ5LCBpbiBvcmRlciBvZiB3aGF0"
    "J3MgY2hlY2tlZDoKIwojICAgMS4gImxhYmVsOjpjb29raWUiICAgICAgICAgICAgPC0gUkVDT01NRU5ERUQgLSBubyBwYXNz"
    "d29yZCwganVzdCBhCiMgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVhZGFibGUgbmFtZSBhbmQgdGhl"
    "IHNlc3Npb24gY29va2llCiMgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeW91IGFscmVhZHkgb2J0YWlu"
    "ZWQgYnkgbG9nZ2luZyBpbgojICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHlvdXJzZWxmIGFzIHRoYXQg"
    "dXNlci4KIyAgIDIuICJsYWJlbDpwYXNzd29yZDo6Y29va2llIiAgIDwtIGxlZ2FjeSBmb3JtLCBrZXB0IGZvciBjb21wYXRp"
    "YmlsaXR5LgojICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFdoYXRldmVyIGlzIHR5cGVkIGFzICJwYXNz"
    "d29yZCIgaXMKIyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXJzZWQgb3V0IGFuZCB0aHJvd24gYXdh"
    "eSB1bnJlYWQgLQojICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGl0IGlzIG5ldmVyIHN0b3JlZC9sb2dn"
    "ZWQvdXNlZC4KIyAgIDMuICJjb29raWVfbmFtZT12YWx1ZSIgICAgICAgIDwtIGJhcmUgY29va2llLCBubyBsYWJlbCBhdCBh"
    "bGwgKG5vICI6OiIsCiMgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnV0IGNvbnRhaW5zICI9IiBzbyBp"
    "dCdzIHJlY29nbmlzZWQKIyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhcyBhIHJhdyBDb29raWUgdmFs"
    "dWUsIGUuZy4gYSBsaW5lCiMgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhhdCdzIGp1c3QgIkpTRVNT"
    "SU9OSUQ9YWJjMTIzIikuCiMKIyBBIGxpbmUgd2l0aCBuZWl0aGVyICI6OiIgbm9yICI9IiAoanVzdCAibGFiZWwiIG9yICJs"
    "YWJlbDpwYXNzd29yZCIgYW5kCiMgbm90aGluZyBlbHNlKSBoYXMgbm8gY29va2llIHRvIHRlc3Qgd2l0aCBhbmQgaXMgcmVw"
    "b3J0ZWQgYXMgc2tpcHBlZC4KIwojIE11bHRpcGxlIGNvb2tpZSB2YWx1ZXMgZm9yIE9ORSBhY2NvdW50IChlLmcuIGEgc2Vz"
    "c2lvbiBjb29raWUgcGx1cyBhCiMgc2VwYXJhdGUgQ1NSRi9YU1JGIGNvb2tpZSkgZ28gb24gdGhlIFNBTUUgbGluZSBhcyBv"
    "bmUgQ29va2llLWhlYWRlcgojIHN0cmluZywgc2VtaWNvbG9uLXNlcGFyYXRlZCAtIGUuZy46CiMgICBhbGljZTo6SlNFU1NJ"
    "T05JRD1hYmMxMjM7IFhTUkYtVE9LRU49ZGVmNDU2CiMgKElmIHRoZSBzZWNvbmQgdmFsdWUgbXVzdCBiZSBzZW50IGFzIGl0"
    "cyBvd24gSFRUUCBoZWFkZXIgcmF0aGVyIHRoYW4gYQojIGNvb2tpZSAtIGUuZy4gYSBjdXN0b20gIlgtQ1NSRi1Ub2tlbjog"
    "Li4uIiBoZWFkZXIgLSB1c2UgLS1oZWFkZXIgaW5zdGVhZC8KIyBpbiBhZGRpdGlvbjsgLS1jb29raWUgb25seSBldmVyIGZp"
    "bGxzIGluIHRoZSBDb29raWUgaGVhZGVyLikKIwojIElNUE9SVEFOVCAtIHRoaXMgZG9lcyBOT1QgYWRkIGEgbG9naW4gZmxv"
    "dy4gVGhpcyBzY3JpcHQgc3RpbGwgbmV2ZXIgbG9ncwojIGluLCBicnV0ZS1mb3JjZXMsIG9yIGhhcnZlc3RzIGNyZWRlbnRp"
    "YWxzIGFueXdoZXJlIChzZWUgdGhlIG1vZHVsZQojIGRvY3N0cmluZykuIFRoZSBsYWJlbCBpcyB1c2VkIE9OTFkgYXMgYSBy"
    "ZWFkYWJsZSBuYW1lIGluIGV2aWRlbmNlIHRleHQKIyAoZS5nLiAiQWxpY2UiIGluc3RlYWQgb2YgIkFjY291bnQgMSIpLiBU"
    "aGUgb25seSB0aGluZyB0aGF0IGFjdHVhbGx5CiMgYXV0aGVudGljYXRlcyBhbnkgcmVxdWVzdCBpcyB0aGUgY29va2llIC0g"
    "aWYgYW4gZW50cnkgaGFzIG5vIGNvb2tpZSBhdAojIGFsbCwgdGhlcmUgaXMgbm90aGluZyB0aGlzIHNjcmlwdCBjYW4gdGVz"
    "dCB3aXRoIGZvciB0aGF0IGFjY291bnQgKG5vCiMgdXNlcm5hbWUvcGFzc3dvcmQgYWxvbmUgZXZlciBwcm9kdWNlcyBhIHdv"
    "cmtpbmcgc2Vzc2lvbiBoZXJlKSwgYW5kIGl0J3MKIyByZXBvcnRlZCBhcyBza2lwcGVkIHJhdGhlciB0aGFuIHNpbGVudGx5"
    "IGlnbm9yZWQuCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0KCmRlZiBfcGFyc2VfY3JlZHNfbGluZShsaW5lKToKICAgICIiIk9uZSBjcmVkZW50aWFsL2Nvb2tp"
    "ZSBlbnRyeSAtPiAobGFiZWwsIGNvb2tpZSkuIGNvb2tpZSBpcyBOb25lIHdoZW4KICAgIHRoZSBlbnRyeSBoYXMgbm8gdXNh"
    "YmxlIGNvb2tpZSB2YWx1ZS4gUmV0dXJucyBOb25lIGZvciBibGFuay9jb21tZW50CiAgICBsaW5lcy4gU2VlIHRoZSBibG9j"
    "ayBjb21tZW50IGFib3ZlIGZvciB0aGUgMyBhY2NlcHRlZCBmb3Jtcy4iIiIKICAgIGxpbmUgPSBsaW5lLnN0cmlwKCkKICAg"
    "IGlmIG5vdCBsaW5lIG9yIGxpbmUuc3RhcnRzd2l0aCgiIyIpOgogICAgICAgIHJldHVybiBOb25lCiAgICBpZiAiOjoiIGlu"
    "IGxpbmU6CiAgICAgICAgIyBGb3JtcyAxIGFuZCAyOiAibGFiZWw6OmNvb2tpZSIgb3IgImxhYmVsOnBhc3N3b3JkOjpjb29r"
    "aWUiLgogICAgICAgICMgV2hhdGV2ZXIgaXMgbGVmdCBvZiAiOjoiIGlzIG9ubHkgZXZlciB1c2VkIGFzIGEgZGlzcGxheSBs"
    "YWJlbCAtCiAgICAgICAgIyBpZiBpdCBpdHNlbGYgY29udGFpbnMgYSAiOiIgKHRoZSBsZWdhY3kgImxhYmVsOnBhc3N3b3Jk"
    "IiBmb3JtKSwKICAgICAgICAjIGV2ZXJ5dGhpbmcgYWZ0ZXIgdGhhdCBmaXJzdCAiOiIgaXMgYW4gdW5yZWFkLCBkaXNjYXJk"
    "ZWQgcGFzc3dvcmQuCiAgICAgICAgbGVmdF9wYXJ0LCBjb29raWVfcGFydCA9IGxpbmUuc3BsaXQoIjo6IiwgMSkKICAgICAg"
    "ICBsYWJlbCwgXywgX3VudXNlZF9wYXNzd29yZCA9IGxlZnRfcGFydC5wYXJ0aXRpb24oIjoiKQogICAgICAgICMgX3VudXNl"
    "ZF9wYXNzd29yZCBpcyBpbnRlbnRpb25hbGx5IHVucmVhZCBwYXN0IHRoaXMgbGluZSAtIHBhcnNlZAogICAgICAgICMgb3V0"
    "IGFuZCBkaXNjYXJkZWQgb24gcHVycG9zZSwgbmV2ZXIgc3RvcmVkL2xvZ2dlZC93cml0dGVuCiAgICAgICAgIyBhbnl3aGVy"
    "ZS4gTm8gcGFzc3dvcmQgaXMgcmVxdWlyZWQgaGVyZSBhdCBhbGwgKGZvcm0gMSkuCiAgICAgICAgbGFiZWwgPSBsYWJlbC5z"
    "dHJpcCgpIG9yIE5vbmUKICAgICAgICBjb29raWUgPSBjb29raWVfcGFydC5zdHJpcCgpIG9yIE5vbmUKICAgICAgICByZXR1"
    "cm4gKGxhYmVsLCBjb29raWUpCiAgICBpZiAiPSIgaW4gbGluZToKICAgICAgICAjIEZvcm0gMzogbm8gIjo6IiBtYXJrZXIs"
    "IGJ1dCB0aGlzIGxvb2tzIGxpa2UgYSByYXcgQ29va2llIGhlYWRlcgogICAgICAgICMgdmFsdWUgKG5hbWU9dmFsdWUpIHJh"
    "dGhlciB0aGFuIGEgImxhYmVsWzpwYXNzd29yZF0iIHBsYWNlaG9sZGVyIC0KICAgICAgICAjIHVzZSB0aGUgd2hvbGUgbGlu"
    "ZSBkaXJlY3RseSBhcyB0aGUgY29va2llLCB3aXRoIG5vIGxhYmVsLgogICAgICAgIHJldHVybiAoTm9uZSwgbGluZSkKICAg"
    "ICMgTm8gIjo6IiBhbmQgbm8gIj0iIC0ganVzdCBhIGJhcmUgbGFiZWwgb3IgImxhYmVsOnBhc3N3b3JkIiB3aXRoCiAgICAj"
    "IG5vdGhpbmcgdXNhYmxlIGFzIGEgY29va2llIHlldC4KICAgIHVzZXJpZCwgXywgX3VudXNlZF9wYXNzd29yZCA9IGxpbmUu"
    "cGFydGl0aW9uKCI6IikKICAgIGxhYmVsID0gdXNlcmlkLnN0cmlwKCkgb3IgTm9uZQogICAgcmV0dXJuIChsYWJlbCwgTm9u"
    "ZSkKCgpkZWYgbG9hZF9jcmVkc19lbnRyaWVzKGFyZ3MpOgogICAgIiIiQ29sbGVjdHMgdXAgdG8gMiAobGFiZWwsIGNvb2tp"
    "ZSkgYWNjb3VudCBlbnRyaWVzIGZyb20gLS1jcmVkcy1maWxlCiAgICAob25lIGVudHJ5IHBlciBub24tY29tbWVudC9ub24t"
    "YmxhbmsgbGluZSAtIGxpbmUgMSA9IGFjY291bnQgMSwgbGluZSAyCiAgICA9IGFjY291bnQgMiwgYSBmaWxlIHdpdGggb25s"
    "eSBvbmUgbGluZSBtZWFucyBhIHNpbmdsZSBhY2NvdW50KSBhbmQvb3IKICAgIC0tY3JlZHMgKHJlcGVhdGFibGUsIHNhbWUg"
    "J3VzZXJJRDpwYXNzd29yZFs6OmNvb2tpZV0nIGZvcm1hdCwgYXBwZW5kZWQKICAgIGFmdGVyIGFueSAtLWNyZWRzLWZpbGUg"
    "ZW50cmllcykuIE1vcmUgdGhhbiAyIGVudHJpZXMgdG90YWwgaXMgdHJpbW1lZAogICAgdG8gMiB3aXRoIGEgd2FybmluZyAt"
    "IHRoaXMgc2NyaXB0IG9ubHkgZXZlciBjb21wYXJlcyB0d28gYWNjb3VudHMuIiIiCiAgICBlbnRyaWVzID0gW10KICAgIGlm"
    "IGdldGF0dHIoYXJncywgImNyZWRzX2ZpbGUiLCBOb25lKToKICAgICAgICB3aXRoIG9wZW4oYXJncy5jcmVkc19maWxlLCAi"
    "ciIsIGVuY29kaW5nPSJ1dGYtOC1zaWciKSBhcyBmOgogICAgICAgICAgICBmb3IgbGluZSBpbiBmOgogICAgICAgICAgICAg"
    "ICAgcGFyc2VkID0gX3BhcnNlX2NyZWRzX2xpbmUobGluZSkKICAgICAgICAgICAgICAgIGlmIHBhcnNlZDoKICAgICAgICAg"
    "ICAgICAgICAgICBlbnRyaWVzLmFwcGVuZChwYXJzZWQpCiAgICBpZiBnZXRhdHRyKGFyZ3MsICJjcmVkcyIsIE5vbmUpOgog"
    "ICAgICAgIGZvciBjIGluIGFyZ3MuY3JlZHM6CiAgICAgICAgICAgIHBhcnNlZCA9IF9wYXJzZV9jcmVkc19saW5lKGMpCiAg"
    "ICAgICAgICAgIGlmIHBhcnNlZDoKICAgICAgICAgICAgICAgIGVudHJpZXMuYXBwZW5kKHBhcnNlZCkKICAgIGlmIGxlbihl"
    "bnRyaWVzKSA+IDI6CiAgICAgICAgcHJpbnQoZiJbIV0ge2xlbihlbnRyaWVzKX0gY3JlZGVudGlhbCBlbnRyaWVzIGdpdmVu"
    "IChmcm9tIC0tY3JlZHMtZmlsZS8tLWNyZWRzIGNvbWJpbmVkKSAtIG9ubHkgdXNpbmcgIgogICAgICAgICAgICAgIGYidGhl"
    "IGZpcnN0IDI7IHRoaXMgc2NyaXB0IG9ubHkgZXZlciBjb21wYXJlcyBhIHR3by1hY2NvdW50IHBhaXIuIiwgZmlsZT1zeXMu"
    "c3RkZXJyKQogICAgICAgIGVudHJpZXMgPSBlbnRyaWVzWzoyXQogICAgcmV0dXJuIGVudHJpZXMKCgpkZWYgYXBwbHlfY3Jl"
    "ZHNfZW50cmllcyhhcmdzKToKICAgICIiIkFwcGxpZXMgbG9hZF9jcmVkc19lbnRyaWVzKCkgcmVzdWx0cyBvbnRvIGFyZ3Mu"
    "Y29va2llL2FyZ3MuY29va2llMi8KICAgIGFyZ3MuYWNjb3VudDFfbGFiZWwvYXJncy5hY2NvdW50Ml9sYWJlbCwgV0lUSE9V"
    "VCBvdmVyd3JpdGluZyBhbnl0aGluZwogICAgdGhlIG9wZXJhdG9yIGFscmVhZHkgc2V0IGV4cGxpY2l0bHkgdmlhIC0tY29v"
    "a2llLy0tY29va2llMi8KICAgIC0tYWNjb3VudDEtbGFiZWwvLS1hY2NvdW50Mi1sYWJlbCBkaXJlY3RseSAtIGV4cGxpY2l0"
    "IGZsYWdzIGFsd2F5cwogICAgd2luLiBDYWxsIHRoaXMgYmVmb3JlIHRoZSAtLWNvb2tpZS8tLWNvb2tpZTIgLT4gYWNjb3Vu"
    "dDFfY29va2llLwogICAgYWNjb3VudDJfY29va2llIGRlcml2YXRpb24gaW4gbWFpbigpIHNvIHRoZSB0d28gZmVhdHVyZXMg"
    "Y29tcG9zZS4iIiIKICAgIGVudHJpZXMgPSBsb2FkX2NyZWRzX2VudHJpZXMoYXJncykKICAgIGZvciBpLCAobGFiZWwsIGNv"
    "b2tpZSkgaW4gZW51bWVyYXRlKGVudHJpZXMpOgogICAgICAgIHNsb3QgPSAxIGlmIGkgPT0gMCBlbHNlIDIKICAgICAgICB3"
    "aG8gPSBsYWJlbCBvciAoImFjY291bnQgMSIgaWYgc2xvdCA9PSAxIGVsc2UgImFjY291bnQgMiIpCiAgICAgICAgaWYgbm90"
    "IGNvb2tpZToKICAgICAgICAgICAgcHJpbnQoZiJbIV0gQ3JlZGVudGlhbCBlbnRyeSB7aSArIDF9ICh7d2hvfSkgaGFzIG5v"
    "IGNvb2tpZSB2YWx1ZSAtIHRoaXMgc2NyaXB0IG5ldmVyIGxvZ3MgaW4gd2l0aCBhICIKICAgICAgICAgICAgICAgICAgZiJ1"
    "c2VybmFtZS9wYXNzd29yZCAobm8gcGFzc3dvcmQgbmVlZGVkIGF0IGFsbCAtIGRvbid0IGJvdGhlciB0eXBpbmcgb25lKSwg"
    "c28gdGhlcmUncyBub3RoaW5nICIKICAgICAgICAgICAgICAgICAgZiJ0byB0ZXN0IHdpdGggZm9yIHRoaXMgYWNjb3VudC4g"
    "QWRkICc6OnNlc3Npb25pZD0uLi4nIGFmdGVyIHRoZSBsYWJlbCBvbiB0aGF0IGxpbmUvZW50cnkgKGEgIgogICAgICAgICAg"
    "ICAgICAgICBmInNlc3Npb24gY29va2llIFlPVSBhbHJlYWR5IG9idGFpbmVkIGJ5IGxvZ2dpbmcgaW4geW91cnNlbGYgYXMg"
    "e3dob30pIHRvIGFjdHVhbGx5IHVzZSBpdC4iLAogICAgICAgICAgICAgICAgICBmaWxlPXN5cy5zdGRlcnIpCiAgICAgICAg"
    "ICAgIGNvbnRpbnVlCiAgICAgICAgaWYgc2xvdCA9PSAxOgogICAgICAgICAgICBpZiBub3QgYXJncy5jb29raWU6CiAgICAg"
    "ICAgICAgICAgICBhcmdzLmNvb2tpZSA9IGNvb2tpZQogICAgICAgICAgICBpZiBsYWJlbCBhbmQgbm90IGFyZ3MuYWNjb3Vu"
    "dDFfbGFiZWw6CiAgICAgICAgICAgICAgICBhcmdzLmFjY291bnQxX2xhYmVsID0gbGFiZWwKICAgICAgICBlbHNlOgogICAg"
    "ICAgICAgICBpZiBub3QgYXJncy5jb29raWUyOgogICAgICAgICAgICAgICAgYXJncy5jb29raWUyID0gY29va2llCiAgICAg"
    "ICAgICAgIGlmIGxhYmVsIGFuZCBub3QgYXJncy5hY2NvdW50Ml9sYWJlbDoKICAgICAgICAgICAgICAgIGFyZ3MuYWNjb3Vu"
    "dDJfbGFiZWwgPSBsYWJlbAoKCmRlZiBub3JtYWxpemVfdXJsKHUpOgogICAgaWYgbm90IHJlLm1hdGNoKHIiXmh0dHBzPzov"
    "LyIsIHUsIHJlLkkpOgogICAgICAgIHUgPSAiaHR0cHM6Ly8iICsgdQogICAgcmV0dXJuIHUKCgpkZWYgcnVuX2Z1bGxfc3Vp"
    "dGUodGFyZ2V0X3VybCwgYXJncyk6CiAgICAiIiJSdW5zIGV2ZXJ5IGF1dG9tYXRlZCBjaGVjayBhZ2FpbnN0IGV4YWN0bHkg"
    "b25lIFVSTCAoZWl0aGVyIHRoZQogICAgZ2l2ZW4tdXJsIHBhc3Mgb3IgdGhlIHNpdGUtcm9vdCBwYXNzIC0gdGhlIGNhbGxl"
    "ciBoYXMgYWxyZWFkeSBzZXQKICAgIENUWCBzbyBldmVyeSBhZGQoKSBjYWxsIGJlbG93IHRhZ3MgaXRzZWxmIGNvcnJlY3Rs"
    "eSkuIiIiCiAgICBoZWFkZXJzX3Jlc3VsdCwgaGRyX2N1cmxfYmxvY2sgPSBjaGVja19zZWN1cml0eV9oZWFkZXJzKHRhcmdl"
    "dF91cmwsIGFyZ3MpCiAgICBjaGVja190bHModGFyZ2V0X3VybCwgYXJncykKICAgIGNoZWNrX2NsaWNramFja2luZyh0YXJn"
    "ZXRfdXJsLCBoZWFkZXJzX3Jlc3VsdCkKICAgIGNoZWNrX2NvcnModGFyZ2V0X3VybCwgYXJncykKICAgIGNoZWNrX2luZm9y"
    "bWF0aW9uX2dhdGhlcmluZyh0YXJnZXRfdXJsLCBoZWFkZXJzX3Jlc3VsdCwgYXJncykKICAgIGNoZWNrX2NvbmZpZ3VyYXRp"
    "b24odGFyZ2V0X3VybCwgaGVhZGVyc19yZXN1bHQsIGhkcl9jdXJsX2Jsb2NrLCBhcmdzKQogICAgY2hlY2tfc2Vzc2lvbl9t"
    "YW5hZ2VtZW50KHRhcmdldF91cmwsIGhlYWRlcnNfcmVzdWx0LCBhcmdzKQogICAgY2hlY2tfY2xpZW50X3N0b3JhZ2UodGFy"
    "Z2V0X3VybCwgaGVhZGVyc19yZXN1bHQsIGFyZ3MpCiAgICBjaGVja19lbWFpbF9zZWN1cml0eSh0YXJnZXRfdXJsLCBhcmdz"
    "KQoKICAgIGhkcjQwMCA9IG5leHQoKHJbImV2aWRlbmNlIl0gZm9yIHIgaW4gUkVTVUxUUyBpZiByWyJpZCJdID09ICJXQS1I"
    "RFItNDAwIiBhbmQgclsidXJsIl0gPT0gdGFyZ2V0X3VybCksICIiKQogICAgaGRyNDAxID0gbmV4dCgoclsiZXZpZGVuY2Ui"
    "XSBmb3IgciBpbiBSRVNVTFRTIGlmIHJbImlkIl0gPT0gIldBLUhEUi00MDEiIGFuZCByWyJ1cmwiXSA9PSB0YXJnZXRfdXJs"
    "KSwgIiIpCiAgICBvdGcyODYgPSBuZXh0KChyWyJldmlkZW5jZSJdIGZvciByIGluIFJFU1VMVFMgaWYgclsiaWQiXSA9PSAi"
    "V0EtT1RHLTI4NiIgYW5kIHJbInVybCJdID09IHRhcmdldF91cmwpLCAiIikKICAgIGNoZWNrX2luZm9ybWF0aW9uX2Rpc2Ns"
    "b3N1cmUodGFyZ2V0X3VybCwgaGVhZGVyc19yZXN1bHQsIGFyZ3MsIGhkcjQwMCwgaGRyNDAxLCBvdGcyODYpCiAgICBjaGVj"
    "a19ob3N0X2hlYWRlcih0YXJnZXRfdXJsLCBhcmdzKQogICAgY2hlY2tfYWNjZXNzX2NvbnRyb2xfMmZhKHRhcmdldF91cmws"
    "IGFyZ3MpCgoKZGVmIHNjYW5fdXJsKHJhd191cmwsIGFyZ3MpOgogICAgIiIiRXZlcnkgVVJMIC0gd2hldGhlciBnaXZlbiB2"
    "aWEgLS11cmwgb3IgcmVhZCBmcm9tIC0tdXJsLWZpbGUgLSBnb2VzCiAgICB0aHJvdWdoIGV4YWN0bHkgdGhpcyBzYW1lIHBh"
    "dGgsIHNvIGEgYmF0Y2ggb2YgbWFudWFsbHkgY3VyYXRlZCBVUkxzIGluCiAgICBhIGZpbGUgaXMgY2FwdHVyZWQgaWRlbnRp"
    "Y2FsbHkgdG8gYSBzaW5nbGUgLS11cmwgcnVuOiBlYWNoIG9uZSBnZXRzCiAgICBpdHMgb3duIGdpdmVuLXVybCBwYXNzLCBh"
    "bmQgKHVubGVzcyAtLXNraXAtcm9vdC1wYXNzKSBpdHMgb3duCiAgICBhdXRvbWF0aWMgc2l0ZS1yb290IHBhc3MgdG9vLiIi"
    "IgogICAgZnVsbF91cmwgPSBub3JtYWxpemVfdXJsKHJhd191cmwpCiAgICByb290X3VybCA9IGJhc2VfdXJsX29mKGZ1bGxf"
    "dXJsKQogICAgc2FtZV9hc19yb290ID0gcm9vdF91cmwucnN0cmlwKCIvIikgPT0gZnVsbF91cmwucnN0cmlwKCIvIikKCiAg"
    "ICB0YXJnZXRzID0gWyhmdWxsX3VybCwgImdpdmVuLXVybCAoc2l0ZSByb290KSIgaWYgc2FtZV9hc19yb290IGVsc2UgImdp"
    "dmVuLXVybCIpXQogICAgaWYgbm90IHNhbWVfYXNfcm9vdCBhbmQgbm90IGFyZ3Muc2tpcF9yb290X3Bhc3M6CiAgICAgICAg"
    "dGFyZ2V0cy5hcHBlbmQoKHJvb3RfdXJsLCAic2l0ZS1yb290IikpCgogICAgZm9yIHRhcmdldF91cmwsIHJvbGUgaW4gdGFy"
    "Z2V0czoKICAgICAgICBDVFhbInNvdXJjZV9pbnB1dCJdID0gcmF3X3VybAogICAgICAgIENUWFsidXJsX3JvbGUiXSA9IHJv"
    "bGUKICAgICAgICBwcmludChmIlxuWypdIFRlc3Rpbmcge3RhcmdldF91cmx9ICAgKHJvbGU6IHtyb2xlfTsgZnJvbSBpbnB1"
    "dDoge3Jhd191cmx9KSIpCiAgICAgICAgcnVuX2Z1bGxfc3VpdGUodGFyZ2V0X3VybCwgYXJncykKICAgICAgICBpZiBhcmdz"
    "LmRlbGF5OgogICAgICAgICAgICB0aW1lLnNsZWVwKGFyZ3MuZGVsYXkpCgoKT1VUUFVUX0ZJRUxEUyA9IFsic291cmNlX2lu"
    "cHV0IiwgInVybF9yb2xlIiwgInVybCIsICJpZCIsICJjYXRlZ29yeSIsICJ0ZXN0IiwKICAgICAgICAgICAgICAgICAgInNl"
    "dmVyaXR5IiwgInByaW9yaXR5IiwgInJlc3VsdCIsICJldmlkZW5jZSIsICJjaGVja2VkX2F0Il0KQ1NWX0ZJRUxEUyA9IE9V"
    "VFBVVF9GSUVMRFMgKyBbInNjcmVlbnNob3QiXQoKIyBXb3JzdC1jYXNlIHdpbnMgd2hlbiB0aGUgc2FtZSBjaGVja2xpc3Qg"
    "SUQgd2FzIHRlc3RlZCBhZ2FpbnN0IG1vcmUgdGhhbgojIG9uZSBVUkwvcm9sZSAodGhlIGRlZmF1bHQgZHVhbC1wYXNzLCBv"
    "ciBhIC0tdXJsLWZpbGUgYmF0Y2gpIC0gbWF0Y2hlcwojIHRoZSBzYW1lIHJhbmtpbmcgdXRpbHNfYXV0b3NjYW5faW1wb3J0"
    "LnB5IHVzZXMgb24gdGhlIERqYW5nbyBpbXBvcnQgc2lkZSwKIyBzbyAid2hhdCBkb2VzIHRoZSBwb3J0YWwgZW5kIHVwIG1h"
    "cmtpbmciIGFuZCAid2hhdCBkb2VzIHRoaXMgcmVwb3J0IHNob3cKIyBhcyB0aGUgb3ZlcmFsbCByZXN1bHQiIGFsd2F5cyBh"
    "Z3JlZS4KUkVTVUxUX1BSSU9SSVRZID0geyJGQUlMIjogNSwgIkVSUk9SIjogNCwgIk1BTlVBTCI6IDMsICJJTkZPIjogMiwg"
    "IlBBU1MiOiAxfQpDT05TT0xJREFURURfRklFTERTID0gWyJpZCIsICJjYXRlZ29yeSIsICJ0ZXN0IiwgInNldmVyaXR5Iiwg"
    "InByaW9yaXR5IiwgInJlc3VsdCIsCiAgICAgICAgICAgICAgICAgICAgICAgICJhZmZlY3RlZF91cmxfY291bnQiLCAiYWZm"
    "ZWN0ZWRfdXJscyIsICJ0b3RhbF91cmxzX3Rlc3RlZCIsICJldmlkZW5jZSIsCiAgICAgICAgICAgICAgICAgICAgICAgICJz"
    "Y3JlZW5zaG90X2NvdW50Il0KCgpkZWYgY29uc29saWRhdGVfYnlfaWQoKToKICAgICIiIkdyb3VwcyBldmVyeSByZXN1bHQg"
    "cm93IGJ5IGNoZWNrbGlzdCBJRCBhY3Jvc3MgQUxMIGlucHV0IFVSTHMgYW5kCiAgICBBTEwgVVJMK3JvbGUgcGFzc2VzIChn"
    "aXZlbi11cmwgKyBzaXRlLXJvb3QsIGFuZCBldmVyeSBVUkwgaW4gYQogICAgLS11cmwtZmlsZSBiYXRjaCkgaW50byBPTkUg"
    "cm93IHBlciBJRCwgd2l0aCBldmVyeSBVUkwgdGhhdCBoaXQgdGhlCiAgICB3b3JzdC1jYXNlIHJlc3VsdCBjb21iaW5lZCBp"
    "bnRvIGEgc2luZ2xlIGNlbGwuIFJlcXVlc3RlZCBkaXJlY3RseToKICAgICJzYW1lIGZpbmRpZ25zIElEIFdBLUhEUi0zOTIg"
    "cmVwb3J0ZWQgb24gPHVybDE+IGFuZCA8dXJsMj4gLi4uIHJlcG9ydAogICAgb25lIElEIGF0IG9uY2UsIGNsdWIgYWxsIHRo"
    "ZSB2dWxuZXJhYmxlIFVSTHMgaW4gb25lIGNlbGxzIGV2ZW4gZm9yCiAgICBtdWx0aXBsZSBVUkxzIGkgcGFzdGVkIHdpbiBV"
    "UkwgdGV4dCBmaWxlLiIgRG9lcyBOT1QgcmVwbGFjZSB0aGUKICAgIGdyYW51bGFyIHBlci1VUkwgSlNPTiAoc3RpbGwgbmVl"
    "ZGVkIGZvciB0aGUgRGphbmdvIGltcG9ydCBmZWF0dXJlIGFuZAogICAgZXh0cmFjdF9ldmlkZW5jZV9pbWFnZXMucHkpIC0g"
    "dGhpcyBpcyBhbiBhZGRpdGlvbmFsIHJvbGxlZC11cCB2aWV3IGZvcgogICAgdGhlIENTVi9YTFNYIHNpZGUuIiIiCiAgICBi"
    "eV9pZCA9IHt9CiAgICBmb3Igcm93IGluIFJFU1VMVFM6CiAgICAgICAgYnlfaWQuc2V0ZGVmYXVsdChyb3dbImlkIl0sIFtd"
    "KS5hcHBlbmQocm93KQoKICAgIGNvbnNvbGlkYXRlZCA9IFtdCiAgICBmb3IgY2lkLCByb3dzIGluIHNvcnRlZChieV9pZC5p"
    "dGVtcygpKToKICAgICAgICB3b3JzdCA9IG1heChyb3dzLCBrZXk9bGFtYmRhIHI6IFJFU1VMVF9QUklPUklUWS5nZXQoclsi"
    "cmVzdWx0Il0sIDApKQogICAgICAgIHdvcnN0X3Jlc3VsdCA9IHdvcnN0WyJyZXN1bHQiXQoKICAgICAgICAjIE11bHRpcGxl"
    "IGFmZmVjdGVkIFVSTHMgY2FuIGVhY2ggY2FycnkgdGhlaXIgT1dOIHNjcmVlbnNob3QKICAgICAgICAjICgtLXNjcmVlbnNo"
    "b3QgZmFpbC9hbGwgZ2VuZXJhdGVzIG9uZSBwZXIgcXVhbGlmeWluZyByb3cpIC0KICAgICAgICAjIHJlcXVlc3RlZCBkaXJl"
    "Y3RseTogInNjcmVlbnNob3Qgc2hvdWxkIGJlIG11bHRpcGxlIG91dHB1dCB3aWxsCiAgICAgICAgIyBiZSBtdWx0aXBsZSBz"
    "byBhZGQgaW1hZ2UgMSBpbWFnZSBmb3IgaW1hZ2UgYmFzZSBjb2RlIiAtIGV2ZXJ5CiAgICAgICAgIyBVUkwncyBpbWFnZSAo"
    "aWYgaXQgaGFzIG9uZSkgaXMga2VwdCwgbnVtYmVyZWQgaW4gdGhlIHNhbWUgb3JkZXIKICAgICAgICAjIGFzIHVybF9yZXN1"
    "bHRzLCBpbnN0ZWFkIG9mIG9ubHkgdGhlIGZpcnN0IFVSTCdzLgogICAgICAgICMKICAgICAgICAjIFRoZSBTQU1FIGFwcGxp"
    "ZXMgdG8gZXZpZGVuY2UgdGV4dCwgZml4ZWQgYWZ0ZXIgYmVpbmcgcmVwb3J0ZWQKICAgICAgICAjIGRpcmVjdGx5OiAiZm9y"
    "IG91dCBwdXQgaW4gZWlkYWNlIGkgbWEgc3NzZWV0aW5nIG9ubHkgdGhlCiAgICAgICAgIyBtZXNzYWdlIG5vdCBhY3R1YWwg"
    "b3V0cHV0IGZvciBvbiB0YXJnZXQgd2hlbmkgcGFzcyBtdWx0aXBsZQogICAgICAgICMgdXJscyBpdCBnaXZlIGdlbnJpYyBt"
    "ZXNzYWdlIG5vdCBzaG93aW5nIHdoYXQgZXhhY3RseSBoYXBwZW5kCiAgICAgICAgIyBmb3IgZWFjaCB1cmwuIiBQcmV2aW91"
    "c2x5IHRoaXMgcm93J3MgImV2aWRlbmNlIiBmaWVsZCB3YXMganVzdAogICAgICAgICMgd29yc3RbImV2aWRlbmNlIl0gLSBP"
    "TkUgcm93J3MgdGV4dCAod2hpY2hldmVyIHRoZSBzYW1lLXByaW9yaXR5CiAgICAgICAgIyB0aWUtYnJlYWsgaGFwcGVuZWQg"
    "dG8gbGFuZCBvbikgLSBldmVuIHRob3VnaCBzZXZlcmFsIGRpZmZlcmVudAogICAgICAgICMgVVJMcyBjb3VsZCBiZSBpbnZv"
    "bHZlZCwgZWFjaCBvZiB3aGljaCByYW4gaXRzIE9XTiByZXF1ZXN0IGFuZAogICAgICAgICMgZ290IGl0cyBPV04gcmVhbCBv"
    "dXRwdXQgKGRpZmZlcmVudCBjdXJsL25tYXAgb3V0cHV0LCBzdGF0dXMKICAgICAgICAjIGNvZGVzLCBldGMuIHBlciBVUkwp"
    "LiBOb3cgZXZlcnkgVVJMJ3Mgb3duIGV2aWRlbmNlIGlzIGtlcHQgYW5kCiAgICAgICAgIyBzaG93biBsYWJlbGxlZCBieSBV"
    "UkwsIHNvIG5vdGhpbmcgaXMgZ2VuZXJpY2l6ZWQgYXdheS4KICAgICAgICAjCiAgICAgICAgIyBBbmQgRVZFUlkgdGVzdGVk"
    "IFVSTCAtIG5vdCBqdXN0IHRoZSBvbmVzIG1hdGNoaW5nIHRoZSB3b3JzdAogICAgICAgICMgcmVzdWx0IC0gaXMgbm93IGxp"
    "c3RlZCB3aXRoIGl0cyBPV04gcGVyLVVSTCByZXN1bHQsIGZpeGVkIGFmdGVyCiAgICAgICAgIyBiZWluZyByZXBvcnRlZCBk"
    "aXJlY3RseTogImlmIGFueSB1cmwgcGFzc2VkIHlvdSBjYW4gbWVudGlvbmUKICAgICAgICAjIDEyNy4wLjAuMTpQQVNTRUQg"
    "aWYgb25lc2VydmVyIGZhaWxlZCB1bmRlciB0aGUgdnVsbmVyYWJpbGl0eQogICAgICAgICMgdGl0dGxlIG1hciB0aGUgc3Rh"
    "dHVzIGFzIGZhaWxlZCBuZCBnaXZlIHRoZSBvdXRwdXQgYWZmZWN0ZWQKICAgICAgICAjIHVybHMgdGVsbCBjcmVhZWx5IHdo"
    "aWNoIHVybCBpcyBwYXNzZWQgd2hpY2ggaXMgZmFpbGVkLiIKICAgICAgICAjIFByZXZpb3VzbHkgIkFmZmVjdGVkIFVSTChz"
    "KSIgb25seSBsaXN0ZWQgdGhlIFVSTChzKSB0aGF0IGhpdAogICAgICAgICMgdGhlIHdvcnN0LWNhc2UgcmVzdWx0IC0gaWYg"
    "VVJMIEEgcGFzc2VkIGFuZCBVUkwgQiBmYWlsZWQsIG9ubHkKICAgICAgICAjIEIgYXBwZWFyZWQsIHdpdGggbm8gd2F5IHRv"
    "IHRlbGwgQSB3YXMgZXZlbiB0ZXN0ZWQsIGxldCBhbG9uZQogICAgICAgICMgdGhhdCBpdCBwYXNzZWQuIFRoZSBvdmVyYWxs"
    "ICJyZXN1bHQiIGZvciB0aGUgSUQgaXMgVU5DSEFOR0VEIC0KICAgICAgICAjIHN0aWxsIHdvcnN0LWNhc2Utd2lucyAoYSBG"
    "QUlMIG9uIGFueSBVUkwgc3RpbGwgcmVwb3J0cyB0aGUgSUQKICAgICAgICAjIGFzIEZBSUwgb3ZlcmFsbCkgLSBidXQgdXJs"
    "X3Jlc3VsdHMvYWZmZWN0ZWRfdXJscyBub3cgc2hvd3MKICAgICAgICAjIEVWRVJZIHRlc3RlZCBVUkwgd2l0aCBpdHMgb3du"
    "IFBBU1MvRkFJTC9ldGMuIGV4cGxpY2l0bHksIHNvCiAgICAgICAgIyBpdCdzIG5ldmVyIGFtYmlndW91cyB3aGljaCBVUkwo"
    "cykgYWN0dWFsbHkgZmFpbGVkIHZzLiB3aGljaAogICAgICAgICMgcGFzc2VkLgogICAgICAgIHNlZW4gPSBzZXQoKQogICAg"
    "ICAgIHVybF9yZXN1bHRzID0gW10KICAgICAgICBzY3JlZW5zaG90cyA9IFtdCiAgICAgICAgZm9yIHIgaW4gcm93czoKICAg"
    "ICAgICAgICAga2V5ID0gKHJbInVybCJdLCByWyJ1cmxfcm9sZSJdKQogICAgICAgICAgICBpZiBrZXkgaW4gc2VlbjoKICAg"
    "ICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIHNlZW4uYWRkKGtleSkKICAgICAgICAgICAgdXJsX3Jlc3VsdHMu"
    "YXBwZW5kKHsKICAgICAgICAgICAgICAgICJpbmRleCI6IGxlbih1cmxfcmVzdWx0cykgKyAxLCAgIyBtYXRjaGVzIHRoaXMg"
    "VVJMJ3MgMS1iYXNlZCBwb3NpdGlvbiBpbiB1cmxfcmVzdWx0cwogICAgICAgICAgICAgICAgInVybCI6IHJbInVybCJdLCAi"
    "dXJsX3JvbGUiOiByWyJ1cmxfcm9sZSJdLAogICAgICAgICAgICAgICAgInJlc3VsdCI6IHJbInJlc3VsdCJdLAogICAgICAg"
    "ICAgICAgICAgImV2aWRlbmNlIjogclsiZXZpZGVuY2UiXSwKICAgICAgICAgICAgfSkKICAgICAgICAgICAgaWYgci5nZXQo"
    "ImV2aWRlbmNlX2ltYWdlX2Jhc2U2NCIpOgogICAgICAgICAgICAgICAgc2NyZWVuc2hvdHMuYXBwZW5kKHsKICAgICAgICAg"
    "ICAgICAgICAgICAiaW5kZXgiOiBsZW4odXJsX3Jlc3VsdHMpLCAgIyBtYXRjaGVzIHRoaXMgVVJMJ3MgMS1iYXNlZCBwb3Np"
    "dGlvbiBpbiB1cmxfcmVzdWx0cwogICAgICAgICAgICAgICAgICAgICJ1cmwiOiByWyJ1cmwiXSwgInVybF9yb2xlIjogclsi"
    "dXJsX3JvbGUiXSwKICAgICAgICAgICAgICAgICAgICAiaW1hZ2VfYmFzZTY0IjogclsiZXZpZGVuY2VfaW1hZ2VfYmFzZTY0"
    "Il0sCiAgICAgICAgICAgICAgICB9KQoKICAgICAgICB0b3RhbF91cmxzID0gbGVuKHVybF9yZXN1bHRzKQogICAgICAgIGFm"
    "ZmVjdGVkX3VybF9jb3VudCA9IHN1bSgxIGZvciB1IGluIHVybF9yZXN1bHRzIGlmIHVbInJlc3VsdCJdID09IHdvcnN0X3Jl"
    "c3VsdCkKCiAgICAgICAgIyAiQWZmZWN0ZWQgVVJMKHMpIiB0ZXh0IG5vdyBzaG93cyBFVkVSWSB0ZXN0ZWQgVVJMIHdpdGgg"
    "aXRzIG93bgogICAgICAgICMgcmVzdWx0IGFwcGVuZGVkIChlLmcuICJodHRwczovL2EuZXhhbXBsZS8gKGdpdmVuLXVybCkg"
    "LSBGQUlMIiksCiAgICAgICAgIyBub3QganVzdCB0aGUgb25lcyBtYXRjaGluZyB0aGUgd29yc3QtY2FzZSByZXN1bHQuCiAg"
    "ICAgICAgYWZmZWN0ZWRfdXJsc19saW5lcyA9IFtmInt1Wyd1cmwnXX0gKHt1Wyd1cmxfcm9sZSddfSkgLSB7dVsncmVzdWx0"
    "J119IiBmb3IgdSBpbiB1cmxfcmVzdWx0c10KCiAgICAgICAgd29yc3RfbWF0Y2hpbmcgPSBbdSBmb3IgdSBpbiB1cmxfcmVz"
    "dWx0cyBpZiB1WyJyZXN1bHQiXSA9PSB3b3JzdF9yZXN1bHRdCiAgICAgICAgaWYgbGVuKHdvcnN0X21hdGNoaW5nKSA+IDE6"
    "CiAgICAgICAgICAgICMgTW9yZSB0aGFuIG9uZSBVUkwgaGl0IHRoZSB3b3JzdC1jYXNlIHJlc3VsdCAtIGxhYmVsIGVhY2gK"
    "ICAgICAgICAgICAgIyBvbmUncyBvd24gZXZpZGVuY2Ugc28gaXQncyBjbGVhciB3aGljaCBvdXRwdXQgY2FtZSBmcm9tCiAg"
    "ICAgICAgICAgICMgd2hpY2ggdGFyZ2V0LCBpbnN0ZWFkIG9mIGNvbGxhcHNpbmcgdG8gYSBzaW5nbGUgcm93J3MgdGV4dC4K"
    "ICAgICAgICAgICAgY29tYmluZWRfZXZpZGVuY2UgPSAiXG5cbiIuam9pbigKICAgICAgICAgICAgICAgIGYiW3t1Wyd1cmxf"
    "cm9sZSddfToge3VbJ3VybCddfV1cbnt1WydldmlkZW5jZSddfSIgZm9yIHUgaW4gd29yc3RfbWF0Y2hpbmcpCiAgICAgICAg"
    "ZWxzZToKICAgICAgICAgICAgIyBFeGFjdGx5IG9uZSBVUkwgaGl0IHRoZSB3b3JzdC1jYXNlIHJlc3VsdCAodGhlIGNvbW1v"
    "biBjYXNlKQogICAgICAgICAgICAjIC0gbm8gbmVlZCBmb3IgYSAiW3VybF0iIGxhYmVsIG9uIGEgc2luZ2xlIGJsb2NrLgog"
    "ICAgICAgICAgICBjb21iaW5lZF9ldmlkZW5jZSA9IHdvcnN0WyJldmlkZW5jZSJdCgogICAgICAgIGNvbnNvbGlkYXRlZC5h"
    "cHBlbmQoewogICAgICAgICAgICAiaWQiOiBjaWQsCiAgICAgICAgICAgICJjYXRlZ29yeSI6IHdvcnN0WyJjYXRlZ29yeSJd"
    "LAogICAgICAgICAgICAidGVzdCI6IHdvcnN0WyJ0ZXN0Il0sCiAgICAgICAgICAgICJzZXZlcml0eSI6IHdvcnN0WyJzZXZl"
    "cml0eSJdLAogICAgICAgICAgICAicHJpb3JpdHkiOiB3b3JzdFsicHJpb3JpdHkiXSwKICAgICAgICAgICAgInJlc3VsdCI6"
    "IHdvcnN0X3Jlc3VsdCwKICAgICAgICAgICAgImFmZmVjdGVkX3VybF9jb3VudCI6IGFmZmVjdGVkX3VybF9jb3VudCwKICAg"
    "ICAgICAgICAgImFmZmVjdGVkX3VybHMiOiAiXG4iLmpvaW4oYWZmZWN0ZWRfdXJsc19saW5lcyksCiAgICAgICAgICAgICJ0"
    "b3RhbF91cmxzX3Rlc3RlZCI6IHRvdGFsX3VybHMsCiAgICAgICAgICAgICJldmlkZW5jZSI6IGNvbWJpbmVkX2V2aWRlbmNl"
    "LAogICAgICAgICAgICAidXJsX3Jlc3VsdHMiOiB1cmxfcmVzdWx0cywgICMgSlNPTi1vbmx5IC0gZXZlcnkgdGVzdGVkIFVS"
    "TCArIGl0cyBvd24gcmVzdWx0L2V2aWRlbmNlCiAgICAgICAgICAgICJzY3JlZW5zaG90X2NvdW50IjogbGVuKHNjcmVlbnNo"
    "b3RzKSwKICAgICAgICAgICAgInNjcmVlbnNob3RzIjogc2NyZWVuc2hvdHMsICAjIEpTT04tb25seSAtIHNlZSB3cml0ZV9j"
    "b25zb2xpZGF0ZWRfanNvbigpL3dyaXRlX3hsc3goKQogICAgICAgIH0pCiAgICByZXR1cm4gY29uc29saWRhdGVkCgoKZGVm"
    "IHdyaXRlX2NvbnNvbGlkYXRlZF9jc3YocGF0aCk6CiAgICByb3dzID0gY29uc29saWRhdGVfYnlfaWQoKQogICAgd2l0aCBv"
    "cGVuKHBhdGgsICJ3IiwgbmV3bGluZT0iIiwgZW5jb2Rpbmc9InV0Zi04IikgYXMgZjoKICAgICAgICB3ID0gY3N2LkRpY3RX"
    "cml0ZXIoZiwgZmllbGRuYW1lcz1DT05TT0xJREFURURfRklFTERTKQogICAgICAgIHcud3JpdGVoZWFkZXIoKQogICAgICAg"
    "IGZvciByb3cgaW4gcm93czoKICAgICAgICAgICAgIyAic2NyZWVuc2hvdHMiICh0aGUgbGlzdCBvZiBiYXNlNjQgaW1hZ2Vz"
    "KSBpcyBKU09OLW9ubHkgLSBhCiAgICAgICAgICAgICMgYmFzZTY0IFBORyBkb2Vzbid0IGJlbG9uZyBpbiBhIENTViBjZWxs"
    "OyBzY3JlZW5zaG90X2NvdW50CiAgICAgICAgICAgICMgKGFscmVhZHkgaW4gQ09OU09MSURBVEVEX0ZJRUxEUykgdGVsbHMg"
    "eW91IGhvdyBtYW55IGV4aXN0LgogICAgICAgICAgICB3LndyaXRlcm93KHtrOiByb3dba10gZm9yIGsgaW4gQ09OU09MSURB"
    "VEVEX0ZJRUxEU30pCiAgICByZXR1cm4gcm93cwoKCmRlZiB3cml0ZV9jb25zb2xpZGF0ZWRfanNvbihwYXRoKToKICAgIHJv"
    "d3MgPSBjb25zb2xpZGF0ZV9ieV9pZCgpCiAgICAjIGFmZmVjdGVkX3VybHMgaXMgIlxuIi1qb2luZWQgZm9yIHRoZSBDU1Yv"
    "WExTWCBzaW5nbGUtY2VsbCB2aWV3IGFib3ZlOwogICAgIyBKU09OIGNvbnN1bWVycyBnZW5lcmFsbHkgd2FudCBhIHJlYWwg"
    "bGlzdCBpbnN0ZWFkIG9mIG9uZSBuZXdsaW5lLQogICAgIyBkZWxpbWl0ZWQgc3RyaW5nLCBzbyBpdCdzIGV4cGFuZGVkIGJh"
    "Y2sgb3V0IGhlcmUuIEVhY2ggc2NyZWVuc2hvdCBpcwogICAgIyBhbHNvIGZsYXR0ZW5lZCBvdXQgdG8gaW1hZ2VfMV9iYXNl"
    "NjQvaW1hZ2VfMl9iYXNlNjQvLi4uIHRvcC1sZXZlbAogICAgIyBrZXlzIChpbiBhZGRpdGlvbiB0byB0aGUgc3RydWN0dXJl"
    "ZCAic2NyZWVuc2hvdHMiIGxpc3QpIGZvciBzaW1wbGUKICAgICMgY29uc3VtZXJzIHRoYXQganVzdCB3YW50ICJpbWFnZSBO"
    "IiBieSBuYW1lLCBwZXIgdGhlIGRpcmVjdCByZXF1ZXN0OgogICAgIyAic2NyZWVuc2hvdCBzaG91bGQgYmUgbXVsdGlwbGUg"
    "Li4uIGFkZCBpbWFnZSAxIGltYWdlIGZvciBpbWFnZSBiYXNlCiAgICAjIGNvZGUiIC0gb25lIHJvdyBjYW4gbm93IGhhdmUg"
    "bW9yZSB0aGFuIG9uZSBhZmZlY3RlZCBVUkwvc2NyZWVuc2hvdC4KICAgIGpzb25fcm93cyA9IFtdCiAgICBmb3Igcm93IGlu"
    "IHJvd3M6CiAgICAgICAganIgPSBkaWN0KHJvdykKICAgICAgICBqclsiYWZmZWN0ZWRfdXJscyJdID0gW3UgZm9yIHUgaW4g"
    "cm93WyJhZmZlY3RlZF91cmxzIl0uc3BsaXQoIlxuIikgaWYgdV0KICAgICAgICBmb3Igc2hvdCBpbiByb3dbInNjcmVlbnNo"
    "b3RzIl06CiAgICAgICAgICAgIGpyW2YiaW1hZ2Vfe3Nob3RbJ2luZGV4J119X2Jhc2U2NCJdID0gc2hvdFsiaW1hZ2VfYmFz"
    "ZTY0Il0KICAgICAgICBqc29uX3Jvd3MuYXBwZW5kKGpyKQogICAgd2l0aCBvcGVuKHBhdGgsICJ3IiwgZW5jb2Rpbmc9InV0"
    "Zi04IikgYXMgZjoKICAgICAgICBqc29uLmR1bXAoanNvbl9yb3dzLCBmLCBpbmRlbnQ9MikKICAgIHJldHVybiByb3dzCgoK"
    "ZGVmIHdyaXRlX2NzdihwYXRoKToKICAgICMgZXZpZGVuY2VfaW1hZ2VfYmFzZTY0IGlzIGludGVudGlvbmFsbHkgbGVmdCBv"
    "dXQgb2YgdGhlIENTViAoaXQgd291bGQKICAgICMgbWFrZSByb3dzIHVucmVhZGFibGUpIC0gInNjcmVlbnNob3Q6IHllcyIg"
    "dGVsbHMgeW91IHRvIGNoZWNrIHRoZQogICAgIyBKU09OIChvciB0aGUgLnhsc3ggRXZpZGVuY2Ugc2hlZXQpIGZvciB0aGF0"
    "IHJvdydzIGltYWdlIGluc3RlYWQuCiAgICB3aXRoIG9wZW4ocGF0aCwgInciLCBuZXdsaW5lPSIiLCBlbmNvZGluZz0idXRm"
    "LTgiKSBhcyBmOgogICAgICAgIHcgPSBjc3YuRGljdFdyaXRlcihmLCBmaWVsZG5hbWVzPUNTVl9GSUVMRFMpCiAgICAgICAg"
    "dy53cml0ZWhlYWRlcigpCiAgICAgICAgZm9yIHJvdyBpbiBSRVNVTFRTOgogICAgICAgICAgICBvdXRfcm93ID0ge2s6IHJv"
    "d1trXSBmb3IgayBpbiBPVVRQVVRfRklFTERTfQogICAgICAgICAgICBvdXRfcm93WyJzY3JlZW5zaG90Il0gPSAieWVzIiBp"
    "ZiByb3cuZ2V0KCJldmlkZW5jZV9pbWFnZV9iYXNlNjQiKSBlbHNlICJubyIKICAgICAgICAgICAgdy53cml0ZXJvdyhvdXRf"
    "cm93KQoKCmRlZiB3cml0ZV9qc29uKHBhdGgpOgogICAgd2l0aCBvcGVuKHBhdGgsICJ3IiwgZW5jb2Rpbmc9InV0Zi04Iikg"
    "YXMgZjoKICAgICAgICBqc29uLmR1bXAoUkVTVUxUUywgZiwgaW5kZW50PTIpCgoKZGVmIHdyaXRlX3hsc3gocGF0aCwgaW1h"
    "Z2VfYnl0ZXMpOgogICAgIiIiQ29sb3ItY29kZWQsIGZpbHRlcmFibGUgd29ya2Jvb2sgLSB0aGUgJ2Vhc3kgdG8gbmF2aWdh"
    "dGUgcG9ydGFsCiAgICBsaXN0IHRvIHRyYWNrJyBvdXRwdXQuIE5lZWRzIHBhbmRhcyArIHhsc3h3cml0ZXI7IGRlZ3JhZGVz"
    "IGdyYWNlZnVsbHkKICAgIChDU1YvSlNPTiBhcmUgdW5hZmZlY3RlZCkgaWYgZWl0aGVyIGlzbid0IGluc3RhbGxlZC4iIiIK"
    "ICAgIHRyeToKICAgICAgICBpbXBvcnQgcGFuZGFzIGFzIHBkCiAgICBleGNlcHQgSW1wb3J0RXJyb3I6CiAgICAgICAgcHJp"
    "bnQoIlxuWyFdICdwYW5kYXMnIG5vdCBpbnN0YWxsZWQgLSBza2lwcGluZyAueGxzeCBvdXRwdXQgKENTVi9KU09OIHdlcmUg"
    "c3RpbGwgd3JpdHRlbikuIikKICAgICAgICBwcmludCgiICAgIEluc3RhbGwgd2l0aDogcGlwMyBpbnN0YWxsIHBhbmRhcyB4"
    "bHN4d3JpdGVyICAgIgogICAgICAgICAgICAgICIoYWRkIC0tYnJlYWstc3lzdGVtLXBhY2thZ2VzIGlmIHlvdXIgUHl0aG9u"
    "IHJlcG9ydHMgYW4gZXh0ZXJuYWxseS1tYW5hZ2VkLWVudmlyb25tZW50IGVycm9yKSIpCiAgICAgICAgcmV0dXJuIEZhbHNl"
    "CiAgICB0cnk6CiAgICAgICAgaW1wb3J0IHhsc3h3cml0ZXIgICMgbm9xYTogRjQwMQogICAgZXhjZXB0IEltcG9ydEVycm9y"
    "OgogICAgICAgIHByaW50KCJcblshXSAneGxzeHdyaXRlcicgbm90IGluc3RhbGxlZCAtIHNraXBwaW5nIC54bHN4IG91dHB1"
    "dCAoQ1NWL0pTT04gd2VyZSBzdGlsbCB3cml0dGVuKS4iKQogICAgICAgIHByaW50KCIgICAgSW5zdGFsbCB3aXRoOiBwaXAz"
    "IGluc3RhbGwgeGxzeHdyaXRlciAgICIKICAgICAgICAgICAgICAiKGFkZCAtLWJyZWFrLXN5c3RlbS1wYWNrYWdlcyBpZiB5"
    "b3VyIFB5dGhvbiByZXBvcnRzIGFuIGV4dGVybmFsbHktbWFuYWdlZC1lbnZpcm9ubWVudCBlcnJvcikiKQogICAgICAgIHJl"
    "dHVybiBGYWxzZQoKICAgIGlmIG5vdCBSRVNVTFRTOgogICAgICAgIHJldHVybiBGYWxzZQoKICAgIHJlbmFtZV9tYXAgPSB7"
    "CiAgICAgICAgInNvdXJjZV9pbnB1dCI6ICJTb3VyY2UgSW5wdXQiLCAidXJsX3JvbGUiOiAiVVJMIFJvbGUiLCAidXJsIjog"
    "IlVSTCBUZXN0ZWQiLAogICAgICAgICJpZCI6ICJDaGVja2xpc3QgSUQiLCAiY2F0ZWdvcnkiOiAiQ2F0ZWdvcnkiLCAidGVz"
    "dCI6ICJUZXN0IE5hbWUiLAogICAgICAgICJzZXZlcml0eSI6ICJTZXZlcml0eSIsICJwcmlvcml0eSI6ICJQcmlvcml0eSIs"
    "ICJyZXN1bHQiOiAiUmVzdWx0IiwKICAgICAgICAiZXZpZGVuY2UiOiAiRXZpZGVuY2UgLyBDb21tZW50cyIsICJjaGVja2Vk"
    "X2F0IjogIkNoZWNrZWQgQXQgKFVUQykiLAogICAgfQogICAgZGYgPSBwZC5EYXRhRnJhbWUoUkVTVUxUUylbT1VUUFVUX0ZJ"
    "RUxEU10ucmVuYW1lKGNvbHVtbnM9cmVuYW1lX21hcCkKICAgIGNvbF9vcmRlciA9IGxpc3QocmVuYW1lX21hcC52YWx1ZXMo"
    "KSkKICAgIGRmID0gZGZbY29sX29yZGVyXQoKICAgIGNvbnNvbGlkYXRlZF9yb3dzID0gY29uc29saWRhdGVfYnlfaWQoKQog"
    "ICAgY29uc19yZW5hbWUgPSB7CiAgICAgICAgImlkIjogIkNoZWNrbGlzdCBJRCIsICJjYXRlZ29yeSI6ICJDYXRlZ29yeSIs"
    "ICJ0ZXN0IjogIlRlc3QgTmFtZSIsCiAgICAgICAgInNldmVyaXR5IjogIlNldmVyaXR5IiwgInByaW9yaXR5IjogIlByaW9y"
    "aXR5IiwgInJlc3VsdCI6ICJPdmVyYWxsIFJlc3VsdCIsCiAgICAgICAgImFmZmVjdGVkX3VybF9jb3VudCI6ICJBZmZlY3Rl"
    "ZCBVUkwgQ291bnQiLCAiYWZmZWN0ZWRfdXJscyI6ICJBZmZlY3RlZCBVUkwocykiLAogICAgICAgICJ0b3RhbF91cmxzX3Rl"
    "c3RlZCI6ICJUb3RhbCBVUkxzIFRlc3RlZCIsICJldmlkZW5jZSI6ICJFdmlkZW5jZSAod29yc3QtY2FzZSBVUkwpIiwKICAg"
    "IH0KICAgIGNvbnNfZGYgPSBwZC5EYXRhRnJhbWUoY29uc29saWRhdGVkX3Jvd3MpW0NPTlNPTElEQVRFRF9GSUVMRFNdLnJl"
    "bmFtZShjb2x1bW5zPWNvbnNfcmVuYW1lKQogICAgY29uc19jb2xfb3JkZXIgPSBsaXN0KGNvbnNfcmVuYW1lLnZhbHVlcygp"
    "KQogICAgY29uc19kZiA9IGNvbnNfZGZbY29uc19jb2xfb3JkZXJdCgogICAgd2l0aCBwZC5FeGNlbFdyaXRlcihwYXRoLCBl"
    "bmdpbmU9Inhsc3h3cml0ZXIiKSBhcyB3cml0ZXI6CiAgICAgICAgIyBXcml0dGVuIEZJUlNUIHNvIGl0J3MgdGhlIHNoZWV0"
    "IHZpc2libGUgd2hlbiB0aGUgZmlsZSBvcGVucyAtCiAgICAgICAgIyBvbmUgcm93IHBlciBjaGVja2xpc3QgSUQsIGV2ZXJ5"
    "IGFmZmVjdGVkIFVSTCBjbHViYmVkIGludG8gYQogICAgICAgICMgc2luZ2xlIGNlbGwgaW5zdGVhZCBvZiBhIHNlcGFyYXRl"
    "IHJvdyBwZXIgVVJML3JvbGUgcGFzcy4KICAgICAgICBjb25zX2RmLnRvX2V4Y2VsKHdyaXRlciwgc2hlZXRfbmFtZT0iQ29u"
    "c29saWRhdGVkIiwgaW5kZXg9RmFsc2UpCiAgICAgICAgd29ya2Jvb2sgPSB3cml0ZXIuYm9vawogICAgICAgIGNvbnNfc2hl"
    "ZXQgPSB3cml0ZXIuc2hlZXRzWyJDb25zb2xpZGF0ZWQiXQogICAgICAgIGNvbnNfaGVhZGVyX2ZtdCA9IHdvcmtib29rLmFk"
    "ZF9mb3JtYXQoeyJib2xkIjogVHJ1ZSwgImJnX2NvbG9yIjogIiNEN0U0QkMiLCAiYm9yZGVyIjogMSwgInRleHRfd3JhcCI6"
    "IFRydWV9KQogICAgICAgIGNvbnNfd3JhcF9mbXQgPSB3b3JrYm9vay5hZGRfZm9ybWF0KHsidGV4dF93cmFwIjogVHJ1ZSwg"
    "InZhbGlnbiI6ICJ0b3AifSkKICAgICAgICBmb3IgaSwgY29sIGluIGVudW1lcmF0ZShjb25zX2NvbF9vcmRlcik6CiAgICAg"
    "ICAgICAgIGNvbnNfc2hlZXQud3JpdGUoMCwgaSwgY29sLCBjb25zX2hlYWRlcl9mbXQpCiAgICAgICAgY29uc193aWR0aHMg"
    "PSBbMTIsIDI0LCAzNiwgMTAsIDEwLCAxNCwgMTAsIDUwLCAxMiwgNjBdCiAgICAgICAgd3JhcF9jb2xzID0gKCJBZmZlY3Rl"
    "ZCBVUkwocykiLCAiRXZpZGVuY2UgKHdvcnN0LWNhc2UgVVJMKSIpCiAgICAgICAgZm9yIGksIHcgaW4gZW51bWVyYXRlKGNv"
    "bnNfd2lkdGhzKToKICAgICAgICAgICAgY29uc19zaGVldC5zZXRfY29sdW1uKGksIGksIHcsIGNvbnNfd3JhcF9mbXQgaWYg"
    "Y29uc19jb2xfb3JkZXJbaV0gaW4gd3JhcF9jb2xzIGVsc2UgTm9uZSkKICAgICAgICBjb25zX3NoZWV0LmZyZWV6ZV9wYW5l"
    "cygxLCAwKQogICAgICAgIGNvbnNfc2hlZXQuYXV0b2ZpbHRlcigwLCAwLCBsZW4oY29uc19kZiksIGxlbihjb25zX2NvbF9v"
    "cmRlcikgLSAxKQogICAgICAgIGNvbnNfcmVzdWx0X2NvbF9pZHggPSBjb25zX2NvbF9vcmRlci5pbmRleCgiT3ZlcmFsbCBS"
    "ZXN1bHQiKQogICAgICAgIGNvbnNfY29sb3JfZm10cyA9IHsKICAgICAgICAgICAgIlBBU1MiOiB3b3JrYm9vay5hZGRfZm9y"
    "bWF0KHsiYmdfY29sb3IiOiAiI0M2RUZDRSIsICJmb250X2NvbG9yIjogIiMwMDYxMDAifSksCiAgICAgICAgICAgICJGQUlM"
    "Ijogd29ya2Jvb2suYWRkX2Zvcm1hdCh7ImJnX2NvbG9yIjogIiNGRkM3Q0UiLCAiZm9udF9jb2xvciI6ICIjOUMwMDA2In0p"
    "LAogICAgICAgICAgICAiTUFOVUFMIjogd29ya2Jvb2suYWRkX2Zvcm1hdCh7ImJnX2NvbG9yIjogIiNGRkVCOUMiLCAiZm9u"
    "dF9jb2xvciI6ICIjOUM2NTAwIn0pLAogICAgICAgICAgICAiSU5GTyI6IHdvcmtib29rLmFkZF9mb3JtYXQoeyJiZ19jb2xv"
    "ciI6ICIjRENFNkYxIiwgImZvbnRfY29sb3IiOiAiIzFGNEU3OCJ9KSwKICAgICAgICAgICAgIkVSUk9SIjogd29ya2Jvb2su"
    "YWRkX2Zvcm1hdCh7ImJnX2NvbG9yIjogIiNEOUQ5RDkiLCAiZm9udF9jb2xvciI6ICIjM0IzQjNCIn0pLAogICAgICAgIH0K"
    "ICAgICAgICBmb3IgdmFsLCBmbXQgaW4gY29uc19jb2xvcl9mbXRzLml0ZW1zKCk6CiAgICAgICAgICAgIGNvbnNfc2hlZXQu"
    "Y29uZGl0aW9uYWxfZm9ybWF0KDEsIGNvbnNfcmVzdWx0X2NvbF9pZHgsIGxlbihjb25zX2RmKSwgY29uc19yZXN1bHRfY29s"
    "X2lkeCwKICAgICAgICAgICAgICAgIHsidHlwZSI6ICJjZWxsIiwgImNyaXRlcmlhIjogImVxdWFsIHRvIiwgInZhbHVlIjog"
    "Zicie3ZhbH0iJywgImZvcm1hdCI6IGZtdH0pCgogICAgICAgIGRmLnRvX2V4Y2VsKHdyaXRlciwgc2hlZXRfbmFtZT0iU2Nh"
    "biBSZXN1bHRzIChEZXRhaWwpIiwgaW5kZXg9RmFsc2UpCiAgICAgICAgc2hlZXQgPSB3cml0ZXIuc2hlZXRzWyJTY2FuIFJl"
    "c3VsdHMgKERldGFpbCkiXQoKICAgICAgICBoZWFkZXJfZm10ID0gd29ya2Jvb2suYWRkX2Zvcm1hdCh7ImJvbGQiOiBUcnVl"
    "LCAiYmdfY29sb3IiOiAiI0Q3RTRCQyIsICJib3JkZXIiOiAxLCAidGV4dF93cmFwIjogVHJ1ZX0pCiAgICAgICAgd3JhcF9m"
    "bXQgPSB3b3JrYm9vay5hZGRfZm9ybWF0KHsidGV4dF93cmFwIjogVHJ1ZSwgInZhbGlnbiI6ICJ0b3AifSkKICAgICAgICBm"
    "b3IgaSwgY29sIGluIGVudW1lcmF0ZShjb2xfb3JkZXIpOgogICAgICAgICAgICBzaGVldC53cml0ZSgwLCBpLCBjb2wsIGhl"
    "YWRlcl9mbXQpCgogICAgICAgIHdpZHRocyA9IFsyMiwgMjAsIDM0LCAxMiwgMjQsIDM2LCAxMCwgMTAsIDEwLCA3MCwgMjBd"
    "CiAgICAgICAgZm9yIGksIHcgaW4gZW51bWVyYXRlKHdpZHRocyk6CiAgICAgICAgICAgIHNoZWV0LnNldF9jb2x1bW4oaSwg"
    "aSwgdywgd3JhcF9mbXQgaWYgY29sX29yZGVyW2ldID09ICJFdmlkZW5jZSAvIENvbW1lbnRzIiBlbHNlIE5vbmUpCiAgICAg"
    "ICAgc2hlZXQuZnJlZXplX3BhbmVzKDEsIDApCiAgICAgICAgc2hlZXQuYXV0b2ZpbHRlcigwLCAwLCBsZW4oZGYpLCBsZW4o"
    "Y29sX29yZGVyKSAtIDEpCgogICAgICAgIHJlc3VsdF9jb2xfaWR4ID0gY29sX29yZGVyLmluZGV4KCJSZXN1bHQiKQogICAg"
    "ICAgIGNvbG9yX2ZtdHMgPSB7CiAgICAgICAgICAgICJQQVNTIjogd29ya2Jvb2suYWRkX2Zvcm1hdCh7ImJnX2NvbG9yIjog"
    "IiNDNkVGQ0UiLCAiZm9udF9jb2xvciI6ICIjMDA2MTAwIn0pLAogICAgICAgICAgICAiRkFJTCI6IHdvcmtib29rLmFkZF9m"
    "b3JtYXQoeyJiZ19jb2xvciI6ICIjRkZDN0NFIiwgImZvbnRfY29sb3IiOiAiIzlDMDAwNiJ9KSwKICAgICAgICAgICAgIk1B"
    "TlVBTCI6IHdvcmtib29rLmFkZF9mb3JtYXQoeyJiZ19jb2xvciI6ICIjRkZFQjlDIiwgImZvbnRfY29sb3IiOiAiIzlDNjUw"
    "MCJ9KSwKICAgICAgICAgICAgIklORk8iOiB3b3JrYm9vay5hZGRfZm9ybWF0KHsiYmdfY29sb3IiOiAiI0RDRTZGMSIsICJm"
    "b250X2NvbG9yIjogIiMxRjRFNzgifSksCiAgICAgICAgICAgICJFUlJPUiI6IHdvcmtib29rLmFkZF9mb3JtYXQoeyJiZ19j"
    "b2xvciI6ICIjRDlEOUQ5IiwgImZvbnRfY29sb3IiOiAiIzNCM0IzQiJ9KSwKICAgICAgICB9CiAgICAgICAgZm9yIHZhbCwg"
    "Zm10IGluIGNvbG9yX2ZtdHMuaXRlbXMoKToKICAgICAgICAgICAgc2hlZXQuY29uZGl0aW9uYWxfZm9ybWF0KDEsIHJlc3Vs"
    "dF9jb2xfaWR4LCBsZW4oZGYpLCByZXN1bHRfY29sX2lkeCwKICAgICAgICAgICAgICAgIHsidHlwZSI6ICJjZWxsIiwgImNy"
    "aXRlcmlhIjogImVxdWFsIHRvIiwgInZhbHVlIjogZicie3ZhbH0iJywgImZvcm1hdCI6IGZtdH0pCgogICAgICAgIHN1bW1h"
    "cnkgPSB3b3JrYm9vay5hZGRfd29ya3NoZWV0KCJTdW1tYXJ5IikKICAgICAgICBzdW1tYXJ5LmhpZGVfZ3JpZGxpbmVzKDIp"
    "CiAgICAgICAgdGl0bGVfZm10ID0gd29ya2Jvb2suYWRkX2Zvcm1hdCh7ImJvbGQiOiBUcnVlLCAiZm9udF9zaXplIjogMTQs"
    "ICJmb250X2NvbG9yIjogIiMyQjU3OTcifSkKICAgICAgICBzdW1tYXJ5LndyaXRlKDAsIDAsICJBdXRvbWF0ZWQgQ2hlY2ts"
    "aXN0IFNjYW4gLSBTdW1tYXJ5IiwgdGl0bGVfZm10KQogICAgICAgIHN1bW1hcnkud3JpdGUoMSwgMCwgZiJHZW5lcmF0ZWQ6"
    "IHtub3dfaXNvKCl9IikKICAgICAgICBzdW1tYXJ5LndyaXRlKDIsIDAsIGYiVG90YWwgY2hlY2tsaXN0IHJvd3M6IHtsZW4o"
    "ZGYpfSIpCiAgICAgICAgc3VtbWFyeS53cml0ZSgzLCAwLCBmIlVuaXF1ZSBzb3VyY2UgVVJMcyAoZnJvbSAtLXVybCAvIC0t"
    "dXJsLWZpbGUpOiB7ZGZbJ1NvdXJjZSBJbnB1dCddLm51bmlxdWUoKX0iKQogICAgICAgIHN1bW1hcnkud3JpdGUoNCwgMCwg"
    "ZiJVbmlxdWUgVVJMK3JvbGUgcGFzc2VzIHRlc3RlZDoge2RmWydVUkwgVGVzdGVkJ10uYXN0eXBlKHN0cikuc3RyLmNhdChk"
    "ZlsnVVJMIFJvbGUnXSwgc2VwPScgfCAnKS5udW5pcXVlKCl9IikKCiAgICAgICAgcm93ID0gNgogICAgICAgIHN1bW1hcnku"
    "d3JpdGUocm93LCAwLCAiUmVzdWx0IiwgaGVhZGVyX2ZtdCkKICAgICAgICBzdW1tYXJ5LndyaXRlKHJvdywgMSwgIkNvdW50"
    "IiwgaGVhZGVyX2ZtdCkKICAgICAgICBmb3IgaSwgKHZhbCwgY250KSBpbiBlbnVtZXJhdGUoZGZbIlJlc3VsdCJdLnZhbHVl"
    "X2NvdW50cygpLml0ZW1zKCksIHN0YXJ0PXJvdyArIDEpOgogICAgICAgICAgICBzdW1tYXJ5LndyaXRlKGksIDAsIHZhbCkK"
    "ICAgICAgICAgICAgc3VtbWFyeS53cml0ZShpLCAxLCBpbnQoY250KSkKCiAgICAgICAgcm93MiA9IHJvdyArIGxlbihkZlsi"
    "UmVzdWx0Il0udmFsdWVfY291bnRzKCkpICsgMwogICAgICAgIHN1bW1hcnkud3JpdGUocm93MiwgMCwgIkNhdGVnb3J5Iiwg"
    "aGVhZGVyX2ZtdCkKICAgICAgICBzdW1tYXJ5LndyaXRlKHJvdzIsIDEsICJDb3VudCIsIGhlYWRlcl9mbXQpCiAgICAgICAg"
    "Zm9yIGksICh2YWwsIGNudCkgaW4gZW51bWVyYXRlKGRmWyJDYXRlZ29yeSJdLnZhbHVlX2NvdW50cygpLml0ZW1zKCksIHN0"
    "YXJ0PXJvdzIgKyAxKToKICAgICAgICAgICAgc3VtbWFyeS53cml0ZShpLCAwLCB2YWwpCiAgICAgICAgICAgIHN1bW1hcnku"
    "d3JpdGUoaSwgMSwgaW50KGNudCkpCgogICAgICAgIHN1bW1hcnkuc2V0X2NvbHVtbigwLCAwLCA0NCkKICAgICAgICBzdW1t"
    "YXJ5LnNldF9jb2x1bW4oMSwgMSwgMTIpCgogICAgICAgIGlmIGltYWdlX2J5dGVzOgogICAgICAgICAgICAjIEdyb3VwZWQg"
    "YnkgY2hlY2tsaXN0IElEIChvbmUgaGVhZGluZyBwZXIgSUQsICJJbWFnZSAxIiwKICAgICAgICAgICAgIyAiSW1hZ2UgMiIs"
    "IC4uLiB1bmRlcm5lYXRoKSBzbyBhbiBJRCB3aXRoIG1vcmUgdGhhbiBvbmUKICAgICAgICAgICAgIyBhZmZlY3RlZCBVUkwg"
    "LSBhbmQgdGhlcmVmb3JlIG1vcmUgdGhhbiBvbmUgc2NyZWVuc2hvdCAtCiAgICAgICAgICAgICMgcmVhZHMgdGhlIHNhbWUg"
    "d2F5IHRoZSBDb25zb2xpZGF0ZWQgc2hlZXQgZ3JvdXBzIGl0LCBpbnN0ZWFkCiAgICAgICAgICAgICMgb2YganVzdCBhIGZs"
    "YXQgbGlzdCBpbiBzY2FuIG9yZGVyLgogICAgICAgICAgICBldnNoZWV0ID0gd29ya2Jvb2suYWRkX3dvcmtzaGVldCgiRXZp"
    "ZGVuY2UiKQogICAgICAgICAgICBldnNoZWV0LmhpZGVfZ3JpZGxpbmVzKDIpCiAgICAgICAgICAgIGV2c2hlZXQud3JpdGUo"
    "MCwgMCwgZiJBdXRvLUdlbmVyYXRlZCBFdmlkZW5jZSBTY3JlZW5zaG90cyAoe2xlbihpbWFnZV9ieXRlcyl9KSIsIHRpdGxl"
    "X2ZtdCkKICAgICAgICAgICAgZXZzaGVldC5zZXRfY29sdW1uKDAsIDAsIDEzMCkKICAgICAgICAgICAgY2FwdGlvbl9mbXQg"
    "PSB3b3JrYm9vay5hZGRfZm9ybWF0KHsiYm9sZCI6IFRydWUsICJiZ19jb2xvciI6ICIjRjJGMkYyIn0pCiAgICAgICAgICAg"
    "IGlkX2hlYWRlcl9mbXQgPSB3b3JrYm9vay5hZGRfZm9ybWF0KHsiYm9sZCI6IFRydWUsICJmb250X3NpemUiOiAxMiwgImZv"
    "bnRfY29sb3IiOiAiIzJCNTc5NyIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ImJvdHRvbSI6IDJ9KQoKICAgICAgICAgICAgYnlfaWRfaWR4ID0ge30KICAgICAgICAgICAgZm9yIGlkeCBpbiBzb3J0ZWQo"
    "aW1hZ2VfYnl0ZXMua2V5cygpKToKICAgICAgICAgICAgICAgIGJ5X2lkX2lkeC5zZXRkZWZhdWx0KFJFU1VMVFNbaWR4XVsi"
    "aWQiXSwgW10pLmFwcGVuZChpZHgpCgogICAgICAgICAgICByb3dfY3Vyc29yID0gMgogICAgICAgICAgICBmb3IgY2lkIGlu"
    "IHNvcnRlZChieV9pZF9pZHgua2V5cygpKToKICAgICAgICAgICAgICAgIGlkeHMgPSBieV9pZF9pZHhbY2lkXQogICAgICAg"
    "ICAgICAgICAgc2FtcGxlID0gUkVTVUxUU1tpZHhzWzBdXQogICAgICAgICAgICAgICAgZXZzaGVldC53cml0ZShyb3dfY3Vy"
    "c29yLCAwLCBmIntjaWR9IC0ge3NhbXBsZVsndGVzdCddfSAgKHtsZW4oaWR4cyl9IGltYWdleydzJyBpZiBsZW4oaWR4cykg"
    "IT0gMSBlbHNlICcnfSkiLCBpZF9oZWFkZXJfZm10KQogICAgICAgICAgICAgICAgcm93X2N1cnNvciArPSAxCiAgICAgICAg"
    "ICAgICAgICBmb3IgbiwgaWR4IGluIGVudW1lcmF0ZShpZHhzLCBzdGFydD0xKToKICAgICAgICAgICAgICAgICAgICByID0g"
    "UkVTVUxUU1tpZHhdCiAgICAgICAgICAgICAgICAgICAgZXZzaGVldC53cml0ZShyb3dfY3Vyc29yLCAwLAogICAgICAgICAg"
    "ICAgICAgICAgICAgICBmIkltYWdlIHtufToge3JbJ3Jlc3VsdCddfSAgfCAge3JbJ3VybCddfSAoe3JbJ3VybF9yb2xlJ119"
    "KSIsIGNhcHRpb25fZm10KQogICAgICAgICAgICAgICAgICAgIHJvd19jdXJzb3IgKz0gMQogICAgICAgICAgICAgICAgICAg"
    "IGltZ19zdHJlYW0gPSBpby5CeXRlc0lPKGltYWdlX2J5dGVzW2lkeF0pCiAgICAgICAgICAgICAgICAgICAgZXZzaGVldC5p"
    "bnNlcnRfaW1hZ2Uocm93X2N1cnNvciwgMCwgZiJ7Y2lkfV97bn0ucG5nIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgeyJpbWFnZV9kYXRhIjogaW1nX3N0cmVhbSwgInhfc2NhbGUiOiAwLjU1LCAieV9zY2FsZSI6IDAu"
    "NTV9KQogICAgICAgICAgICAgICAgICAgIHJvd19jdXJzb3IgKz0gMjAgICMgcm91Z2hseSB0aGUgc2NhbGVkIGltYWdlIGhl"
    "aWdodCBpbiBkZWZhdWx0LXNpemUgcm93cwogICAgICAgICAgICAgICAgcm93X2N1cnNvciArPSAxCgogICAgcmV0dXJuIFRy"
    "dWUKCgojIFRoZSAzIGNoZWNrbGlzdCBpdGVtcyBjaGVja19hY2Nlc3NfY29udHJvbF8yZmEoKSBjYW4gdHVybiBmcm9tIE1B"
    "TlVBTAojIGludG8gYSByZWFsIFBBU1MvRkFJTCByZXN1bHQsIGFuZCBob3cgbWFueSBkaXN0aW5jdCBhY2NvdW50cyBlYWNo"
    "IG5lZWRzLgojIFVzZWQgYnkgYm90aCBjb3ZlcmFnZS1yZXBvcnQgZnVuY3Rpb25zIGJlbG93IHNvIHRoZSB0d28gc3RheSBp"
    "biBzeW5jLgpBVVRIX0dBVEVEX0lEUyA9IFsKICAgICgiV0EtT1RHLTMxMiIsICJBdXRob3JpemF0aW9uIFRlc3RpbmciLCAi"
    "VGVzdCBieXBhc3NpbmcgYXV0aG9yaXphdGlvbiBzY2hlbWEgKGZvcmNlIGJyb3dzZSkiLCAxKSwKICAgICgiV0EtU1MtMDcx"
    "IiwgIkFjY2VzcyBDb250cm9sIiwgIkhvcml6b250YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24gKGFjY2VzcyBhbm90aGVyIHVz"
    "ZXIgZGF0YSkiLCAyKSwKICAgICgiV0EtT1RHLTMxNCIsICJBdXRob3JpemF0aW9uIFRlc3RpbmciLCAiVGVzdCBpbnNlY3Vy"
    "ZSBkaXJlY3Qgb2JqZWN0IHJlZmVyZW5jZXMgKElET1IpIiwgMiksCl0KCgpkZWYgcHJpbnRfYXV0aF9jb3ZlcmFnZV9wbGFu"
    "KGFyZ3MpOgogICAgIiIiUHJpbnRlZCBvbmNlLCByaWdodCBiZWZvcmUgc2Nhbm5pbmcgc3RhcnRzIC0gdGVsbHMgeW91IHVw"
    "ZnJvbnQKICAgIGV4YWN0bHkgd2hhdCAtLWNvb2tpZS8tLWNvb2tpZTIgd2lsbCBhbmQgd29uJ3QgY292ZXIsIHNvIHlvdSBr"
    "bm93CiAgICB3aGV0aGVyIHlvdSBuZWVkIGEgc2Vjb25kIHNlc3Npb24gYmVmb3JlIHRoZSBydW4gZXZlbiBiZWdpbnMuIFRo"
    "aXMgaXMKICAgIHRoZSAnYXV0byBjaGVjaycgYmVoYXZpb3I6IG9uZSBjb29raWUgaXMgZW5vdWdoIHRvIGF1dGhlbnRpY2F0"
    "ZSB0aGUKICAgIEVOVElSRSBzdWl0ZSAoZXZlcnkgY2hlY2ssIG5vdCBqdXN0IHRoZSAzIGJlbG93KSBwbHVzIFdBLU9URy0z"
    "MTI7CiAgICBhZGRpbmcgYSBzZWNvbmQgY29va2llIGlzIG9ubHkgbmVlZGVkIGZvciB0aGUgdHdvIGNoZWNrcyB0aGF0CiAg"
    "ICBzcGVjaWZpY2FsbHkgcmVxdWlyZSBjb21wYXJpbmcgdHdvIGRpZmZlcmVudCBhY2NvdW50cyBhZ2FpbnN0IGVhY2gKICAg"
    "IG90aGVyLiIiIgogICAgaGF2ZTEgPSBib29sKGFyZ3MuY29va2llIG9yIGFyZ3MuYWNjb3VudDFfY29va2llKQogICAgaGF2"
    "ZTIgPSBib29sKGFyZ3MuY29va2llMiBvciBhcmdzLmFjY291bnQyX2Nvb2tpZSkKICAgIHByaW50KCkKICAgIGlmIG5vdCBo"
    "YXZlMToKICAgICAgICBwcmludCgiWypdIE5vIC0tY29va2llIGdpdmVuIC0gZXZlcnkgY2hlY2sgcnVucyB1bmF1dGhlbnRp"
    "Y2F0ZWQuIEFkZCAtLWNvb2tpZSBcInNlc3Npb25pZD0uLi5cIiB0byB0ZXN0ICIKICAgICAgICAgICAgICAiZXZlcnl0aGlu"
    "ZyBhcyBhIGxvZ2dlZC1pbiBzZXNzaW9uIHNlZXMgaXQgKHJlY29tbWVuZGVkIGZvciBtb3N0IGVuZ2FnZW1lbnRzKS4iKQog"
    "ICAgICAgIHJldHVybgogICAgcHJpbnQoIlsqXSAtLWNvb2tpZSBnaXZlbiAtIEFMTCB+MTAwIGNoZWNrcyBpbiB0aGlzIHN1"
    "aXRlIChoZWFkZXJzLCBUTFMsIGNvb2tpZXMsIENPUlMsIGluZm9ybWF0aW9uIikKICAgIHByaW50KCIgICAgZ2F0aGVyaW5n"
    "LCBldGMuKSBydW4gYXMgdGhhdCBhdXRoZW50aWNhdGVkIHNlc3Npb24sIHBsdXMgcmVhbCAobm9uLU1BTlVBTCkgdGVzdGlu"
    "ZyBmb3I6IikKICAgIHByaW50KCIgICAgICBXQS1PVEctMzEyICBUZXN0IGJ5cGFzc2luZyBhdXRob3JpemF0aW9uIHNjaGVt"
    "YSAoZm9yY2UgYnJvd3NlKSIpCiAgICBpZiBoYXZlMjoKICAgICAgICBwcmludCgiWypdIC0tY29va2llMiBhbHNvIGdpdmVu"
    "IC0gdGhlc2UgQUxTTyBnZXQgcmVhbCB0ZXN0aW5nLCBjb21wYXJpbmcgYWNjb3VudCAxIHZzIGFjY291bnQgMjoiKQogICAg"
    "ICAgIHByaW50KCIgICAgICBXQS1TUy0wNzEgICBIb3Jpem9udGFsIHByaXZpbGVnZSBlc2NhbGF0aW9uIChhY2Nlc3MgYW5v"
    "dGhlciB1c2VyIGRhdGEpIikKICAgICAgICBwcmludCgiICAgICAgV0EtT1RHLTMxNCAgVGVzdCBpbnNlY3VyZSBkaXJlY3Qg"
    "b2JqZWN0IHJlZmVyZW5jZXMgKElET1IpIikKICAgIGVsc2U6CiAgICAgICAgcHJpbnQoIlsqXSBObyAtLWNvb2tpZTIgLSB0"
    "aGVzZSBzdGF5IE1BTlVBTCAobmVlZCBhIFNFQ09ORCwgZGlmZmVyZW50IGFjY291bnQncyBzZXNzaW9uIHRvIGNvbXBhcmUi"
    "KQogICAgICAgIHByaW50KCIgICAgYWdhaW5zdCB0aGUgZmlyc3QpOiBXQS1TUy0wNzEsIFdBLU9URy0zMTQuIEFkZCAtLWNv"
    "b2tpZTIgXCJzZXNzaW9uaWQ9Li4uXCIgdG8gY292ZXIgdGhlbSB0b28uIikKICAgIHByaW50KCkKCgojIFRoZXNlIGFyZSBs"
    "aXRlcmFsIHByZWZpeGVzIG9mIHRoZSB0d28gIndlIG5ldmVyIGV2ZW4gdHJpZWQiIE1BTlVBTAojIGV2aWRlbmNlIHN0cmlu"
    "Z3MgY2hlY2tfYWNjZXNzX2NvbnRyb2xfMmZhKCkgd3JpdGVzIHdoZW4gYSBjb29raWUgaXMKIyBtaXNzaW5nIChzZWUgdGhh"
    "dCBmdW5jdGlvbikuIE1hdGNoaW5nIG9uIHRoZXNlIC0gbm90IGp1c3QgcmVzdWx0ID09CiMgIk1BTlVBTCIgLSBpcyB3aGF0"
    "IGxldHMgcHJpbnRfYXV0aF9jb3ZlcmFnZV9hY3R1YWwoKSB0ZWxsICJza2lwcGVkLAojIG5vIGNvb2tpZSIgYXBhcnQgZnJv"
    "bSAicmFuIGZvciByZWFsLCBidXQgdGhlIG91dGNvbWUgaXRzZWxmIG5lZWRzIGEKIyBodW1hbiBqdWRnbWVudCBjYWxsIiAo"
    "ZS5nLiB0d28gYWNjb3VudHMgc2F3IGJ5dGUtaWRlbnRpY2FsIGNvbnRlbnQgLQojIHRoYXQncyBNQU5VQUwgYnkgZGVzaWdu"
    "IGV2ZW4gd2hlbiBib3RoIGNvb2tpZXMgV0VSRSBwcm92aWRlZCBhbmQgdGhlCiMgY29tcGFyaXNvbiBnZW51aW5lbHkgcmFu"
    "KS4gS2VlcCB0aGVzZSBpbiBzeW5jIGlmIHRoYXQgZXZpZGVuY2Ugd29yZGluZwojIGV2ZXIgY2hhbmdlcy4KX0FVVEhfU0tJ"
    "UF9OT19TRVNTSU9OID0gIk1hbnVhbCB0ZXN0IHJlcXVpcmVkLiBOZWVkcyBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gdG8g"
    "dGVzdCIKX0FVVEhfU0tJUF9OT19TRUNPTkRfQUNDT1VOVCA9ICJNYW51YWwgdGVzdCByZXF1aXJlZC4gTmVlZHMgYSBTRUNP"
    "TkQgYWNjb3VudCdzIHNlc3Npb24gdG9vIgoKCmRlZiBwcmludF9hdXRoX2NvdmVyYWdlX2FjdHVhbCgpOgogICAgIiIiUHJp"
    "bnRlZCBhZnRlciBzY2FubmluZywgYXMgcGFydCBvZiBwcmludF9zdW1tYXJ5KCkgLSBncm91bmQtdHJ1dGgKICAgIGNvbmZp"
    "cm1hdGlvbiBvZiB3aGF0IGFjdHVhbGx5IGdvdCByZWNvcmRlZCBhcyBhIHJlYWwsIGF1dG9tYXRlZAogICAgY29tcGFyaXNv"
    "biB2cyB3YXMgc2tpcHBlZCBvdXRyaWdodCBmb3IgbGFjayBvZiBhIGNvb2tpZSwgcmVhZCBzdHJhaWdodAogICAgZnJvbSBS"
    "RVNVTFRTIHJhdGhlciB0aGFuIGp1c3QgaW50ZW50IGZyb20gdGhlIGZsYWdzLiBBIE1BTlVBTCByZXN1bHQKICAgIGhlcmUg"
    "Y2FuIG1lYW4gdHdvIGRpZmZlcmVudCB0aGluZ3MgYW5kIHRoaXMgcmVwb3J0cyB0aGVtIHNlcGFyYXRlbHk6CiAgICAoYSkg"
    "dGhlIGNoZWNrIG5ldmVyIHJhbiBhdCBhbGwgYmVjYXVzZSBubyBjb29raWUgd2FzIGdpdmVuLCBvciAoYikgaXQKICAgIERJ"
    "RCBydW4gLSBib3RoIGFjY291bnRzIHdlcmUgYWN0dWFsbHkgY29tcGFyZWQgLSBidXQgdGhlIG91dGNvbWUKICAgIGl0c2Vs"
    "ZiBuZWVkcyBhIGh1bWFuIGp1ZGdtZW50IGNhbGwgKGUuZy4gaWRlbnRpY2FsIGNvbnRlbnQgYmV0d2VlbgogICAgdHdvIGFj"
    "Y291bnRzLCB3aGljaCBpcyByZXBvcnRlZCBNQU5VQUwgYnkgZGVzaWduLCBub3Qgc2tpcHBlZCkuIiIiCiAgICBieV9pZCA9"
    "IHt9CiAgICBmb3IgciBpbiBSRVNVTFRTOgogICAgICAgIGJ5X2lkLnNldGRlZmF1bHQoclsiaWQiXSwgW10pLmFwcGVuZChy"
    "KQogICAgaWYgbm90IGFueShjaWQgaW4gYnlfaWQgZm9yIGNpZCwgKl8gaW4gQVVUSF9HQVRFRF9JRFMpOgogICAgICAgIHJl"
    "dHVybgogICAgcHJpbnQoIi0iICogNzApCiAgICBwcmludCgiQUNDRVNTIENPTlRST0wgLyBBVVRIIENPVkVSQUdFIC0gd2hh"
    "dCBhY3R1YWxseSByYW4gYXV0aGVudGljYXRlZDoiKQogICAgZm9yIGNpZCwgY2F0LCBuYW1lLCBhY2NvdW50c19uZWVkZWQg"
    "aW4gQVVUSF9HQVRFRF9JRFM6CiAgICAgICAgcm93cyA9IGJ5X2lkLmdldChjaWQpCiAgICAgICAgaWYgbm90IHJvd3M6CiAg"
    "ICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgcmFuID0gc2tpcHBlZCA9IGVycm9yID0gMAogICAgICAgIGZvciByIGluIHJv"
    "d3M6CiAgICAgICAgICAgIHJlcywgZXYgPSByWyJyZXN1bHQiXSwgci5nZXQoImV2aWRlbmNlIikgb3IgIiIKICAgICAgICAg"
    "ICAgaWYgcmVzID09ICJFUlJPUiI6CiAgICAgICAgICAgICAgICBlcnJvciArPSAxCiAgICAgICAgICAgIGVsaWYgcmVzID09"
    "ICJNQU5VQUwiIGFuZCAoZXYuc3RhcnRzd2l0aChfQVVUSF9TS0lQX05PX1NFU1NJT04pIG9yIGV2LnN0YXJ0c3dpdGgoX0FV"
    "VEhfU0tJUF9OT19TRUNPTkRfQUNDT1VOVCkpOgogICAgICAgICAgICAgICAgc2tpcHBlZCArPSAxCiAgICAgICAgICAgIGVs"
    "c2U6CiAgICAgICAgICAgICAgICAjIFBBU1MsIEZBSUwsIG9yIGEgTUFOVUFMIHRoYXQgcmFuIGZvciByZWFsIChodW1hbiBq"
    "dWRnbWVudAogICAgICAgICAgICAgICAgIyBuZWVkZWQgb24gdGhlIG91dGNvbWUsIG5vdCBhIHNraXApLgogICAgICAgICAg"
    "ICAgICAgcmFuICs9IDEKICAgICAgICBwYXJ0cyA9IFtdCiAgICAgICAgaWYgcmFuOgogICAgICAgICAgICBwYXJ0cy5hcHBl"
    "bmQoZiJ7cmFufSB0ZXN0ZWQgZm9yIHJlYWwiKQogICAgICAgIGlmIHNraXBwZWQ6CiAgICAgICAgICAgIG5lZWQgPSAiYSAy"
    "bmQgYWNjb3VudCdzIGNvb2tpZSAoLS1jb29raWUyKSIgaWYgYWNjb3VudHNfbmVlZGVkID09IDIgZWxzZSAiYSBzZXNzaW9u"
    "IGNvb2tpZSAoLS1jb29raWUpIgogICAgICAgICAgICBwYXJ0cy5hcHBlbmQoZiJ7c2tpcHBlZH0gU0tJUFBFRCAtIG5lZWRz"
    "IHtuZWVkfSIpCiAgICAgICAgaWYgZXJyb3I6CiAgICAgICAgICAgIHBhcnRzLmFwcGVuZChmIntlcnJvcn0gRVJST1IgKHJl"
    "cXVlc3QgZmFpbGVkIC0gY2hlY2sgLS1pbnNlY3VyZS90YXJnZXQgcmVhY2hhYmlsaXR5L2Nvb2tpZSB2YWxpZGl0eSkiKQog"
    "ICAgICAgIHByaW50KGYiICB7Y2lkOjEyc30ge25hbWV9OiB7JywgJy5qb2luKHBhcnRzKX0iKQogICAgcHJpbnQoIi0iICog"
    "NzApCgoKZGVmIHByaW50X3NzbF92ZXJpZnlfc3VtbWFyeV9jYWxsb3V0KCk6CiAgICAiIiJPbmUgdG9wLW9mLXN1bW1hcnkg"
    "bm90ZSB3aGVuIFRMUyBjZXJ0aWZpY2F0ZS1jaGFpbiB2ZXJpZmljYXRpb24KICAgIGZhaWx1cmVzIChyYXdfcmVxdWVzdCgp"
    "J3Mgc3NsLlNTTENlcnRWZXJpZmljYXRpb25FcnJvciBoYW5kbGVyKSBhZmZlY3RlZAogICAgb25lIG9yIG1vcmUgcm93cyAt"
    "IHNvIHRoaXMgZG9lc24ndCBvbmx5IHNob3cgdXAgc2NhdHRlcmVkIGluc2lkZQogICAgaW5kaXZpZHVhbCByb3dzJyBldmlk"
    "ZW5jZSB0ZXh0LCB3aGljaCBpcyBlYXN5IHRvIG1pc3Mgd2hlbiBzY2FubmluZwogICAgbWFueSBVUkxzLiBTZWUgX1NTTF9W"
    "RVJJRllfSElOVF9NQVJLRVIuIiIiCiAgICBhZmZlY3RlZF9pZHMgPSBzZXQoKQogICAgYWZmZWN0ZWRfcm93cyA9IDAKICAg"
    "IGZvciByIGluIFJFU1VMVFM6CiAgICAgICAgZXYgPSByLmdldCgiZXZpZGVuY2UiKSBvciAiIgogICAgICAgIGlmIF9TU0xf"
    "VkVSSUZZX0hJTlRfTUFSS0VSIGluIGV2OgogICAgICAgICAgICBhZmZlY3RlZF9yb3dzICs9IDEKICAgICAgICAgICAgYWZm"
    "ZWN0ZWRfaWRzLmFkZChyWyJpZCJdKQogICAgaWYgbm90IGFmZmVjdGVkX3Jvd3M6CiAgICAgICAgcmV0dXJuCiAgICBwcmlu"
    "dCgiLSIgKiA3MCkKICAgIHByaW50KGYiVExTIENFUlRJRklDQVRFIFZFUklGSUNBVElPTiBGQUlMRUQgb24ge2FmZmVjdGVk"
    "X3Jvd3N9IHJvdyhzKSBhY3Jvc3Mge2xlbihhZmZlY3RlZF9pZHMpfSAiCiAgICAgICAgICBmImNoZWNrbGlzdCBJRChzKSAt"
    "IGV2ZXJ5IGNoZWNrIHRoYXQgbmVlZGVkIGFuIEhUVFBTIHJlcXVlc3QgdG8gdGhpcyB0YXJnZXQgZ290IGFuIFNTTCBjZXJ0"
    "LXZlcmlmeSIpCiAgICBwcmludCgiZXJyb3IgaW5zdGVhZCBvZiBhIHJlYWwgcmVzdWx0IGZvciB0aGF0IHJlcXVlc3QgKHNl"
    "ZSB0aG9zZSByb3dzJyBldmlkZW5jZSBmb3IgdGhlIGV4YWN0IHJlYXNvbikuIikKICAgIHByaW50KCJJZiB0aGlzIGlzIGFu"
    "IGV4cGVjdGVkIHNlbGYtc2lnbmVkL2ludGVybmFsL1VBVCBjZXJ0aWZpY2F0ZSwgcmUtcnVuIHdpdGggLS1pbnNlY3VyZSB0"
    "byBza2lwIikKICAgIHByaW50KCJ2ZXJpZmljYXRpb24gYW5kIGdldCByZWFsIHJlc3VsdHM7IGlmIHlvdSBleHBlY3RlZCBh"
    "IHRydXN0ZWQgY2VydGlmaWNhdGUsIHRoaXMgaXMgaXRzZWxmIGEiKQogICAgcHJpbnQoImxlZ2l0aW1hdGUgZmluZGluZyAo"
    "V0EtVExTLTQwNy1zdHlsZSBjaGFpbiBpc3N1ZSkgd29ydGggcmVwb3J0aW5nIGFzLWlzLiIpCiAgICBwcmludCgiLSIgKiA3"
    "MCkKCgpkZWYgcHJpbnRfc3VtbWFyeSh4bHN4X29rKToKICAgIGNvdW50cyA9IHt9CiAgICBmb3IgciBpbiBSRVNVTFRTOgog"
    "ICAgICAgIGNvdW50c1tyWyJyZXN1bHQiXV0gPSBjb3VudHMuZ2V0KHJbInJlc3VsdCJdLCAwKSArIDEKICAgIHRvdGFsID0g"
    "bGVuKFJFU1VMVFMpCiAgICBwcmludCgiXG4iICsgIj0iICogNzApCiAgICBwcmludChmIlNVTU1BUlkgLSB7dG90YWx9IGNo"
    "ZWNrbGlzdCByb3dzIHByb2R1Y2VkIGFjcm9zcyAiCiAgICAgICAgICBmIntsZW4oc2V0KHJbJ3NvdXJjZV9pbnB1dCddIGZv"
    "ciByIGluIFJFU1VMVFMpKX0gaW5wdXQgVVJMKHMpICIKICAgICAgICAgIGYiKHtsZW4oc2V0KChyWyd1cmwnXSwgclsndXJs"
    "X3JvbGUnXSkgZm9yIHIgaW4gUkVTVUxUUykpfSBVUkwrcm9sZSBwYXNzZXMpIikKICAgIGZvciBrIGluIFsiRkFJTCIsICJQ"
    "QVNTIiwgIk1BTlVBTCIsICJJTkZPIiwgIkVSUk9SIl06CiAgICAgICAgaWYgayBpbiBjb3VudHM6CiAgICAgICAgICAgIHBy"
    "aW50KGYiICB7azo4c306IHtjb3VudHNba119IikKICAgIHNjcmVlbnNob3RfY291bnQgPSBzdW0oMSBmb3IgciBpbiBSRVNV"
    "TFRTIGlmIHIuZ2V0KCJldmlkZW5jZV9pbWFnZV9iYXNlNjQiKSkKICAgIGlmIHNjcmVlbnNob3RfY291bnQ6CiAgICAgICAg"
    "cHJpbnQoZiIgIFNjcmVlbnNob3RzIGdlbmVyYXRlZDoge3NjcmVlbnNob3RfY291bnR9IikKICAgIHByaW50X2F1dGhfY292"
    "ZXJhZ2VfYWN0dWFsKCkKICAgIHByaW50X3NzbF92ZXJpZnlfc3VtbWFyeV9jYWxsb3V0KCkKICAgIHByaW50KCItIiAqIDcw"
    "KQogICAgcHJpbnQoIlRoaXMgY292ZXJzIDEzIGNoZWNrbGlzdCBjYXRlZ29yaWVzICh+Nzcgb2YgdGhlIH40MjEgdG90YWwg"
    "bWFzdGVyLWNoZWNrbGlzdCIpCiAgICBwcmludCgiaXRlbXMpIHRoYXQgYXJlIHNhZmVseSwgbm9uLWRlc3RydWN0aXZlbHkg"
    "dGVzdGFibGUgYnkgc2NyaXB0OiBIVFRQIFNlY3VyaXR5IikKICAgIHByaW50KCJIZWFkZXJzLCBTU0wvVExTIChwYXJ0aWFs"
    "IC0gcmVhbCBncmFkZS9jaXBoZXItY2hlY2sgdmlhIG5tYXAvc3NseXplL3NzbHNjYW4vIikKICAgIHByaW50KCJ0ZXN0c3Ns"
    "LnNoIGlmIGluc3RhbGxlZCksIENsaWNramFja2luZyAocGFydGlhbCksIENPUlMsIEluZm9ybWF0aW9uIEdhdGhlcmluZyIp"
    "CiAgICBwcmludCgiKHBhcnRpYWwpLCBDb25maWd1cmF0aW9uIFRlc3RpbmcgKHBhcnRpYWwpLCBTZXNzaW9uIE1hbmFnZW1l"
    "bnQgKHBhcnRpYWwpLCIpCiAgICBwcmludCgiQ2xpZW50LVNpZGUgVGVzdGluZyAobG9jYWwvc2Vzc2lvbiBzdG9yYWdlIGhl"
    "dXJpc3RpYyksIEVtYWlsIFNlY3VyaXR5LCIpCiAgICBwcmludCgiSW5mb3JtYXRpb24gRGlzY2xvc3VyZSwgSFRUUCBIb3N0"
    "IEhlYWRlciBBdHRhY2tzIChiYXNpYyBwcm9iZSksIGFuZCBBY2Nlc3MiKQogICAgcHJpbnQoIkNvbnRyb2wgLyBBdXRob3Jp"
    "emF0aW9uIFRlc3RpbmcgKGZvcmNlLWJyb3dzZS9JRE9SL2hvcml6b250YWwtZXNjYWxhdGlvbiAtIikKICAgIHByaW50KCJv"
    "bmx5IHJ1bnMgZm9yIHJlYWwgd2hlbiAtLWNvb2tpZS8tLWNvb2tpZTIgKG9yIC0tYWNjb3VudDEtY29va2llLy0tYWNjb3Vu"
    "dDItIikKICAgIHByaW50KCJjb29raWUpIGFyZSBnaXZlbiwgb3RoZXJ3aXNlIE1BTlVBTCkuIEV2ZXJ5dGhpbmcgZWxzZSBp"
    "biB0aGUgbWFzdGVyIGNoZWNrbGlzdCAtIFNRTCBJbmplY3Rpb24sIikKICAgIHByaW50KCJYU1MsIEJ1c2luZXNzIExvZ2lj"
    "LCBSYWNlIENvbmRpdGlvbnMsIGV0Yy4gLSBzdGlsbCBuZWVkcyB0aGUgdG9vbCBuYW1lZCBpbiIpCiAgICBwcmludCgidGhh"
    "dCBpdGVtJ3MgJ1Rvb2xzJyBjb2x1bW4gKHNxbG1hcCwgQnVycCwgbnVjbGVpLCAuLi4pIG9yIG1hbnVhbCB0ZXN0aW5nOyIp"
    "CiAgICBwcmludCgiZXZlcnkgcm93IGFib3ZlIHdpdGggcmVzdWx0PU1BTlVBTCBzdGFydHMgd2l0aCB0aGUgZml4ZWQgcGhy"
    "YXNlICdNYW51YWwgdGVzdCIpCiAgICBwcmludCgicmVxdWlyZWQuJyBzbyB5b3UgY2FuIGZpbHRlci9zZWFyY2ggZm9yIGl0"
    "IGRpcmVjdGx5LiIpCiAgICBpZiBub3QgeGxzeF9vazoKICAgICAgICBwcmludCgiLSIgKiA3MCkKICAgICAgICBwcmludCgi"
    "Tk9URTogLnhsc3ggd2FzIE5PVCB3cml0dGVuIHRoaXMgcnVuIChzZWUgbWVzc2FnZSBhYm92ZSkgLSAuY3N2Ly5qc29uIGFy"
    "ZSBjb21wbGV0ZS4iKQogICAgcHJpbnQoIj0iICogNzApCgoKZGVmIG1haW4oKToKICAgIGFwID0gYXJncGFyc2UuQXJndW1l"
    "bnRQYXJzZXIoZGVzY3JpcHRpb249IkF1dG9tYXRlZCBwcmUtY2hlY2sgc2Nhbm5lciBmb3IgdGhlIFdQVCBtYXN0ZXIgY2hl"
    "Y2tsaXN0IChzZWUgbW9kdWxlIGRvY3N0cmluZykuIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcm1h"
    "dHRlcl9jbGFzcz1hcmdwYXJzZS5SYXdEZXNjcmlwdGlvbkhlbHBGb3JtYXR0ZXIsCiAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICBlcGlsb2c9X19kb2NfXykKICAgIHNyYyA9IGFwLmFkZF9tdXR1YWxseV9leGNsdXNpdmVfZ3JvdXAocmVx"
    "dWlyZWQ9VHJ1ZSkKICAgIHNyYy5hZGRfYXJndW1lbnQoIi0tdXJsIiwgaGVscD0iU2luZ2xlIHRhcmdldCBVUkwgdG8gdGVz"
    "dCIpCiAgICBzcmMuYWRkX2FyZ3VtZW50KCItLXVybC1maWxlIiwgaGVscD0iUGF0aCB0byBhIHRleHQgZmlsZSB3aXRoIG9u"
    "ZSBVUkwgcGVyIGxpbmUgKCMgY29tbWVudHMvYmxhbmsgbGluZXMgaWdub3JlZCkgLSBldmVyeSBVUkwgaW4gaXQgaXMgdGVz"
    "dGVkIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1vdXQiLCBoZWxwPSJPdXRwdXQgYmFzZSBmaWxlbmFtZSwgV0lUSE9VVCBl"
    "eHRlbnNpb24gLSB3cml0ZXMgPG91dD4uY3N2LCA8b3V0Pi5qc29uIGFuZCA8b3V0Pi54bHN4LiBEZWZhdWx0OiBjaGVja2xp"
    "c3Rfc2Nhbl88dGltZXN0YW1wPiIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tdGltZW91dCIsIHR5cGU9ZmxvYXQsIGRlZmF1"
    "bHQ9MTAsIGhlbHA9IlBlci1yZXF1ZXN0IHRpbWVvdXQgaW4gc2Vjb25kcyAoZGVmYXVsdDogMTApIikKICAgIGFwLmFkZF9h"
    "cmd1bWVudCgiLS1pbnNlY3VyZSIsIGFjdGlvbj0ic3RvcmVfdHJ1ZSIsIGhlbHA9IkRvbid0IHZlcmlmeSBUTFMgY2VydGlm"
    "aWNhdGVzIChzZWxmLXNpZ25lZC9pbnRlcm5hbCBsYWIgdGFyZ2V0cykiKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLXNraXAt"
    "cm9vdC1wYXNzIiwgYWN0aW9uPSJzdG9yZV90cnVlIiwKICAgICAgICAgICAgICAgICAgICAgaGVscD0iT25seSB0ZXN0IHRo"
    "ZSBleGFjdCBVUkwgZ2l2ZW4gLSBza2lwIHRoZSBhdXRvbWF0aWMgZXh0cmEgcGFzcyBhZ2FpbnN0IHRoYXQgaG9zdCdzIHNp"
    "dGUgcm9vdC4gRGVmYXVsdDogT0ZGIChib3RoIGFyZSB0ZXN0ZWQpIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1wb3J0LXNj"
    "YW4iLCBhY3Rpb249InN0b3JlX3RydWUiLCBoZWxwPSJBbHNvIHJ1biB0aGUgbGlnaHQgY29tbW9uLWFkbWluLXBvcnQgc2Nh"
    "biAoV0EtT1RHLTI4MykuIE9mZiBieSBkZWZhdWx0IC0gbm9pc2llci4iKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLWRraW0t"
    "c2VsZWN0b3IiLCBhY3Rpb249ImFwcGVuZCIsIGhlbHA9IkV4dHJhIERLSU0gc2VsZWN0b3IgdG8gdHJ5IChyZXBlYXRhYmxl"
    "KSwgaW4gYWRkaXRpb24gdG8gdGhlIGJ1aWx0LWluIGNvbW1vbiBsaXN0IikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1kZWxh"
    "eSIsIHR5cGU9ZmxvYXQsIGRlZmF1bHQ9MCwgaGVscD0iRGVsYXkgaW4gc2Vjb25kcyBiZXR3ZWVuIGVhY2ggVVJMK3JvbGUg"
    "cGFzcyAoZGVmYXVsdDogMCkiKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLXNjcmVlbnNob3QiLCBjaG9pY2VzPVsibm9uZSIs"
    "ICJmYWlsIiwgImZhaWwrcGFzcyIsICJhbGwiXSwgZGVmYXVsdD0iZmFpbCIsCiAgICAgICAgICAgICAgICAgICAgIGhlbHA9"
    "IldoaWNoIHJvd3MgZ2V0IGFuIGF1dG8tZ2VuZXJhdGVkIGV2aWRlbmNlIHNjcmVlbnNob3QgKG5lZWRzIFBpbGxvdykuIERl"
    "ZmF1bHQ6IGZhaWwiKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLW5vLWNsaS10b29scyIsIGFjdGlvbj0ic3RvcmVfdHJ1ZSIs"
    "CiAgICAgICAgICAgICAgICAgICAgIGhlbHA9IkRvbid0IHNoZWxsIG91dCB0byBjdXJsL25tYXAvc3NseXplL3NzbHNjYW4v"
    "dGVzdHNzbC5zaCBldmVuIGlmIGluc3RhbGxlZCAtICIKICAgICAgICAgICAgICAgICAgICAgICAgICAidXNlIHRoZSBwdXJl"
    "LVB5dGhvbi9NQU5VQUwgZmFsbGJhY2sgYmVoYXZpb3VyIG9ubHkiKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLWFjY291bnQx"
    "LWNvb2tpZSIsIGhlbHA9IlNlc3Npb24gQ29va2llIGhlYWRlciB2YWx1ZSBmb3IgYWNjb3VudCAxLCBlLmcuIFwic2Vzc2lv"
    "bmlkPWFiYzEyM1wiIC0gIgogICAgICAgICAgICAgICAgICAgICAiWU9VUiBPV04gYWxyZWFkeS1hdXRoZW50aWNhdGVkIHNl"
    "c3Npb24sIG5ldmVyIGhhcnZlc3RlZC9ndWVzc2VkIGJ5IHRoaXMgc2NyaXB0LiBFbmFibGVzIHJlYWwgIgogICAgICAgICAg"
    "ICAgICAgICAgICAiYXV0aC1ieXBhc3MgdGVzdGluZyAoV0EtT1RHLTMxMik7IGFkZCAtLWFjY291bnQyLWNvb2tpZSB0b28g"
    "Zm9yIGhvcml6b250YWwtZXNjYWxhdGlvbi9JRE9SICIKICAgICAgICAgICAgICAgICAgICAgImNoZWNrcy4gVXN1YWxseSB5"
    "b3Ugd2FudCAtLWNvb2tpZSBpbnN0ZWFkIChzZWUgYWJvdmUpIC0gaXQgZG9lcyBldmVyeXRoaW5nIHRoaXMgZG9lcyBQTFVT"
    "ICIKICAgICAgICAgICAgICAgICAgICAgImF1dGhlbnRpY2F0ZXMgZXZlcnkgb3RoZXIgY2hlY2sgaW4gdGhlIHN1aXRlOyB1"
    "c2UgLS1hY2NvdW50MS1jb29raWUgb25seSBpZiB5b3Ugc3BlY2lmaWNhbGx5ICIKICAgICAgICAgICAgICAgICAgICAgIndh"
    "bnQgSlVTVCB0aGUgYWNjZXNzLWNvbnRyb2wgY2hlY2tzIGF1dGhlbnRpY2F0ZWQgYW5kIGV2ZXJ5dGhpbmcgZWxzZSBydW4g"
    "YW5vbnltb3VzbHkuIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1hY2NvdW50MS1sYWJlbCIsIGhlbHA9IkRpc3BsYXkgbGFi"
    "ZWwgZm9yIGFjY291bnQgMSBpbiBldmlkZW5jZSB0ZXh0IChkZWZhdWx0OiAnQWNjb3VudCAxJykiKQogICAgYXAuYWRkX2Fy"
    "Z3VtZW50KCItLWFjY291bnQyLWNvb2tpZSIsIGhlbHA9IlNlc3Npb24gQ29va2llIGhlYWRlciB2YWx1ZSBmb3IgYWNjb3Vu"
    "dCAyIC0gYSBTRUNPTkQsIERJRkZFUkVOVCAiCiAgICAgICAgICAgICAgICAgICAgICJ1c2VyJ3Mgb3duIHNlc3Npb24gLSBl"
    "bmFibGVzIHRoZSB0d28tYWNjb3VudCBob3Jpem9udGFsLXByaXZpbGVnZS1lc2NhbGF0aW9uL0lET1IgY2hlY2tzICIKICAg"
    "ICAgICAgICAgICAgICAgICAgIihXQS1TUy0wNzEsIFdBLU9URy0zMTQpLiBVc3VhbGx5IHlvdSB3YW50IC0tY29va2llMiBp"
    "bnN0ZWFkIChzZWUgYWJvdmUpIC0gc2FtZSBlZmZlY3QsICIKICAgICAgICAgICAgICAgICAgICAgIm5hbWVkIHRvIHBhaXIg"
    "d2l0aCAtLWNvb2tpZS4iKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLWFjY291bnQyLWxhYmVsIiwgaGVscD0iRGlzcGxheSBs"
    "YWJlbCBmb3IgYWNjb3VudCAyIGluIGV2aWRlbmNlIHRleHQgKGRlZmF1bHQ6ICdBY2NvdW50IDInKSIpCiAgICBhcC5hZGRf"
    "YXJndW1lbnQoIi0tY29va2llIiwgaGVscD0iQ29va2llIGhlYWRlciB2YWx1ZSB0byBzZW5kIHdpdGggZXZlcnkgcmVxdWVz"
    "dCAoeW91ciBvd24gYWxyZWFkeS0iCiAgICAgICAgICAgICAgICAgICAgICJhdXRoZW50aWNhdGVkIHNlc3Npb24pLCBlLmcu"
    "IFwic2Vzc2lvbmlkPWFiYzEyMzsgY3NyZnRva2VuPXh5elwiLiBBcHBsaWVzIHRvIGV2ZXJ5IHNpbmdsZSAiCiAgICAgICAg"
    "ICAgICAgICAgICAgICJjaGVjaywgc28gcmVzdWx0cyByZWZsZWN0IHdoYXQgYW4gYXV0aGVudGljYXRlZCB1c2VyIHNlZXMg"
    "LSBBTkQgYXV0b21hdGljYWxseSBhbHNvIGNvdmVycyAiCiAgICAgICAgICAgICAgICAgICAgICJ0aGUgV0EtT1RHLTMxMiBh"
    "dXRoLWJ5cGFzcyBjaGVjayAoc2FtZSBhcyBwYXNzaW5nIHRoaXMgc2FtZSB2YWx1ZSBhcyAtLWFjY291bnQxLWNvb2tpZSks"
    "IHNvICIKICAgICAgICAgICAgICAgICAgICAgInlvdSBkb24ndCBuZWVkIHRvIHBhc3MgdGhlIHNhbWUgY29va2llIHR3aWNl"
    "LiBTZWUgdGhlIGNvdmVyYWdlIHJlcG9ydCBwcmludGVkIGF0IHRoZSBzdGFydCAiCiAgICAgICAgICAgICAgICAgICAgICJv"
    "ZiBldmVyeSBydW4gZm9yIGV4YWN0bHkgd2hhdCBvbmUgY29va2llIGRvZXMvZG9lc24ndCBjb3Zlci4iKQogICAgYXAuYWRk"
    "X2FyZ3VtZW50KCItLWNvb2tpZTIiLCBoZWxwPSJBIFNFQ09ORCwgRElGRkVSRU5UIGFjY291bnQncyBvd24gQ29va2llIGhl"
    "YWRlciB2YWx1ZSwgZS5nLiAiCiAgICAgICAgICAgICAgICAgICAgICJcInNlc3Npb25pZD14eXo3ODlcIi4gT25seSBtZWFu"
    "aW5nZnVsIHRvZ2V0aGVyIHdpdGggLS1jb29raWUgLSBhdXRvbWF0aWNhbGx5IGV4dGVuZHMgIgogICAgICAgICAgICAgICAg"
    "ICAgICAiY292ZXJhZ2UgdG8gdGhlIHR3by1hY2NvdW50IGhvcml6b250YWwtcHJpdmlsZWdlLWVzY2FsYXRpb24vSURPUiBj"
    "aGVja3MgKFdBLVNTLTA3MSwgIgogICAgICAgICAgICAgICAgICAgICAiV0EtT1RHLTMxNCksIGNvbXBhcmluZyAtLWNvb2tp"
    "ZSdzIGFjY291bnQgYWdhaW5zdCB0aGlzIG9uZSAoc2FtZSBhcyBwYXNzaW5nIHRoaXMgdmFsdWUgYXMgIgogICAgICAgICAg"
    "ICAgICAgICAgICAiLS1hY2NvdW50Mi1jb29raWUpLiBOb3Qgc2VudCB3aXRoIGV2ZXJ5IHJlcXVlc3QgbGlrZSAtLWNvb2tp"
    "ZSBpcyAtIG9ubHkgdXNlZCBmb3IgdGhhdCAiCiAgICAgICAgICAgICAgICAgICAgICJzcGVjaWZpYyB0d28tYWNjb3VudCBj"
    "b21wYXJpc29uLiIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0taGVhZGVyIiwgYWN0aW9uPSJhcHBlbmQiLCBtZXRhdmFyPSIn"
    "TmFtZTogVmFsdWUnIiwKICAgICAgICAgICAgICAgICAgICAgaGVscD0iRXh0cmEgaGVhZGVyIHRvIHNlbmQgd2l0aCBldmVy"
    "eSByZXF1ZXN0IChyZXBlYXRhYmxlKSwgZS5nLiAtLWhlYWRlciBcIkF1dGhvcml6YXRpb246ICIKICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAiQmVhcmVyIGV5Si4uLlwiLiBBcHBsaWVzIGV2ZXJ5d2hlcmUgLS1jb29raWUgZG9lczsgYSBoZWFkZXIg"
    "bmFtZWQgaGVyZSBhbHdheXMgd2lucyBvdmVyICIKICAgICAgICAgICAgICAgICAgICAgICAgICAiYW4gaWRlbnRpY2FsbHkt"
    "bmFtZWQgb25lIGZyb20gLS1jb29raWUgaWYgdGhleSBzb21laG93IG92ZXJsYXAuIikKICAgIGFwLmFkZF9hcmd1bWVudCgi"
    "LS1vbmx5IiwgYWN0aW9uPSJhcHBlbmQiLCBtZXRhdmFyPSJJRCIsCiAgICAgICAgICAgICAgICAgICAgIGhlbHA9IlJlc3Ry"
    "aWN0IG91dHB1dCB0byBqdXN0IHRoaXMgQ2hlY2tsaXN0IElEIChyZXBlYXRhYmxlLCBhbmQvb3IgY29tbWEtc2VwYXJhdGVk"
    "IC0gZS5nLiAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgIi0tb25seSBXQS1IRFItMzkyIC0tb25seSBXQS1TUy0wMDEs"
    "V0EtU1MtMDAyKS4gRXZlcnkgY2hlY2sgc3RpbGwgcnVucyAodGhleSdyZSBhbGwgZmFzdCAiCiAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgIkhUVFAvVExTIHByb2JlcyksIGJ1dCByb3dzIGZvciBhbnkgb3RoZXIgSUQgYXJlIGRyb3BwZWQgYmVmb3Jl"
    "IGJlaW5nIHdyaXR0ZW4gb3V0LiBNZWFudCAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgImZvciBhICdyZXJ1biBzZWxl"
    "Y3RlZCByb3dzIG9ubHknIHdvcmtmbG93IGRyaXZlbiBieSBhbm90aGVyIHRvb2wgKGUuZy4gYSBCdXJwIGV4dGVuc2lvbikg"
    "IgogICAgICAgICAgICAgICAgICAgICAgICAgICJyYXRoZXIgdGhhbiB0eXBpY2FsIGludGVyYWN0aXZlIHVzZS4iKQogICAg"
    "YXAuYWRkX2FyZ3VtZW50KCItLWNyZWRzIiwgYWN0aW9uPSJhcHBlbmQiLCBtZXRhdmFyPSInbGFiZWw6OmNvb2tpZSciLAog"
    "ICAgICAgICAgICAgICAgICAgICBoZWxwPSJBIGZyaWVuZGxpZXIgYWx0ZXJuYXRpdmUgdG8gLS1jb29raWUvLS1jb29raWUy"
    "Ly0tYWNjb3VudDEtbGFiZWwvLS1hY2NvdW50Mi1sYWJlbCwgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJyZXBlYXRh"
    "YmxlIHVwIHRvIHR3aWNlICgxc3QgPSBhY2NvdW50IDEsIDJuZCA9IGFjY291bnQgMikuIFRoaXMgc2NyaXB0IGhhcyBubyBs"
    "b2dpbiAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgImZsb3cgYXQgYWxsIChieSBkZXNpZ24pIGFuZCBuZXZlciB1c2Vz"
    "IGEgcGFzc3dvcmQsIHNvIFJFQ09NTUVOREVEIGZvcm1hdCBpcyBqdXN0ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAi"
    "XCJsYWJlbDo6c2Vzc2lvbmlkPS4uLlwiIC0gbm8gcGFzc3dvcmQgbmVlZGVkLCBkb24ndCB3YXN0ZSB0aW1lIHR5cGluZyBv"
    "bmUuIEEgYmFyZSAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgImNvb2tpZSB3aXRoIG5vIGxhYmVsIGFsc28gd29ya3M6"
    "IFwic2Vzc2lvbmlkPS4uLlwiIG9uIGl0cyBvd24uIChMZWdhY3kgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJcImxh"
    "YmVsOnBhc3N3b3JkOjpzZXNzaW9uaWQ9Li4uXCIgaXMgc3RpbGwgYWNjZXB0ZWQgZm9yIGNvbXBhdGliaWxpdHkgLSBhbnkg"
    "IgogICAgICAgICAgICAgICAgICAgICAgICAgICJcInBhc3N3b3JkXCIgdHlwZWQgdGhlcmUgaXMgcGFyc2VkIG91dCBhbmQg"
    "ZGlzY2FyZGVkLCBORVZFUiBzdG9yZWQsIGxvZ2dlZCwgb3IgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJ3cml0dGVu"
    "IHRvIGV2aWRlbmNlL0pTT04vQ1NWIGFueXdoZXJlLCBhbmQgbmV2ZXIgdXNlZCB0byBsb2cgaW4uKSBUaGUgbGFiZWwgYmVj"
    "b21lcyAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgInRoYXQgYWNjb3VudCdzIHJlYWRhYmxlIG5hbWUgaW4gZXZpZGVu"
    "Y2UgdGV4dC4gT25seSB0aGUgcGFydCBhZnRlciBcIjo6XCIgKG9yIHRoZSAiCiAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "Indob2xlIGVudHJ5LCBmb3IgYSBiYXJlIGNvb2tpZSkgaXMgd2hhdCBhY3R1YWxseSBhdXRoZW50aWNhdGVzIHJlcXVlc3Rz"
    "IC0gYW4gZW50cnkgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJ3aXRoIG5vIHVzYWJsZSBjb29raWUgaXMgcmVwb3J0"
    "ZWQgYXMgc2tpcHBlZC4gVHdvIGNvb2tpZSB2YWx1ZXMgZm9yIHRoZSBTQU1FIGFjY291bnQgIgogICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICIoZS5nLiBhIHNlc3Npb24gY29va2llIHBsdXMgYSBzZXBhcmF0ZSBDU1JGL1hTUkYgY29va2llKSBnbyBv"
    "biBvbmUgbGluZSwgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJzZW1pY29sb24tc2VwYXJhdGVkOiBcImFsaWNlOjpK"
    "U0VTU0lPTklEPWFiYzEyMzsgWFNSRi1UT0tFTj1kZWY0NTZcIi4gRXhhbXBsZXM6ICIKICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAiLS1jcmVkcyBcImFsaWNlOjpzZXNzaW9uaWQ9YWJjMTIzXCIgLS1jcmVkcyBcImJvYjo6c2Vzc2lvbmlkPXh5ejc4"
    "OVwiIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1jcmVkcy1maWxlIiwgbWV0YXZhcj0iUEFUSCIsCiAgICAgICAgICAgICAg"
    "ICAgICAgIGhlbHA9IlNhbWUgZm9ybWF0IGFzIC0tY3JlZHMsIG9uZSBlbnRyeSBwZXIgbGluZSwgcmVhZCBmcm9tIGEgdGV4"
    "dCBmaWxlIGluc3RlYWQgb2YgdGhlICIKICAgICAgICAgICAgICAgICAgICAgICAgICAiY29tbWFuZCBsaW5lICgjIGNvbW1l"
    "bnRzL2JsYW5rIGxpbmVzIGlnbm9yZWQpLiBPbmUgbGluZSA9IG9uZSBhY2NvdW50IChhY2NvdW50IDEgIgogICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICJvbmx5KTsgdHdvIGxpbmVzID0gYWNjb3VudCAxIChsaW5lIDEpIGFuZCBhY2NvdW50IDIgKGxp"
    "bmUgMikuIENvbWJpbmUgd2l0aCAtLWNyZWRzICIKICAgICAgICAgICAgICAgICAgICAgICAgICAidG8gYWRkIG1vcmUgZW50"
    "cmllcyBvbiB0b3Agb2YgdGhlIGZpbGUncyAtIGVudHJpZXMgYmV5b25kIDIgdG90YWwgYXJlIGRyb3BwZWQgd2l0aCBhICIK"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAid2FybmluZywgc2luY2UgdGhpcyBzY3JpcHQgb25seSBldmVyIGNvbXBhcmVz"
    "IGEgdHdvLWFjY291bnQgcGFpci4iKQogICAgYXJncyA9IGFwLnBhcnNlX2FyZ3MoKQoKICAgICMgLS1jcmVkcy8tLWNyZWRz"
    "LWZpbGUgcG9wdWxhdGUgYXJncy5jb29raWUvYXJncy5jb29raWUyL2FjY291bnQxX2xhYmVsLwogICAgIyBhY2NvdW50Ml9s"
    "YWJlbCAod2l0aG91dCBvdmVyd3JpdGluZyBhbnl0aGluZyBzZXQgZXhwbGljaXRseSB2aWEgdGhvc2UKICAgICMgZmxhZ3Mg"
    "ZGlyZWN0bHkpIEJFRk9SRSB0aGUgLS1jb29raWUvLS1jb29raWUyIC0+IGFjY291bnQxX2Nvb2tpZS8KICAgICMgYWNjb3Vu"
    "dDJfY29va2llIGRlcml2YXRpb24gcmlnaHQgYmVsb3csIHNvIHRoZSB0d28gZmVhdHVyZXMgY29tcG9zZToKICAgICMgYSAt"
    "LWNyZWRzLWZpbGUgd2l0aCBvbmUgbGluZSBiZWhhdmVzIGV4YWN0bHkgbGlrZSAtLWNvb2tpZSwgdHdvIGxpbmVzCiAgICAj"
    "IGV4YWN0bHkgbGlrZSAtLWNvb2tpZSArIC0tY29va2llMiwganVzdCB3aXRoIHJlYWRhYmxlIGxhYmVscyBhdHRhY2hlZC4K"
    "ICAgIGFwcGx5X2NyZWRzX2VudHJpZXMoYXJncykKCiAgICAjIC0tY29va2llLy0tY29va2llMiBkb3VibGUgYXMgLS1hY2Nv"
    "dW50MS1jb29raWUvLS1hY2NvdW50Mi1jb29raWUgZm9yCiAgICAjIHRoZSAyLWFjY291bnQgYWNjZXNzLWNvbnRyb2wvSURP"
    "UiBjaGVja3MgKGNoZWNrX2FjY2Vzc19jb250cm9sXzJmYSkKICAgICMgVU5MRVNTIC0tYWNjb3VudDEtY29va2llLy0tYWNj"
    "b3VudDItY29va2llIHdlcmUgZXhwbGljaXRseSBzZXQgdG8KICAgICMgc29tZXRoaW5nIGRpZmZlcmVudC4gVGhpcyBpcyB3"
    "aGF0IG1ha2VzIGNvdmVyYWdlICJhdXRvbWF0aWMiOiBwYXNzCiAgICAjIC0tY29va2llIGFsb25lIGFuZCBldmVyeSBjaGVj"
    "ayBpbiB0aGUgc3VpdGUgcnVucyBhdXRoZW50aWNhdGVkLAogICAgIyBpbmNsdWRpbmcgV0EtT1RHLTMxMiBmb3IgcmVhbDsg"
    "YWRkIC0tY29va2llMiBhbmQgV0EtU1MtMDcxLwogICAgIyBXQS1PVEctMzE0ICh3aGljaCBuZWVkIGEgc2Vjb25kLCBkaWZm"
    "ZXJlbnQgYWNjb3VudCB0byBjb21wYXJlCiAgICAjIGFnYWluc3QpIGF1dG9tYXRpY2FsbHkgZ2V0IHJlYWwgdGVzdGluZyB0"
    "b28gLSBubyBuZWVkIHRvIGFsc28gcmVwZWF0CiAgICAjIHRoZSBzYW1lIGNvb2tpZSB2YWx1ZSBvbiAtLWFjY291bnQxLWNv"
    "b2tpZS8tLWFjY291bnQyLWNvb2tpZS4KICAgIGlmIGFyZ3MuY29va2llIGFuZCBub3QgYXJncy5hY2NvdW50MV9jb29raWU6"
    "CiAgICAgICAgYXJncy5hY2NvdW50MV9jb29raWUgPSBhcmdzLmNvb2tpZQogICAgaWYgYXJncy5jb29raWUyIGFuZCBub3Qg"
    "YXJncy5hY2NvdW50Ml9jb29raWU6CiAgICAgICAgYXJncy5hY2NvdW50Ml9jb29raWUgPSBhcmdzLmNvb2tpZTIKCiAgICBn"
    "bG9iYWwgRVhUUkFfQVVUSF9IRUFERVJTLCBPTkxZX0lEUwogICAgaWYgYXJncy5jb29raWU6CiAgICAgICAgRVhUUkFfQVVU"
    "SF9IRUFERVJTWyJDb29raWUiXSA9IGFyZ3MuY29va2llCiAgICBpZiBhcmdzLmhlYWRlcjoKICAgICAgICBmb3IgaCBpbiBh"
    "cmdzLmhlYWRlcjoKICAgICAgICAgICAgaWYgIjoiIG5vdCBpbiBoOgogICAgICAgICAgICAgICAgcHJpbnQoZiJbIV0gSWdu"
    "b3JpbmcgbWFsZm9ybWVkIC0taGVhZGVyIHtoIXJ9IC0gZXhwZWN0ZWQgXCJOYW1lOiBWYWx1ZVwiIiwgZmlsZT1zeXMuc3Rk"
    "ZXJyKQogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgbmFtZSwgXywgdmFsdWUgPSBoLnBhcnRpdGlvbigi"
    "OiIpCiAgICAgICAgICAgIEVYVFJBX0FVVEhfSEVBREVSU1tuYW1lLnN0cmlwKCldID0gdmFsdWUuc3RyaXAoKQogICAgaWYg"
    "YXJncy5vbmx5OgogICAgICAgIE9OTFlfSURTID0gc2V0KCkKICAgICAgICBmb3IgcmF3IGluIGFyZ3Mub25seToKICAgICAg"
    "ICAgICAgT05MWV9JRFMudXBkYXRlKHguc3RyaXAoKSBmb3IgeCBpbiByYXcuc3BsaXQoIiwiKSBpZiB4LnN0cmlwKCkpCgog"
    "ICAgdXJscyA9IFthcmdzLnVybF0gaWYgYXJncy51cmwgZWxzZSByZWFkX3VybF9saXN0KGFyZ3MudXJsX2ZpbGUpCiAgICBp"
    "ZiBub3QgdXJsczoKICAgICAgICBwcmludCgiTm8gVVJMcyB0byBzY2FuLiIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICBz"
    "eXMuZXhpdCgxKQoKICAgIGlmIGFyZ3Mubm9fY2xpX3Rvb2xzOgogICAgICAgIHByaW50KCJbKl0gLS1uby1jbGktdG9vbHMg"
    "c2V0IC0gY3VybC9ubWFwL3NzbHl6ZS9zc2xzY2FuL3Rlc3Rzc2wuc2ggd2lsbCBOT1QgYmUgdXNlZCBldmVuIGlmIGluc3Rh"
    "bGxlZC4iKQogICAgZWxzZToKICAgICAgICBmb3VuZCA9IFt0IGZvciB0IGluICgiY3VybCIsICJubWFwIiwgInNzbHl6ZSIs"
    "ICJzc2xzY2FuIiwgInRlc3Rzc2wuc2giKSBpZiBfY2xpX2F2YWlsYWJsZSh0KV0KICAgICAgICBpZiBmb3VuZDoKICAgICAg"
    "ICAgICAgcHJpbnQoZiJbKl0gQ29tbWFuZC1saW5lIHRvb2xzIGRldGVjdGVkIG9uIFBBVEggYW5kIHdpbGwgYmUgdXNlZCBh"
    "dXRvbWF0aWNhbGx5OiB7JywgJy5qb2luKGZvdW5kKX0iKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHByaW50KCJbKl0g"
    "Tm8gY3VybC9ubWFwL3NzbHl6ZS9zc2xzY2FuL3Rlc3Rzc2wuc2ggZm91bmQgb24gUEFUSCAtIHRob3NlIGNoZWNrcyBzdGF5"
    "IE1BTlVBTC9QeXRob24tb25seS4iKQogICAgcHJpbnRfYXV0aF9jb3ZlcmFnZV9wbGFuKGFyZ3MpCgogICAgZm9yIHUgaW4g"
    "dXJsczoKICAgICAgICBzY2FuX3VybCh1LCBhcmdzKQoKICAgIGltYWdlX2J5dGVzID0gZ2VuZXJhdGVfc2NyZWVuc2hvdHMo"
    "YXJncy5zY3JlZW5zaG90KQoKICAgIHN0YW1wID0gZGF0ZXRpbWUubm93KCkuc3RyZnRpbWUoIiVZJW0lZC0lSCVNJVMiKQog"
    "ICAgb3V0X2Jhc2UgPSBhcmdzLm91dCBvciBmImNoZWNrbGlzdF9zY2FuX3tzdGFtcH0iCiAgICBmb3IgZXh0IGluICgiLmNz"
    "diIsICIuanNvbiIsICIueGxzeCIpOgogICAgICAgIGlmIG91dF9iYXNlLmxvd2VyKCkuZW5kc3dpdGgoZXh0KToKICAgICAg"
    "ICAgICAgb3V0X2Jhc2UgPSBvdXRfYmFzZVs6IC1sZW4oZXh0KV0KICAgIGNzdl9wYXRoLCBqc29uX3BhdGgsIHhsc3hfcGF0"
    "aCA9IG91dF9iYXNlICsgIi5jc3YiLCBvdXRfYmFzZSArICIuanNvbiIsIG91dF9iYXNlICsgIi54bHN4IgogICAgY29uc29s"
    "aWRhdGVkX2Nzdl9wYXRoID0gb3V0X2Jhc2UgKyAiX2NvbnNvbGlkYXRlZC5jc3YiCiAgICBjb25zb2xpZGF0ZWRfanNvbl9w"
    "YXRoID0gb3V0X2Jhc2UgKyAiX2NvbnNvbGlkYXRlZC5qc29uIgoKICAgIHdyaXRlX2Nzdihjc3ZfcGF0aCkKICAgIHdyaXRl"
    "X2pzb24oanNvbl9wYXRoKQogICAgd3JpdGVfY29uc29saWRhdGVkX2Nzdihjb25zb2xpZGF0ZWRfY3N2X3BhdGgpCiAgICB3"
    "cml0ZV9jb25zb2xpZGF0ZWRfanNvbihjb25zb2xpZGF0ZWRfanNvbl9wYXRoKQogICAgeGxzeF9vayA9IHdyaXRlX3hsc3go"
    "eGxzeF9wYXRoLCBpbWFnZV9ieXRlcykKCiAgICBwcmludF9zdW1tYXJ5KHhsc3hfb2spCiAgICBwcmludCgiXG5SZXN1bHRz"
    "IHdyaXR0ZW4gdG86IikKICAgIHByaW50KGYiICBDU1YgIChwZXItVVJMIGRldGFpbCk6ICB7Y3N2X3BhdGh9IikKICAgIHBy"
    "aW50KGYiICBDU1YgIChvbmUgcm93IHBlciBJRCk6ICB7Y29uc29saWRhdGVkX2Nzdl9wYXRofSIpCiAgICBwcmludChmIiAg"
    "SlNPTiAocGVyLVVSTCBkZXRhaWwsIHVzZSB0aGlzIG9uZSBmb3IgdGhlIHBvcnRhbCBpbXBvcnQgLSBzZWUgUkVBRE1FKTog"
    "e2pzb25fcGF0aH0iKQogICAgcHJpbnQoZiIgIEpTT04gKG9uZSByb3cgcGVyIElEKTogIHtjb25zb2xpZGF0ZWRfanNvbl9w"
    "YXRofSIpCiAgICBpZiB4bHN4X29rOgogICAgICAgIHByaW50KGYiICBYTFNYICgnQ29uc29saWRhdGVkJyBzaGVldCArICdT"
    "Y2FuIFJlc3VsdHMgKERldGFpbCknIHNoZWV0KToge3hsc3hfcGF0aH0iKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6"
    "CiAgICBtYWluKCkK"
)


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    # ------------------------------------------------------------------
    # Burp extension entry point
    # ------------------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

        self._rows = []             # last scan's parsed result rows (list of dict)
        self._burp_issues_raw = []  # full-detail Burp Scanner issue dicts, same order as _burp_issues_model rows
        self._worst_findings_rows = []  # row dicts behind Summary's Failed vulnerabilities table, same order
        self._last_out_base = None  # path prefix of the last scan's output files
        self._last_xlsx_ok = True   # False if the last scan's .xlsx wasn't written (missing pandas/xlsxwriter)
        self._scan_running = False
        self._scan_proc = None      # the live checklist_auto_scan.py subprocess, if a scan is running
        self._scan_timer = None     # watchdog timer that kills a hung subprocess (see _start_scan)
        self._scan_cancelled = False

        # Detailed Results filter state - a category/group AND a result
        # type AND a free-text search can all be active at once (e.g.
        # "SQL Injection" + "FAIL" + "cookie").
        self._filter_categories = None
        self._filter_result = None
        self._filter_search_text = ""

        self._build_ui()
        callbacks.addSuiteTab(self)
        # Reported directly: "when I can confirm the test XSS in repeater
        # or proxy or intruder selected output can be moved to quickchop
        # for a record vulnerability list" - registers this class's
        # createMenuItems() (below) as a right-click context menu source
        # across every Burp tool (Proxy, Repeater, Intruder, Target,
        # Scanner, ...), adding a "Log finding to QuickChop..." item that
        # opens _open_log_finding_dialog() pre-filled with whatever
        # request/response was right-clicked.
        callbacks.registerContextMenuFactory(self)
        callbacks.printOutput("%s loaded. Open the '%s' tab to configure and run." % (EXT_NAME, EXT_NAME))

    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self._main_panel

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())

        # Reported directly: JTabbedPane.LEFT (vertical tabs down the left
        # edge) rendered "tottaly collapsed" in Burp's embedded panel - only
        # the first tab's label was visible and the rest were unreachable,
        # which also meant there was "no option to enter target and cheks"
        # since Configuration lived on one of the unreachable tabs. Switched
        # to JTabbedPane.TOP (Swing's default, most-tested tab placement) to
        # fix that outright, matching the latest request too: "on top tabs,
        # left sected details ... scan status should comes in summary".
        # Tab order: Summary, Configuration, Categories, then the existing
        # Detailed Results / Burp Findings tabs. NOTE: if this order changes,
        # update the index used by _apply_filter()'s
        # self._tabs.setSelectedIndex(...) call.
        self._tabs = JTabbedPane(JTabbedPane.TOP)
        self._tabs.addTab("Summary", self._build_summary_panel())
        self._tabs.addTab("Configuration", self._build_config_panel())
        self._tabs.addTab("Categories", self._build_categories_panel())
        self._tabs.addTab("Detailed Results", self._build_results_panel())
        self._tabs.addTab("Burp Scanner Findings (context only)", self._build_burp_findings_panel())
        # Reported directly: "reference sho all the check list items with
        # name ows id default sevarity etc" - added at the end so the
        # hardcoded self._tabs.setSelectedIndex(3) for Detailed Results
        # above doesn't need to change.
        self._tabs.addTab("Checklist Reference", self._build_checklist_reference_panel())
        # Reported directly: "run and export appearing in two places when i
        # go to config page and moving back to other page config page stays
        # same only top findings are changing" / "something went terribly
        # wrong" (screenshot showed a mostly-blank window with a tab
        # missing from the strip) - forces a full repaint of the tab strip
        # and whichever tab is newly selected every time the selection
        # changes, working around stale/blank Swing rendering after a
        # background-thread-driven UI update. See _TabChangeListener.
        self._tabs.addChangeListener(_TabChangeListener(self))
        self._main_panel.add(self._tabs, BorderLayout.CENTER)

        self._main_panel.add(self._build_status_bar(), BorderLayout.SOUTH)

        # NOTE: a call to self._populate_summary() used to live here, to
        # pre-fill the coverage tables with default 0-value rows before
        # any scan ran. Reverted - it ran extra table/JList-selection
        # logic synchronously during extension load, before the tab was
        # even shown, right when "QuickChop not loading / frozen on
        # load" started. Stability first; the coverage tables just stay
        # empty until the first scan again, like the earliest working
        # builds. Can revisit later once the tab-corruption issue is
        # confirmed fully resolved.

    def _titled_section(self, title):
        """A JPanel with a titled border, laid out top-to-bottom - the
        shared building block for every grouped section in the config
        panel below. Reported directly: "crate same with catagory
        overview, details resutls testing target, and export tabs to
        look neeat" - grouping related fields under labelled sections
        (instead of one long undifferentiated stack of rows) is the
        pure-Swing equivalent of the card-based mockup layout."""
        section = JPanel()
        section.setLayout(BoxLayout(section, BoxLayout.Y_AXIS))
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(title),
            BorderFactory.createEmptyBorder(2, 4, 6, 4)))
        section.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        return section

    def _build_config_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder("Configuration"))

        # --- Section: scanner setup ---
        setup = self._titled_section("Scanner setup")
        row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        row1.add(JLabel("Python 3 interpreter:"))
        self._python_path_field = JTextField("python3", 12)
        row1.add(self._python_path_field)
        # Reported directly: "make it one file instead of two python
        # files so it is easy to share with burp extension marketplace
        # without the dependency or need to share autoscan script
        # separately" - the "checklist_auto_scan.py path" field/Browse
        # button that used to live here are gone; the scan engine is now
        # embedded in this file (_ENGINE_SOURCE_B64, near the top) and
        # self-extracted to a temp .py at scan time by
        # _materialize_engine_script() - nothing left to point at.
        engine_note = JLabel("Scan engine: bundled with this extension (rev %s) - "
                              "self-extracted automatically, nothing to configure." % ENGINE_SOURCE_REV)
        engine_note.setFont(engine_note.getFont().deriveFont(11.0))
        engine_note.setForeground(Color(0x66, 0x66, 0x66))
        row1.add(engine_note)
        # Reported directly: "configuration tab not aligned properly.
        # targets and run progress bar is right aligned make sure
        # properly left aligned after the text" - root cause (confirmed
        # with a live Swing layout test): a BoxLayout.Y_AXIS container
        # positions each direct child using that child's alignmentX
        # RELATIVE TO ITS SIBLINGS, not independently - if even one
        # sibling in a titled section is left at Swing's default (0.5,
        # CENTER) while another is explicitly 0.0 (LEFT), BoxLayout's
        # cross-axis math splits the difference and renders the LEFT one
        # squeezed to roughly half-width, offset to roughly the
        # horizontal center - exactly the "right aligned" look reported.
        # Every direct child added to a BoxLayout.Y_AXIS section in this
        # file must set the SAME alignmentX as its siblings - LEFT,
        # consistently - or this comes back.
        row1.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        setup.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        row2.add(JLabel("Output folder:"))
        self._output_dir_field = JTextField(tempfile.gettempdir(), 34)
        row2.add(self._output_dir_field)
        out_browse_btn = JButton("Browse...")
        out_browse_btn.addActionListener(self._on_browse_output_dir)
        row2.add(out_browse_btn)
        row2.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        setup.add(row2)

        row6b = JPanel(FlowLayout(FlowLayout.LEFT))
        # Real command-line evidence toggle. Earlier builds always passed
        # --no-cli-tools here, which is why runs from inside Burp never
        # showed the real "$ curl ..." command + response that the
        # standalone CLI tool captures - reported directly: "it is not
        # looks like the output you showed... unable to check the request
        # and response". Defaulting this ON matches checklist_auto_scan.py's
        # own CLI default (auto-detect curl/nmap/sslyze/sslscan/testssl.sh
        # on PATH, silently skip whatever isn't installed) - untick it only
        # if you want the old fast/no-subprocess behaviour back.
        self._cli_tools_checkbox = JCheckBox(
            "Use command-line tools (curl/nmap/sslyze/sslscan/testssl.sh) if installed, "
            "for real request/response evidence", True)
        row6b.add(self._cli_tools_checkbox)
        row6b.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        setup.add(row6b)
        panel.add(setup)

        # --- Section: targets & session ---
        targets_section = self._titled_section("Targets & session")
        row3 = JPanel(FlowLayout(FlowLayout.LEFT))
        row3.add(JLabel("Targets (one per line):"))
        row3.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(row3)
        self._targets_area = JTextArea(4, 60)
        self._targets_area.setLineWrap(True)
        targets_scroll = JScrollPane(self._targets_area)
        targets_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(targets_scroll)

        row4 = JPanel(FlowLayout(FlowLayout.LEFT))
        pull_targets_btn = JButton("Pull in-scope targets from Proxy history")
        pull_targets_btn.addActionListener(self._on_pull_targets)
        row4.add(pull_targets_btn)
        # Reported directly: "not all soping urls are pulling only top one
        # it adding as target" - the default (unticked) behaviour collapses
        # Proxy history down to one entry per distinct HOST (scheme+host+
        # port), which is correct for a single-host engagement (most
        # checklist items are host-level: headers/SSL/cookies/etc. don't
        # vary by path, so testing every path would just multiply scan
        # time for no extra coverage) - but if you actually have several
        # distinct in-scope hosts/paths you want tested individually,
        # ticking this pulls full URLs (path included, query stripped)
        # instead of collapsing to one row per host.
        self._pull_full_urls_checkbox = JCheckBox("Pull full URLs (paths too, not just hosts)", False)
        row4.add(self._pull_full_urls_checkbox)
        capture_session_btn = JButton("Capture session (Cookie) from Proxy history")
        capture_session_btn.addActionListener(self._on_capture_session)
        row4.add(capture_session_btn)
        row4.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(row4)

        row5 = JPanel(FlowLayout(FlowLayout.LEFT))
        row5.add(JLabel("Cookie header (captured or paste your own):"))
        self._cookie_field = JTextField("", 40)
        row5.add(self._cookie_field)
        row5.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(row5)

        row6 = JPanel(FlowLayout(FlowLayout.LEFT))
        row6.add(JLabel("Extra header (optional, e.g. Authorization: Bearer ...):"))
        self._extra_header_field = JTextField("", 40)
        row6.add(self._extra_header_field)
        row6.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(row6)
        panel.add(targets_section)

        # --- Section: run / export ---
        actions_section = self._titled_section("Run & export")
        row7 = JPanel(FlowLayout(FlowLayout.LEFT))
        self._run_all_btn = JButton("Run All Tests")
        self._run_all_btn.addActionListener(self._on_run_all)
        row7.add(self._run_all_btn)

        self._rerun_selected_btn = JButton("Re-run Selected")
        self._rerun_selected_btn.addActionListener(self._on_rerun_selected)
        row7.add(self._rerun_selected_btn)

        self._export_btn = JButton("Export -> ReportSystem JSON/CSV/XLSX")
        self._export_btn.addActionListener(self._on_export)
        row7.add(self._export_btn)

        self._pull_burp_issues_btn = JButton("Pull Burp Scanner findings for these targets")
        self._pull_burp_issues_btn.addActionListener(self._on_pull_burp_issues)
        row7.add(self._pull_burp_issues_btn)
        # Reported directly: "burp freezes" - if a scan ever hangs again
        # (SCAN_TIMEOUT_SECONDS is a 20-minute backstop, but no need to
        # wait that long), this lets the user kill it and get the UI back
        # immediately instead of restarting Burp.
        self._cancel_scan_btn = JButton("Cancel Scan")
        self._cancel_scan_btn.addActionListener(self._on_cancel_scan)
        self._cancel_scan_btn.setEnabled(False)
        row7.add(self._cancel_scan_btn)
        row7.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Same unbounded FlowLayout-row-under-BoxLayout gap bug as
        # Summary's cards_row/run_export_row/toggle_row (see those for the
        # full explanation) - fixed here too for consistency, since this
        # is the same button row duplicated onto Configuration.
        row7.setMaximumSize(Dimension(4000, 40))
        actions_section.add(row7)

        # Reported directly: "in run all test and re-run selected below
        # add progress bar while test are running and add statement once
        # completed never know if test are performed or idle" - a status
        # bar tucked away at the very bottom of the whole tab (the
        # existing self._status_label) was easy to miss; this progress
        # bar + label live right under the buttons that start a scan, so
        # it's obvious at a glance whether a scan is running, finished,
        # or never started. Kept in sync with the real self._scan_running
        # state from _start_scan()/_on_scan_complete() below - not a
        # decorative/static bar.
        row8 = JPanel(BorderLayout())
        row8.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        row8.setMaximumSize(Dimension(4000, 22))
        row8.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0))
        self._config_progress_bar = JProgressBar(0, 100)
        self._config_progress_bar.setStringPainted(True)
        self._config_progress_bar.setString("Idle")
        row8.add(self._config_progress_bar, BorderLayout.CENTER)
        actions_section.add(row8)

        self._config_status_label = JLabel("Idle - no scan has been run yet. Click 'Run All Tests' to start.")
        self._config_status_label.setFont(self._config_status_label.getFont().deriveFont(11.0))
        self._config_status_label.setForeground(Color(0x66, 0x66, 0x66))
        self._config_status_label.setBorder(BorderFactory.createEmptyBorder(4, 2, 0, 0))
        self._config_status_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        actions_section.add(self._config_status_label)

        panel.add(actions_section)

        return panel

    def _make_stat_card(self, title, accent, on_click=None):
        """One KPI 'card' (colored accent stripe + big number + small caption)
        - the pure-Swing equivalent of the card-based mockup's stat tiles.
        Plain JLabel text throughout, deliberately no HTML - the old summary
        line used an HTML JLabel and it rendered the literal '<html><b>...'
        tags on screen instead of formatting them (reported directly, with a
        screenshot circling it in red). Cause wasn't chased down since the
        fix is the same either way: don't rely on Swing's HTML label support
        for anything that has to look right.

        on_click, if given, is a zero-arg callable invoked when the card is
        clicked - the Swing equivalent of the mockup's clickable KPI cards
        that jump to Detailed Results filtered to that number. It's read
        lazily at click time (not bound at card-creation time), so a single
        card built once can still reflect whatever category scope is
        currently selected on the Categories tab."""
        card = JPanel(BorderLayout())
        card.setBackground(Color.WHITE)
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 4, 0, accent),
            BorderFactory.createEmptyBorder(8, 16, 8, 16)))
        # Reported directly: "alignment still missgin layout still not
        # looks like model" - the value/title were left-biased inside
        # each card instead of centered like a real stat tile.
        value_label = JLabel("0", JLabel.CENTER)
        value_label.setHorizontalAlignment(JLabel.CENTER)
        value_label.setFont(Font("SansSerif", Font.BOLD, 28))
        value_label.setForeground(accent)
        title_label = JLabel(title, JLabel.CENTER)
        title_label.setHorizontalAlignment(JLabel.CENTER)
        title_label.setFont(Font("SansSerif", Font.PLAIN, 10))
        title_label.setForeground(Color(0x66, 0x66, 0x66))
        card.add(value_label, BorderLayout.CENTER)
        card.add(title_label, BorderLayout.SOUTH)
        card.setPreferredSize(Dimension(170, 62))
        if on_click is not None:
            card.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
            listener = _CallbackMouseListener(on_click)
            card.addMouseListener(listener)
            value_label.addMouseListener(listener)
            title_label.addMouseListener(listener)
        return {"panel": card, "value_label": value_label}

    def _build_summary_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Reported directly: "Run & export moved to top kepp below KPIs so
        # an every page it will be consistent, KPIs on top, next Run &
        # Export then Categories" - KPI cards come first now (see below),
        # then Run & export, then Coverage.
        cards_row = JPanel(FlowLayout(FlowLayout.LEFT, 12, 6))
        self._card_total = self._make_stat_card("TOTAL CHECKS RUN", Color(0x2C, 0x3E, 0x50),
                                                  lambda: self._apply_filter(None, None, None))
        self._card_pass = self._make_stat_card("PASS", Color(0x1E, 0x7E, 0x34),
                                                 lambda: self._apply_filter(None, "PASS", None))
        self._card_fail = self._make_stat_card("FAIL (VULNERABLE)", Color(0xA4, 0x26, 0x2C),
                                                 lambda: self._apply_filter(None, "FAIL", None))
        self._card_manual = self._make_stat_card("MANUAL / INFO / ERROR", Color(0x8A, 0x6D, 0x00),
                                                   lambda: self._apply_filter(None, "OTHER", None))
        self._card_categories = self._make_stat_card("CATEGORIES COVERED", Color(0x1F, 0x4E, 0x78))
        for card in (self._card_total, self._card_pass, self._card_fail, self._card_manual, self._card_categories):
            cards_row.add(card["panel"])
        cards_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Reported directly: "auto fit as ther is log of gaps" - a
        # FlowLayout row has an unbounded default max height (FlowLayout
        # doesn't override maximumLayoutSize()), so under a BoxLayout.Y_AXIS
        # parent it's treated as "infinitely stretchable" and soaks up all
        # of the tab's surplus vertical space, showing up as a big empty
        # gap below it. Same fix as the progress-bar rows below
        # (bar_row/row8): pin a bounded max height so this row only ever
        # takes the space its content actually needs.
        cards_row.setMaximumSize(Dimension(4000, 80))
        panel.add(cards_row)

        hint = JLabel("Click a number above (Total / Pass / Fail / Manual) to jump to Detailed Results filtered to it.")
        hint.setFont(hint.getFont().deriveFont(11.0))
        hint.setForeground(Color(0x66, 0x66, 0x66))
        hint.setBorder(BorderFactory.createEmptyBorder(4, 4, 2, 4))
        hint.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(hint)

        # Reported directly (this build's freeze/getColumnClass bug is now
        # fixed, so this is safe to bring back): "can we bring run & export
        # to Summary page?" - a second set of buttons, wired to the exact
        # same handlers as the Configuration tab's (_on_run_all/
        # _on_rerun_selected/_on_export/_on_pull_burp_issues/
        # _on_cancel_scan), so clicking either copy does the identical
        # thing and both copies are kept enabled/disabled in lockstep by
        # _start_scan()/_on_scan_complete() below - no separate state to
        # drift out of sync. Targets/cookie/etc. still only live on
        # Configuration (this is just a shortcut to start/export a scan
        # without switching tabs, not a second config surface).
        run_export_section = self._titled_section("Run & export")
        run_export_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self._summary_run_all_btn = JButton("Run All Tests")
        self._summary_run_all_btn.addActionListener(self._on_run_all)
        run_export_row.add(self._summary_run_all_btn)

        self._summary_rerun_selected_btn = JButton("Re-run Selected")
        self._summary_rerun_selected_btn.addActionListener(self._on_rerun_selected)
        run_export_row.add(self._summary_rerun_selected_btn)

        self._summary_export_btn = JButton("Export -> ReportSystem JSON/CSV/XLSX")
        self._summary_export_btn.addActionListener(self._on_export)
        run_export_row.add(self._summary_export_btn)

        self._summary_pull_burp_issues_btn = JButton("Pull Burp Scanner findings for these targets")
        self._summary_pull_burp_issues_btn.addActionListener(self._on_pull_burp_issues)
        run_export_row.add(self._summary_pull_burp_issues_btn)

        self._summary_cancel_scan_btn = JButton("Cancel Scan")
        self._summary_cancel_scan_btn.addActionListener(self._on_cancel_scan)
        self._summary_cancel_scan_btn.setEnabled(False)
        run_export_row.add(self._summary_cancel_scan_btn)
        run_export_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # See cards_row.setMaximumSize() note above - same unbounded
        # FlowLayout-row-under-BoxLayout gap bug, this time on the
        # Run & export button row.
        run_export_row.setMaximumSize(Dimension(4000, 40))
        run_export_section.add(run_export_row)
        run_export_section.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(run_export_section)

        self._progress_label = JLabel("No scan run yet - open the Configuration tab, set your targets, and "
                                       "click Run All Tests.")
        self._progress_label.setBorder(BorderFactory.createEmptyBorder(8, 4, 2, 4))
        self._progress_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(self._progress_label)

        # Reported directly: "alignment still missgin" - the progress bar
        # previously carried its OWN long descriptive sentence as the bar's
        # setString() text, which visually overlapped/garbled against the
        # "NN%" Aqua/macOS auto-draws on top of a JProgressBar's fill -
        # the bar itself now shows only a short "NN%", and the descriptive
        # sentence moved to its own label underneath where it can't clash.
        bar_row = JPanel(BorderLayout())
        bar_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        bar_row.setMaximumSize(Dimension(4000, 22))
        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setStringPainted(True)
        self._progress_bar.setString("0%")
        bar_row.add(self._progress_bar, BorderLayout.CENTER)
        panel.add(bar_row)

        self._progress_detail_label = JLabel(" ")
        self._progress_detail_label.setFont(self._progress_detail_label.getFont().deriveFont(11.0))
        self._progress_detail_label.setForeground(Color(0x66, 0x66, 0x66))
        self._progress_detail_label.setBorder(BorderFactory.createEmptyBorder(3, 4, 10, 4))
        self._progress_detail_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(self._progress_detail_label)

        # Reported directly: "bring run & export to Summary page? and
        # worst findings no need can be removed as it is not use for me"
        # - Run & export now lives both here and on Configuration (kept in
        # lockstep, see the button block above). Worst Findings was
        # removed at that point, then reported directly again later: "add
        # bototm fauled vulnerabiitys below the gatagory" - it's back
        # below, now named "Failed vulnerabilities" and placed below the
        # Coverage table specifically (see panel.add(coverage_box) then
        # panel.add(worst_box) below), and reflects the unified
        # automated + manually-logged row set via _refresh_worst_findings().
        #
        # Reported directly (earlier): "when no need to show two different
        # tables you can add the tab above" - one table, a small toggle
        # above it switches between category rows and OWASP Top 10 rows
        # instead of stacking two tables permanently. Same idea as the
        # Categories tab's mode toggle.
        coverage_box = self._titled_section("Coverage")
        coverage_box.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        toggle_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        toggle_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        self._summary_cat_toggle = JToggleButton("Coverage by category", True)
        self._summary_owasp_toggle = JToggleButton("OWASP Top 10 coverage", False)
        summary_mode_group = ButtonGroup()
        summary_mode_group.add(self._summary_cat_toggle)
        summary_mode_group.add(self._summary_owasp_toggle)
        self._summary_cat_toggle.addActionListener(lambda e: self._on_summary_coverage_mode_changed("cat"))
        self._summary_owasp_toggle.addActionListener(lambda e: self._on_summary_coverage_mode_changed("owasp"))
        toggle_row.add(self._summary_cat_toggle)
        toggle_row.add(self._summary_owasp_toggle)
        # See cards_row.setMaximumSize() note above - same fix, this time
        # on the Coverage mode-toggle row.
        toggle_row.setMaximumSize(Dimension(4000, 36))
        coverage_box.add(toggle_row)

        self._summary_coverage_table_model = ColoredTableModel(
            ["Category", "Total", "Pass", "Fail", "Manual/Other"], 0)
        self._summary_coverage_table = JTable(self._summary_coverage_table_model)
        self._summary_coverage_table.setAutoCreateRowSorter(True)
        summary_coverage_renderer = CategoryFailRenderer(self, None, None)
        self._summary_coverage_table.setDefaultRenderer(JObject, summary_coverage_renderer)
        self._summary_coverage_table.setDefaultRenderer(JInteger, summary_coverage_renderer)
        self._summary_coverage_table.setRowHeight(22)
        self._apply_coverage_table_widths(self._summary_coverage_table)
        self._summary_coverage_table.addMouseListener(_SummaryCoverageDoubleClickListener(self))
        coverage_scroll = JScrollPane(self._summary_coverage_table)
        coverage_scroll.setPreferredSize(Dimension(680, 220))
        coverage_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        coverage_box.add(coverage_scroll)

        self._summary_coverage_hint = JLabel(
            "Double-click a row to jump to Detailed Results for that category, or use the Categories "
            "tab to browse interactively.")
        self._summary_coverage_hint.setFont(self._summary_coverage_hint.getFont().deriveFont(11.0))
        self._summary_coverage_hint.setForeground(Color(0x66, 0x66, 0x66))
        self._summary_coverage_hint.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        coverage_box.add(self._summary_coverage_hint)
        panel.add(coverage_box)

        # Reported directly: "add bototm fauled vulnerabiitys below the
        # gatagory" - a small ranked list of the current worst (highest
        # severity first) FAIL results, placed below the Coverage table.
        # Populated/refreshed by _refresh_worst_findings(), called from
        # _populate_summary() alongside everything else on this tab.
        # Reported directly again later: "add color codeing for severaity
        # add table form" - rebuilt as a real sortable JTable (was a
        # stack of plain JLabel rows) with its own color-coded Severity
        # column (see _SeverityTextRenderer), same as Detailed Results
        # and Checklist Reference now both have.
        worst_box = self._titled_section("Failed vulnerabilities")
        worst_box.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        self._worst_findings_table_model = ColoredTableModel(["ID", "Category", "Test", "Severity", "Source"], 0)
        self._worst_findings_table = JTable(self._worst_findings_table_model)
        self._worst_findings_table.setAutoCreateRowSorter(True)
        self._worst_findings_table.setRowHeight(22)
        worst_col_model = self._worst_findings_table.getColumnModel()
        for idx, width in ((0, 90), (1, 150), (3, 90), (4, 130)):
            worst_col_model.getColumn(idx).setPreferredWidth(width)
        worst_col_model.getColumn(3).setCellRenderer(_SeverityTextRenderer())
        # Double-click a row for the same full-evidence popup Detailed
        # Results uses (_show_row_detail) - these are real rows out of
        # self._rows, just a filtered/ranked subset (see
        # _worst_findings_rows in _refresh_worst_findings).
        self._worst_findings_table.addMouseListener(_WorstFindingsDoubleClickListener(self))
        # Reported directly: "add slider so i can navigae down" - its own
        # scrollbar (same pattern as coverage_scroll just above), instead
        # of every FAIL row just stretching the whole Summary tab taller
        # and taller.
        worst_scroll = JScrollPane(self._worst_findings_table)
        worst_scroll.setPreferredSize(Dimension(680, 260))
        worst_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        worst_scroll.getVerticalScrollBar().setUnitIncrement(16)
        worst_box.add(worst_scroll)
        panel.add(worst_box)

        self._summary_coverage_mode = "cat"

        scroll = JScrollPane(panel)
        scroll.setBorder(BorderFactory.createEmptyBorder())
        scroll.getVerticalScrollBar().setUnitIncrement(16)
        return scroll

    def _build_categories_panel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0))

        # Reported directly: "show the main KPIs in top always like
        # summary static ... when select the specific category change
        # the count in KPI accordingly" - these cards rescope to
        # whichever category/OWASP bucket is selected on the left
        # (All Categories by default = the same global totals Summary
        # shows), instead of staying fixed or duplicating small counts
        # elsewhere ("no need to keep count again in small icons").
        self._cat_scope_label = JLabel("Showing: All Categories")
        self._cat_scope_label.setFont(self._cat_scope_label.getFont().deriveFont(Font.BOLD, 11.5))
        self._cat_scope_label.setForeground(Color(0xB8, 0x56, 0x0F))
        self._cat_scope_label.setBorder(BorderFactory.createEmptyBorder(2, 2, 6, 2))
        self._cat_scope_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(self._cat_scope_label)

        cards_row = JPanel(FlowLayout(FlowLayout.LEFT, 12, 6))
        self._cat_card_total = self._make_stat_card(
            "TOTAL CHECKS RUN", Color(0x2C, 0x3E, 0x50),
            lambda: self._apply_filter(self._cat_selected_categories, None, self._cat_selected_label))
        self._cat_card_pass = self._make_stat_card(
            "PASS", Color(0x1E, 0x7E, 0x34),
            lambda: self._apply_filter(self._cat_selected_categories, "PASS", self._cat_selected_label))
        self._cat_card_fail = self._make_stat_card(
            "FAIL (VULNERABLE)", Color(0xA4, 0x26, 0x2C),
            lambda: self._apply_filter(self._cat_selected_categories, "FAIL", self._cat_selected_label))
        self._cat_card_manual = self._make_stat_card(
            "MANUAL / INFO / ERROR", Color(0x8A, 0x6D, 0x00),
            lambda: self._apply_filter(self._cat_selected_categories, "OTHER", self._cat_selected_label))
        self._cat_card_categories = self._make_stat_card("CATEGORIES COVERED", Color(0x1F, 0x4E, 0x78))
        for card in (self._cat_card_total, self._cat_card_pass, self._cat_card_fail,
                     self._cat_card_manual, self._cat_card_categories):
            cards_row.add(card["panel"])
        cards_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Same unbounded FlowLayout-row-under-BoxLayout gap bug as
        # Summary's cards_row - fixed here too for consistency.
        cards_row.setMaximumSize(Dimension(4000, 80))
        top.add(cards_row)

        hint = JLabel("Click a category on the left to change these numbers to just that category. Click a "
                       "number above (Total / Pass / Fail / Manual) to jump to Detailed Results filtered to it.")
        hint.setFont(hint.getFont().deriveFont(11.0))
        hint.setForeground(Color(0x66, 0x66, 0x66))
        hint.setBorder(BorderFactory.createEmptyBorder(2, 4, 6, 4))
        hint.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(hint)

        bar_row = JPanel(BorderLayout())
        bar_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        bar_row.setMaximumSize(Dimension(4000, 22))
        self._cat_progress_bar = JProgressBar(0, 100)
        self._cat_progress_bar.setStringPainted(True)
        self._cat_progress_bar.setString("0%")
        bar_row.add(self._cat_progress_bar, BorderLayout.CENTER)
        top.add(bar_row)

        self._cat_progress_detail_label = JLabel(" ")
        self._cat_progress_detail_label.setFont(self._cat_progress_detail_label.getFont().deriveFont(11.0))
        self._cat_progress_detail_label.setForeground(Color(0x66, 0x66, 0x66))
        self._cat_progress_detail_label.setBorder(BorderFactory.createEmptyBorder(3, 4, 0, 4))
        self._cat_progress_detail_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(self._cat_progress_detail_label)

        panel.add(top, BorderLayout.NORTH)

        body = JPanel(BorderLayout())

        # --- Left column: All Categories / OWASP Top 10 mode toggle + list ---
        left = JPanel(BorderLayout())
        left.setPreferredSize(Dimension(270, 100))

        mode_row = JPanel(GridLayout(1, 2))
        # Reported directly: "change name from all categories to
        # vulnerability by categories" - this toggle's "flat list" mode
        # label (left column, top of Categories tab).
        self._cat_all_toggle = JToggleButton("Vulnerability by Categories", True)
        self._cat_owasp_toggle = JToggleButton("OWASP Top 10", False)
        cat_mode_group = ButtonGroup()
        cat_mode_group.add(self._cat_all_toggle)
        cat_mode_group.add(self._cat_owasp_toggle)
        self._cat_all_toggle.addActionListener(lambda e: self._on_cat_mode_changed("all"))
        self._cat_owasp_toggle.addActionListener(lambda e: self._on_cat_mode_changed("owasp"))
        mode_row.add(self._cat_all_toggle)
        mode_row.add(self._cat_owasp_toggle)
        left.add(mode_row, BorderLayout.NORTH)

        # Reported directly: "by default all test should pear if any
        # catarogy select then only those test case shuld be apear".
        # Index 0 is always "All Categories" / clears the scope back to
        # global; self._cat_list_keys/_cats/_labels are parallel arrays
        # (rebuilt by _refresh_categories_tab) so a list row can carry a
        # raw category name (All-Categories mode) or an OWASP bucket key
        # like "A03" (OWASP mode) without parsing it back out of the
        # display text (which also carries a pass/total count).
        self._populating_cat_list = True
        self._cat_list_keys = []
        self._cat_list_cats = []
        self._cat_list_labels = []
        self._cat_list_model = DefaultListModel()
        self._cat_list_model.addElement("All Categories")
        self._cat_list = JList(self._cat_list_model)
        self._cat_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._cat_list.setSelectedIndex(0)
        self._cat_list.addListSelectionListener(_CategoryListSelectionListener(self))
        self._populating_cat_list = False
        left.add(JScrollPane(self._cat_list), BorderLayout.CENTER)
        body.add(left, BorderLayout.WEST)

        # --- Right column: breakdown table, switches content with the mode ---
        right = JPanel(BorderLayout())
        right.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0))
        self._cat_note_label = JLabel("Coverage by category (this scan's targets/session only, not the full "
                                       "ReportSystem master checklist). The selected category is highlighted "
                                       "below - double-click any row to jump straight to Detailed Results for it.")
        self._cat_note_label.setBorder(BorderFactory.createEmptyBorder(4, 4, 8, 4))
        right.add(self._cat_note_label, BorderLayout.NORTH)

        # ColoredTableModel (not a plain DefaultTableModel) specifically so
        # isCellEditable() is False - reported directly: "wehn I click it
        # is renaming it" - a plain DefaultTableModel's cells are editable
        # by default, so clicking a cell opened an in-place text edit box
        # instead of doing anything useful with the click.
        self._cat_table_model = ColoredTableModel(["Category", "Total", "Pass", "Fail", "Manual/Other"], 0)
        self._cat_table = JTable(self._cat_table_model)
        self._cat_table.setAutoCreateRowSorter(True)  # click any column header to sort
        cat_table_renderer = CategoryFailRenderer(self, "_cat_table_keys", "_cat_selected_key")
        self._cat_table.setDefaultRenderer(JObject, cat_table_renderer)
        self._cat_table.setDefaultRenderer(JInteger, cat_table_renderer)
        self._cat_table.setRowHeight(22)
        self._apply_coverage_table_widths(self._cat_table)
        # Reported directly: "it is not taking into the selected catagory
        # findings... not allowing to land the fineld items" - double-
        # click a row (category row, or OWASP bucket row) to jump to
        # Detailed Results filtered down to it.
        self._cat_table.addMouseListener(_CategoryTableDoubleClickListener(self))
        right.add(JScrollPane(self._cat_table), BorderLayout.CENTER)
        body.add(right, BorderLayout.CENTER)

        panel.add(body, BorderLayout.CENTER)

        self._cat_table_keys = []
        self._cat_table_cats = []
        self._cat_table_labels = []
        self._cat_mode = "all"
        self._cat_selected_key = "ALL"
        self._cat_selected_categories = None
        self._cat_selected_label = "All Categories"
        return panel

    def _apply_coverage_table_widths(self, table):
        # Explicit widths so numeric columns stay compact instead of
        # stretching to evenly fill the tab (reported: "alignment still
        # missgin") - Category/OWASP Category gets the room, the four
        # count columns don't need it. Re-applied any time a table's
        # column identifiers are rebuilt (setColumnIdentifiers() resets
        # column objects, which resets their preferred widths too).
        col_widths = {0: 300, 1: 70, 2: 70, 3: 70, 4: 110}
        for idx, width in col_widths.items():
            try:
                table.getColumnModel().getColumn(idx).setPreferredWidth(width)
            except Exception:
                pass

    def _build_results_panel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))
        self._results_table_model = ColoredTableModel(RESULT_COLUMNS, 0)
        self._results_table = JTable(self._results_table_model)
        self._results_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        # Reported directly: "apply sort so i can sor by falied or seqency
        # of id bases" - this turns on Swing's built-in click-a-column-
        # header-to-sort behaviour (toggles ascending/descending, click a
        # second column while holding Shift to sort by that as a tiebreak).
        # Click "Result" to group all FAILs together, or "ID" for checklist
        # sequence order.
        self._results_table.setAutoCreateRowSorter(True)
        # JObject (java.lang.Object, not Python's builtin object) is required
        # here - setDefaultRenderer keys off the column's Java Class, and a
        # plain DefaultTableModel reports every column's class as
        # Object.class, so this one registration colors every column.
        self._results_table.setDefaultRenderer(JObject, ResultRowRenderer())
        self._results_table.setRowHeight(22)
        # Explicit widths so ID/Severity/Priority/Result stay compact and
        # Test/Evidence/URL get the room they actually need, instead of
        # all 9 columns splitting the tab width evenly (reported:
        # "alignment still missgin"). RESULT_COLUMNS order:
        # ID, Category, Test, Severity, Priority, Result, Evidence, URL, Source.
        for idx, width in {0: 90, 1: 140, 2: 230, 3: 80, 4: 60, 5: 70, 6: 320, 7: 220, 8: 140}.items():
            self._results_table.getColumnModel().getColumn(idx).setPreferredWidth(width)
        # Reported directly: "not looks like the output you showed... i am
        # unable to check the request and response, and found what is the
        # messing" - the Evidence column is truncated to 300 chars for the
        # grid, so the real curl/nmap command + full response was never
        # visible in-app. Double-click a row to see it in full.
        self._results_table.addMouseListener(_ResultsTableDoubleClickListener(self))

        # Reported directly: "allow user to add manual search Input box"
        # - matches on ID / Category / Test / Evidence / URL, combines
        # with whatever category/result filter is active (see
        # _apply_row_filter()), and updates live as you type via
        # _SearchDocumentListener below.
        search_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        search_row.add(JLabel("Search:"))
        self._results_search_field = JTextField(24)
        self._results_search_field.getDocument().addDocumentListener(_SearchDocumentListener(self))
        search_row.add(self._results_search_field)
        search_hint = JLabel("matches ID / Category / Test / Evidence / URL - or type result=FAIL, "
                              "severity=High, category=..., etc. for an exact field match")
        search_hint.setFont(search_hint.getFont().deriveFont(11.0))
        search_hint.setForeground(Color(0x99, 0x99, 0x99))
        search_row.add(search_hint)

        # Shown/hidden by _apply_filter()/_clear_filter() - double-
        # clicking a category/OWASP row (or clicking a KPI card) on the
        # Summary/Categories tabs lands here with the table filtered;
        # click this banner to go back to showing everything.
        self._filter_label = JLabel(" ")
        self._filter_label.setOpaque(True)
        self._filter_label.setBackground(Color(0xFF, 0xF3, 0xCD))
        self._filter_label.setBorder(BorderFactory.createEmptyBorder(5, 8, 5, 8))
        self._filter_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        self._filter_label.setVisible(False)
        self._filter_label.addMouseListener(_ClearFilterMouseListener(self))

        # BorderLayout (NORTH/SOUTH), not BoxLayout - a plain BorderLayout
        # slot always fills the full available width regardless of each
        # child's own alignmentX/maximumSize, sidestepping the BoxLayout
        # cross-axis alignment bug documented at length in
        # _build_config_panel above.
        north_wrap = JPanel(BorderLayout())
        north_wrap.add(search_row, BorderLayout.NORTH)
        north_wrap.add(self._filter_label, BorderLayout.SOUTH)
        panel.add(north_wrap, BorderLayout.NORTH)

        results_scroll = JScrollPane(self._results_table)
        results_scroll.setBorder(BorderFactory.createTitledBorder("Detailed Results (click a column header to "
                                                                    "sort, double-click a row for full evidence)"))
        panel.add(results_scroll, BorderLayout.CENTER)
        hint = JLabel("  Select one or more rows, then click 'Re-run Selected' above to re-test just those "
                       "Checklist IDs (against the same targets/session).")
        hint.setFont(hint.getFont().deriveFont(11.0))
        panel.add(hint, BorderLayout.SOUTH)
        return panel

    def _show_row_detail_from_event(self, event):
        view_row = self._results_table.rowAtPoint(event.getPoint())
        if view_row < 0:
            return
        model_row = self._results_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._rows):
            return
        self._show_row_detail(self._rows[model_row])

    # ------------------------------------------------------------------
    # Categories tab: mode toggle, list selection, table double-click
    # ------------------------------------------------------------------
    def _on_cat_mode_changed(self, mode):
        self._cat_mode = mode
        self._refresh_categories_tab()

    def _on_category_list_selection(self):
        if getattr(self, "_populating_cat_list", False):
            return
        index = self._cat_list.getSelectedIndex()
        if index < 0 or index >= len(self._cat_list_keys):
            return
        key = self._cat_list_keys[index]
        cats = self._cat_list_cats[index]
        label = self._cat_list_labels[index]
        self._set_category_scope(cats, label, key)

    def _on_category_table_double_click(self, event):
        view_row = self._cat_table.rowAtPoint(event.getPoint())
        if view_row < 0:
            return
        model_row = self._cat_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._cat_table_keys):
            return
        key = self._cat_table_keys[model_row]
        cats = self._cat_table_cats[model_row]
        label = self._cat_table_labels[model_row]
        self._set_category_scope(cats, label, key)
        self._apply_filter(cats, None, label)

    def _on_summary_coverage_table_double_click(self, event):
        view_row = self._summary_coverage_table.rowAtPoint(event.getPoint())
        if view_row < 0:
            return
        model_row = self._summary_coverage_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._summary_coverage_table_cats):
            return
        cats = self._summary_coverage_table_cats[model_row]
        label = self._summary_coverage_table_labels[model_row]
        self._apply_filter(cats, None, label)

    def _on_summary_coverage_mode_changed(self, mode):
        self._summary_coverage_mode = mode
        self._refresh_summary_coverage_table()
        # Reported directly: "summary tab not dynamically updating" -
        # the top KPI cards (specifically "Categories Covered") need to
        # re-render scoped to whichever mode is now active too, same as
        # the Categories tab already does for its own toggle.
        self._update_summary_top_cards()

    def _set_category_scope(self, categories, label, key):
        # Reported directly: "by default select All categories" - cats
        # is None for the "All Categories"/"ALL" scope (no restriction);
        # otherwise a list of one or more real category names. Rescopes
        # the top KPI cards in place - does NOT navigate anywhere; that's
        # what clicking one of the KPI numbers or double-clicking a table
        # row is for.
        self._cat_selected_categories = categories
        self._cat_selected_label = label
        self._cat_selected_key = key
        if hasattr(self, "_cat_scope_label"):
            self._cat_scope_label.setText("Showing: %s" % label)
        self._update_categories_top_cards()
        if hasattr(self, "_cat_table"):
            self._cat_table.repaint()
        self._sync_cat_list_selection(key)

    def _sync_cat_list_selection(self, key):
        if not hasattr(self, "_cat_list_keys") or not hasattr(self, "_cat_list"):
            return
        target_index = 0
        for i, k in enumerate(self._cat_list_keys):
            if k == key:
                target_index = i
                break
        if self._cat_list.getSelectedIndex() == target_index:
            return
        self._populating_cat_list = True
        self._cat_list.setSelectedIndex(target_index)
        self._populating_cat_list = False

    # ------------------------------------------------------------------
    # Detailed Results filtering (category/group + result-type, combinable)
    # ------------------------------------------------------------------
    def _apply_filter(self, categories, result, label):
        self._filter_categories = categories
        self._filter_result = result
        self._apply_row_filter()
        self._update_filter_banner(label)
        self._tabs.setSelectedIndex(3)  # Detailed Results (Summary=0, Configuration=1, Categories=2)

    def _apply_row_filter(self):
        # Reported directly: "allow user to add manual search Input
        # box" - the search box is independent of (but combinable with)
        # the category/result quick-filter, so both _apply_filter() and
        # _on_search_text_changed() funnel through this one place to
        # rebuild the actual RowFilter from whatever's currently active.
        sorter = self._results_table.getRowSorter()
        if sorter is None:
            return
        if self._filter_categories or self._filter_result or self._filter_search_text:
            sorter.setRowFilter(_ResultCategoryRowFilter(
                self._filter_categories, self._filter_result, self._filter_search_text))
        else:
            sorter.setRowFilter(None)

    def _on_search_text_changed(self):
        text = self._results_search_field.getText() or ""
        self._filter_search_text = text.strip().lower()
        self._apply_row_filter()

    def _update_filter_banner(self, label):
        if not self._filter_categories and not self._filter_result:
            self._filter_label.setVisible(False)
            return
        parts = []
        if self._filter_categories:
            cat_label = label or ", ".join(self._filter_categories)
            is_group = len(self._filter_categories) > 1
            parts.append(("Category group = %s" if is_group else "Category = %s") % cat_label)
        if self._filter_result:
            result_text = "MANUAL/INFO/ERROR" if self._filter_result == "OTHER" else self._filter_result
            parts.append("Result = %s" % result_text)
        self._filter_label.setText("  Showing: %s  -  click here to clear this filter and see all rows again"
                                    % ", ".join(parts))
        self._filter_label.setVisible(True)

    def _clear_filter(self):
        self._filter_categories = None
        self._filter_result = None
        self._filter_search_text = ""
        if hasattr(self, "_results_search_field") and self._results_search_field.getText():
            self._results_search_field.setText("")  # triggers _on_search_text_changed, harmless/idempotent
        sorter = self._results_table.getRowSorter()
        if sorter is not None:
            sorter.setRowFilter(None)
        self._filter_label.setVisible(False)
        self._set_category_scope(None, "All Categories", "ALL")

    def _show_row_detail(self, row):
        result = row.get("result", "")
        accent = RESULT_ACCENT_COLORS.get(result, Color(0x33, 0x33, 0x33))

        header = JPanel(BorderLayout())
        header.setBackground(accent)
        header_label = JLabel("  %s  -  %s  -  %s" % (result or "?", row.get("id", ""), row.get("test", "")))
        header_label.setForeground(Color.WHITE)
        header_label.setFont(Font("Monospaced", Font.BOLD, 14))
        header_label.setBorder(BorderFactory.createEmptyBorder(8, 4, 8, 4))
        header.add(header_label, BorderLayout.WEST)

        pane = JTextPane()
        pane.setEditable(False)
        pane.setBackground(Color(0x0C, 0x0C, 0x0C))
        pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        doc = pane.getStyledDocument()

        def make_style(color, bold=False):
            attrs = SimpleAttributeSet()
            StyleConstants.setForeground(attrs, color)
            StyleConstants.setBold(attrs, bold)
            return attrs

        label_style = make_style(Color(0x57, 0xE3, 0x89), True)   # field labels + section headers - green, bold
        field_style = make_style(Color(0x9A, 0xA5, 0xB1))         # field values - muted gray-blue
        body_style = make_style(Color(0xE0, 0xE0, 0xE0))          # evidence body text - light gray
        prompt_style = make_style(Color(0x57, 0xE3, 0x89), True)  # "$ curl ..." command lines - green, bold

        def append(text, style):
            try:
                doc.insertString(doc.getLength(), text, style)
            except Exception:
                pass

        for label, value in (
            ("ID", row.get("id", "")), ("Test", row.get("test", "")),
            ("Category", row.get("category", "")),
            ("Severity", "%s (%s)" % (row.get("severity", ""), row.get("priority", ""))),
            ("Result", result), ("URL", row.get("url", "")),
            ("URL Role", row.get("url_role", "")), ("Checked At", row.get("checked_at", "")),
        ):
            append("%-12s" % (label + ":"), label_style)
            append("%s\n" % value, field_style)

        append("\nEvidence (full, untruncated):\n", label_style)
        evidence = row.get("evidence", "") or "(no evidence text)"
        for line in evidence.splitlines() or [""]:
            append(line + "\n", prompt_style if line.startswith("$ ") else body_style)

        pane.setCaretPosition(0)
        scroll = JScrollPane(pane)
        scroll.setPreferredSize(Dimension(900, 560))

        container = JPanel(BorderLayout())
        container.add(header, BorderLayout.NORTH)
        container.add(scroll, BorderLayout.CENTER)

        JOptionPane.showMessageDialog(self._main_panel, container,
                                       "%s - %s" % (row.get("id", ""), row.get("test", "")),
                                       JOptionPane.PLAIN_MESSAGE)

    def _build_burp_findings_panel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))
        # Plain text, deliberately no <html> markup - see the note on
        # _make_stat_card() above for why (the old Summary tab's HTML
        # label rendered its raw "<html><b>...</b>" tags on screen
        # instead of formatting them). Reported directly (again, on THIS
        # exact label): "htmls code is not renderd properly" - two plain
        # JLabels instead of one <html>...<br>...</html> label fixes it
        # the same way the rest of the file already does it.
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        note1 = JLabel("Burp Scanner's own findings for these targets (requires Burp Pro's Scanner to have "
                        "already run). Shown for cross-reference only - Burp's issue names don't carry a real "
                        "WPT checklist ID, so they aren't auto-counted in the Summary KPIs or ReportSystem export.")
        note1.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4))
        note1.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(note1)
        note2 = JLabel("Double-click a row for the full detail. Select a row and click 'Add selected to "
                        "QuickChop tracked list...' to confirm which checklist ID it maps to - that's what makes "
                        "it count.")
        note2.setBorder(BorderFactory.createEmptyBorder(0, 4, 8, 4))
        note2.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(note2)
        burp_btn_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self._burp_add_to_tracked_btn = JButton("Add selected to QuickChop tracked list...")
        self._burp_add_to_tracked_btn.addActionListener(self._on_add_burp_finding_to_tracked)
        burp_btn_row.add(self._burp_add_to_tracked_btn)
        burp_btn_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Same unbounded-FlowLayout-row-under-BoxLayout gap bug as
        # Summary's rows (see _build_summary_panel) - bounded here too.
        burp_btn_row.setMaximumSize(Dimension(4000, 40))
        top.add(burp_btn_row)
        panel.add(top, BorderLayout.NORTH)
        self._burp_issues_model = ColoredTableModel(["Severity", "Confidence", "Issue", "URL", "Detail"], 0)
        self._burp_table = JTable(self._burp_issues_model)
        self._burp_table.setAutoCreateRowSorter(True)
        self._burp_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        # Reported directly: "when I double click it is not openign
        # related record like scanner page does" - same double-click ->
        # full-detail-popup pattern as Detailed Results (_show_row_detail)
        # and the Summary/Categories coverage tables, now here too.
        self._burp_table.addMouseListener(_BurpFindingsDoubleClickListener(self))
        burp_scroll = JScrollPane(self._burp_table)
        burp_scroll.setBorder(BorderFactory.createTitledBorder("Burp Scanner Findings (context only)"))
        panel.add(burp_scroll, BorderLayout.CENTER)
        return panel

    def _burp_issue_for_view_row(self, view_row):
        if view_row < 0:
            return None
        model_row = self._burp_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._burp_issues_raw):
            return None
        return self._burp_issues_raw[model_row]

    def _show_burp_issue_detail(self, issue):
        # Same visual language as _show_row_detail (colored banner +
        # monospace body) so this reads as the same kind of popup, just
        # for a Burp Scanner issue instead of a QuickChop checklist row.
        severity = issue.get("severity", "")
        accent = SEVERITY_ACCENT_COLORS.get(severity, RESULT_ACCENT_COLORS.get("FAIL"))

        header = JPanel(BorderLayout())
        header.setBackground(accent)
        header_label = JLabel("  %s  -  %s" % (severity or "?", issue.get("issue", "")))
        header_label.setForeground(Color.WHITE)
        header_label.setFont(Font("Monospaced", Font.BOLD, 14))
        header_label.setBorder(BorderFactory.createEmptyBorder(8, 4, 8, 4))
        header.add(header_label, BorderLayout.WEST)

        pane = JTextPane()
        pane.setEditable(False)
        pane.setBackground(Color(0x0C, 0x0C, 0x0C))
        pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        doc = pane.getStyledDocument()

        def make_style(color, bold=False):
            attrs = SimpleAttributeSet()
            StyleConstants.setForeground(attrs, color)
            StyleConstants.setBold(attrs, bold)
            return attrs

        label_style = make_style(Color(0x57, 0xE3, 0x89), True)
        field_style = make_style(Color(0x9A, 0xA5, 0xB1))
        body_style = make_style(Color(0xE0, 0xE0, 0xE0))

        def append(text, style):
            try:
                doc.insertString(doc.getLength(), text, style)
            except Exception:
                pass

        for label, value in (
            ("Issue", issue.get("issue", "")), ("Severity", severity),
            ("Confidence", issue.get("confidence", "")), ("URL", issue.get("url", "")),
        ):
            append("%-12s" % (label + ":"), label_style)
            append("%s\n" % value, field_style)

        append("\nDetail (full, untruncated):\n", label_style)
        detail = issue.get("detail_full", "") or "(no detail text)"
        for line in detail.splitlines() or [""]:
            append(line + "\n", body_style)

        # Reported directly: "request and response detals cptured here
        # for burp scaner resutls" - Burp's own IScanIssue carries the
        # real request/response it based the finding on
        # (getHttpMessages(), captured in _on_pull_burp_issues) - shown
        # here the same way Detailed Results shows real curl/captured
        # evidence, instead of just the prose Detail text above.
        req_full = issue.get("req_full", "")
        resp_full = issue.get("resp_full", "")
        if req_full or resp_full:
            if req_full:
                append("\nRequest captured (full, untruncated):\n", label_style)
                for line in req_full.splitlines() or [""]:
                    append(line + "\n", body_style)
            if resp_full:
                append("\nResponse captured (full, untruncated):\n", label_style)
                for line in resp_full.splitlines() or [""]:
                    append(line + "\n", body_style)
        else:
            append("\n(No request/response captured for this issue by Burp Scanner.)\n", field_style)

        pane.setCaretPosition(0)
        scroll = JScrollPane(pane)
        scroll.setPreferredSize(Dimension(900, 560))

        container = JPanel(BorderLayout())
        container.add(header, BorderLayout.NORTH)
        container.add(scroll, BorderLayout.CENTER)

        JOptionPane.showMessageDialog(self._main_panel, container,
                                       "Burp Scanner - %s" % issue.get("issue", ""),
                                       JOptionPane.PLAIN_MESSAGE)

    def _show_burp_issue_detail_from_event(self, event):
        view_row = self._burp_table.rowAtPoint(event.getPoint())
        issue = self._burp_issue_for_view_row(view_row)
        if issue is not None:
            self._show_burp_issue_detail(issue)

    def _on_add_burp_finding_to_tracked(self, event):
        view_row = self._burp_table.getSelectedRow()
        if view_row < 0:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Select a row in 'Burp Scanner Findings' first.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        issue = self._burp_issue_for_view_row(view_row)
        if issue is None:
            return
        severity = issue.get("severity", "")
        # Burp Scanner's own severities (High/Medium/Low/Information) are
        # a different vocabulary than the checklist Result column
        # (PASS/FAIL/MANUAL/INFO) - a reasonable starting guess, always
        # editable in the dialog before saving.
        default_result = "FAIL" if severity in ("High", "Medium") else "INFO"
        context_label_text = "Burp Scanner  -  %s  -  %s  -  %s" % (
            severity or "?", issue.get("issue", ""), issue.get("url", ""))
        evidence_prefill_text = "Confirmed via Burp Scanner (%s confidence, %s severity).\n%s\n\nDetail:\n%s" % (
            issue.get("confidence", "?"), severity or "?", issue.get("url", ""),
            (issue.get("detail_full", "") or "")[:4000])
        # Reported directly: "request and response detals cptured here
        # for burp scaner resutls" - carry the same real request/response
        # (captured in _on_pull_burp_issues via IScanIssue.getHttpMessages())
        # into the tracked-list evidence too, same as the Repeater/Proxy/
        # Intruder "Log finding to QuickChop" flow already does.
        req_full = issue.get("req_full", "")
        resp_full = issue.get("resp_full", "")
        if req_full:
            evidence_prefill_text += "\n\n---- Request captured ----\n" + req_full[:4000]
        if resp_full:
            evidence_prefill_text += "\n\n---- Response captured ----\n" + resp_full[:4000]
        self._show_log_finding_dialog(context_label_text, issue.get("url", ""), evidence_prefill_text,
                                       "Burp Scanner", default_result=default_result)

    def _build_checklist_reference_panel(self):
        # Reported directly: "reference sho all the check list items with
        # name ows id default sevarity etc" - a browsable/searchable list
        # of every one of the 421 Web App Checklist items (not just the
        # ~77 the automated engine covers), independent of any scan
        # having run, plus its own CSV export so the full reference can be
        # handed off on its own (see MASTER_CHECKLIST / AUTOMATED_CHECKLIST_IDS
        # near the top of this file for where this data comes from).
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        note = JLabel("All %d Web App Checklist items - ID, category, OWASP mapping, default severity/priority, "
                       "and whether Run All Tests already automates it. Independent of any scan you've run."
                       % len(MASTER_CHECKLIST))
        note.setBorder(BorderFactory.createEmptyBorder(2, 2, 6, 2))
        note.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(note)

        search_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        search_row.add(JLabel("Search (ID / category / test name):"))
        self._checklist_ref_search_field = JTextField(30)
        search_row.add(self._checklist_ref_search_field)
        self._checklist_ref_export_btn = JButton("Export checklist reference -> CSV")
        self._checklist_ref_export_btn.addActionListener(self._on_export_checklist_reference)
        search_row.add(self._checklist_ref_export_btn)
        search_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Same unbounded-FlowLayout-row-under-BoxLayout gap bug as Summary's
        # rows (see _build_summary_panel) - bounded here too from the start.
        search_row.setMaximumSize(Dimension(4000, 40))
        top.add(search_row)
        panel.add(top, BorderLayout.NORTH)

        self._checklist_ref_model = ColoredTableModel(
            ["ID", "Category", "OWASP Category", "Test Name", "Default Severity", "Priority", "Automated"], 0)
        ref_table = JTable(self._checklist_ref_model)
        ref_table.setAutoCreateRowSorter(True)
        ref_table.setRowHeight(22)
        col_model = ref_table.getColumnModel()
        for idx, width in ((0, 90), (1, 160), (2, 170), (4, 110), (5, 60), (6, 80)):
            col_model.getColumn(idx).setPreferredWidth(width)
        # Reported directly: "add color codeing for severaity" - Default
        # Severity is column index 4.
        col_model.getColumn(4).setCellRenderer(_SeverityTextRenderer())
        ref_scroll = JScrollPane(ref_table)
        panel.add(ref_scroll, BorderLayout.CENTER)

        def refresh():
            query = (self._checklist_ref_search_field.getText() or "").strip().lower()
            self._checklist_ref_model.setRowCount(0)
            for cid, category, test, severity, priority in MASTER_CHECKLIST:
                haystack = (cid + " " + category + " " + test).lower()
                if query and query not in haystack:
                    continue
                owasp_key = OWASP_CATEGORY_MAP.get(category, OWASP_OTHER_KEY)
                owasp_label = OWASP_GROUPS_BY_KEY.get(owasp_key, owasp_key)
                automated = "Yes" if cid in AUTOMATED_CHECKLIST_IDS else "No"
                self._checklist_ref_model.addRow([cid, category, owasp_label, test, severity, priority, automated])

        self._checklist_ref_search_field.getDocument().addDocumentListener(_CallbackDocumentListener(refresh))
        refresh()
        return panel

    def _on_export_checklist_reference(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Choose a folder to save the checklist reference CSV into")
        if chooser.showSaveDialog(self._main_panel) != JFileChooser.APPROVE_OPTION:
            return
        dest_dir = chooser.getSelectedFile().getAbsolutePath()
        path = os.path.join(dest_dir, "quickchop_checklist_reference_%s.csv" % str(int(time.time())))
        try:
            with open(path, "wb") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Category", "OWASP Category", "Test Name",
                                  "Default Severity", "Priority", "Automated"])
                for cid, category, test, severity, priority in MASTER_CHECKLIST:
                    owasp_key = OWASP_CATEGORY_MAP.get(category, OWASP_OTHER_KEY)
                    owasp_label = OWASP_GROUPS_BY_KEY.get(owasp_key, owasp_key)
                    automated = "Yes" if cid in AUTOMATED_CHECKLIST_IDS else "No"
                    writer.writerow([
                        cid.encode("utf-8", "replace"), category.encode("utf-8", "replace"),
                        owasp_label.encode("utf-8", "replace"), test.encode("utf-8", "replace"),
                        severity.encode("utf-8", "replace"), priority.encode("utf-8", "replace"),
                        automated.encode("utf-8", "replace"),
                    ])
            self._set_status("Exported the full %d-item checklist reference to %s" % (len(MASTER_CHECKLIST), path))
        except Exception as e:
            self._callbacks.printError("Checklist reference export failed: %s" % e)
            JOptionPane.showMessageDialog(self._main_panel, "Export failed: %s" % e,
                                           EXT_NAME, JOptionPane.ERROR_MESSAGE)

    def _build_status_bar(self):
        self._status_label = JLabel("Ready.")
        self._status_label.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8))
        return self._status_label

    def _materialize_engine_script(self, out_dir):
        """Decode the embedded _ENGINE_SOURCE_B64 (checklist_auto_scan.py's
        full source - see the constant's definition near the top of this
        file) out to a real .py file on disk, and return its path.

        Reported directly: "make it one file instead of two python files
        so it is easy to share with burp extension marketplace without
        the dependency or need to share autoscan script separately" -
        this is what makes that true: the engine's source now travels
        INSIDE WPTChecklistScanner.py, so there's nothing second to
        install/lose/version-mismatch. It still has to land on disk as a
        real file before this can shell out to it though - Jython can't
        execute embedded CPython-3-only source in-process (see this
        file's module docstring for why the subprocess split exists at
        all: pandas/xlsxwriter/requests aren't importable under Jython).
        Written fresh into the SAME output folder as this run's other
        artifacts every time (cheap, and guarantees it's always exactly
        the version embedded in the extension currently loaded - no
        stale copy from a previous QuickChop version can linger)."""
        import base64
        engine_path = os.path.join(out_dir, "quickchop_engine.py")
        try:
            source_bytes = base64.b64decode(_ENGINE_SOURCE_B64)
            with open(engine_path, "wb") as f:
                f.write(source_bytes)
        except Exception as e:
            raise Exception("Could not write the bundled scan engine to %s: %s" % (engine_path, e))
        return engine_path

    # ------------------------------------------------------------------
    # Config panel button handlers
    # ------------------------------------------------------------------
    def _on_browse_output_dir(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        if chooser.showOpenDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            self._output_dir_field.setText(chooser.getSelectedFile().getAbsolutePath())

    def _on_pull_targets(self, event):
        try:
            history = self._callbacks.getProxyHistory()
        except Exception as e:
            self._set_status("Could not read Proxy history: %s" % e)
            return
        full_urls = self._pull_full_urls_checkbox.isSelected()
        cap = 100 if full_urls else 50
        seen = set()
        bases = []
        for item in history:
            try:
                url = self._helpers.analyzeRequest(item).getUrl()
                if not self._callbacks.isInScope(url):
                    continue
                if full_urls:
                    # Full URL, path included, query string stripped (a
                    # query string on its own doesn't change which
                    # checklist items apply, and would otherwise blow up
                    # the distinct-URL count with near-duplicates).
                    entry = "%s://%s%s" % (url.getProtocol(), url.getAuthority(), url.getPath() or "/")
                else:
                    # One entry per distinct HOST only (default) - almost
                    # all checklist items are host-level (headers/SSL/
                    # cookies/etc.), so this is normal/expected to
                    # collapse to a single row for a single-host
                    # engagement, not a bug.
                    entry = "%s://%s" % (url.getProtocol(), url.getAuthority())
                if entry not in seen:
                    seen.add(entry)
                    bases.append(entry)
            except Exception:
                continue
            if len(bases) >= cap:
                break
        if not bases:
            self._set_status("No in-scope requests found in Proxy history yet. Browse the target through Burp's "
                              "Proxy first (Target > Scope must be set), then try again - or just type URLs "
                              "directly into the Targets box.")
            return
        self._targets_area.setText("\n".join(bases))
        self._set_status("Pulled %d in-scope target(s) from Proxy history%s." % (
            len(bases), " (full URLs)" if full_urls else " (one per host - tick 'Pull full URLs' for paths too)"))

    def _on_capture_session(self, event):
        try:
            history = self._callbacks.getProxyHistory()
        except Exception as e:
            self._set_status("Could not read Proxy history: %s" % e)
            return
        captured_cookie = None
        captured_auth = None
        # Walk from most recent backwards so we pick up your latest session.
        for item in reversed(list(history)):
            try:
                req = self._helpers.analyzeRequest(item)
                url = req.getUrl()
                if not self._callbacks.isInScope(url):
                    continue
                for h in req.getHeaders():
                    if h.lower().startswith("cookie:") and not captured_cookie:
                        captured_cookie = h.split(":", 1)[1].strip()
                    if h.lower().startswith("authorization:") and not captured_auth:
                        captured_auth = h.strip()
                if captured_cookie or captured_auth:
                    break
            except Exception:
                continue
        if captured_cookie:
            self._cookie_field.setText(captured_cookie)
        if captured_auth:
            self._extra_header_field.setText(captured_auth)
        if not captured_cookie and not captured_auth:
            self._set_status("No Cookie/Authorization header found on any in-scope request yet - browse an "
                              "authenticated page through Burp's Proxy first, or paste your session Cookie "
                              "manually above.")
        else:
            self._set_status("Session captured from Proxy history (Cookie%s). Values are used locally when "
                              "invoking checklist_auto_scan.py - never sent anywhere else." %
                              (" + Authorization" if captured_auth else ""))

    def _on_pull_burp_issues(self, event):
        targets = self._get_target_list()
        prefix = targets[0] if targets else None
        try:
            issues = self._callbacks.getScanIssues(prefix)
        except Exception as e:
            self._set_status("Could not read Burp Scanner issues: %s" % e)
            return
        self._burp_issues_model.setRowCount(0)
        # Reported directly: "when I double click it is not openign
        # related record like scanner page does" and separately "why burp
        # findigns are not adding a vulnerabilityes and updating the
        # KPIS" - the table only ever held the truncated (400-char)
        # display strings, nothing to show a full-detail popup from or to
        # hand off to the "Log finding to QuickChop" dialog. Keep the
        # untruncated detail text per row here, in the SAME order as
        # addRow() below, so a table row index (even after the user
        # re-sorts the view - see convertRowIndexToModel in the
        # double-click/add-to-tracked handlers) can look its full record
        # back up.
        self._burp_issues_raw = []
        if not issues:
            self._set_status("No Burp Scanner issues found for prefix %r - this needs Burp Pro's Scanner to have "
                              "already run against the target (passive or active)." % prefix)
            return
        for issue in issues:
            try:
                detail_full = re.sub("<[^>]+>", " ", issue.getIssueDetail() or "").strip()
                severity = issue.getSeverity()
                confidence = issue.getConfidence()
                issue_name = issue.getIssueName()
                url = str(issue.getUrl())
                # Reported directly: "request and response detals cptured
                # here for burp scaner resutls" - IScanIssue carries the
                # actual request/response pair(s) Burp Scanner based the
                # finding on (getHttpMessages()), same idea as the real
                # request/response capture already added for the Log
                # finding to QuickChop dialog (see
                # _open_log_finding_dialog) - just from Burp's own Scan
                # Issue object instead of a right-clicked message. Only
                # the FIRST message pair is captured (an issue can carry
                # several near-identical ones; one real example is enough
                # evidence and keeps this from ballooning).
                req_full_text, resp_full_text = "", ""
                try:
                    msgs = issue.getHttpMessages()
                    if msgs:
                        msg = msgs[0]
                        req_bytes = msg.getRequest()
                        if req_bytes is not None:
                            req_full_text = self._helpers.bytesToString(req_bytes)
                        resp_bytes = msg.getResponse()
                        if resp_bytes is not None:
                            resp_full_text = self._helpers.bytesToString(resp_bytes)
                except Exception:
                    pass
                self._burp_issues_model.addRow([severity, confidence, issue_name, url, detail_full[:400]])
                self._burp_issues_raw.append({
                    "severity": severity, "confidence": confidence, "issue": issue_name,
                    "url": url, "detail_full": detail_full,
                    "req_full": req_full_text, "resp_full": resp_full_text,
                })
            except Exception:
                continue
        self._set_status("Pulled %d Burp Scanner issue(s) for cross-reference. Double-click a row for full detail, "
                          "or select one and use 'Add selected to QuickChop tracked list...' to map it to a real "
                          "checklist ID (that's what makes it count toward the KPIs/export - see the tab's note "
                          "above for why they aren't included automatically)." % len(issues))

    # ------------------------------------------------------------------
    # Context menu: "Log finding to QuickChop" (Proxy/Repeater/Intruder/
    # Target/Scanner - anywhere Burp shows a right-click menu on HTTP
    # traffic). Reported directly: "when I can confirm the test XSS in
    # repeater or proxy or intruder selected output can be moved to
    # quickchop for a record vulnerability list so we understand how many
    # findings have been covered."
    # ------------------------------------------------------------------
    def _tool_name_for_flag(self, flag):
        """Maps IBurpExtenderCallbacks.TOOL_* int constants to a readable
        name for the "source" field on a manually-logged row (e.g.
        "Manual (Repeater)") - built once, lazily, off self._callbacks
        rather than hardcoded, so it stays correct across Burp versions
        that might add/renumber tool flags."""
        if not hasattr(self, "_tool_flag_names"):
            names = {}
            for attr in ("TOOL_PROXY", "TOOL_REPEATER", "TOOL_INTRUDER", "TOOL_SCANNER",
                         "TOOL_TARGET", "TOOL_SPIDER", "TOOL_SEQUENCER", "TOOL_DECODER",
                         "TOOL_COMPARER", "TOOL_EXTENDER"):
                try:
                    names[getattr(self._callbacks, attr)] = attr[len("TOOL_"):].title()
                except Exception:
                    pass
            self._tool_flag_names = names
        return self._tool_flag_names.get(flag, "Burp")

    def createMenuItems(self, invocation):
        item = JMenuItem("Log finding to QuickChop...")
        item.addActionListener(lambda event, inv=invocation: self._open_log_finding_dialog(inv))
        return [item]

    def _open_log_finding_dialog(self, invocation):
        # Best-effort context extraction - ANY failure here (unexpected
        # Burp API behaviour for a given tool/context, no response yet,
        # etc.) must still let the dialog open with what it has rather
        # than not open at all, since typing the URL/evidence by hand is
        # a fine fallback and a silent crash here is not.
        tool_name = "Burp"
        url_text, method_text, status_text, selected_text = "", "", "", ""
        req_full_text, resp_full_text = "", ""
        messages = None
        try:
            tool_name = self._tool_name_for_flag(invocation.getToolFlag())
        except Exception:
            pass
        try:
            messages = invocation.getSelectedMessages()
        except Exception:
            messages = None
        if messages:
            try:
                msg = messages[0]
                req_info = self._helpers.analyzeRequest(msg)
                url_text = str(req_info.getUrl())
                method_text = req_info.getMethod()
                resp = msg.getResponse()
                if resp is not None:
                    status_text = str(self._helpers.analyzeResponse(resp).getStatusCode())
                # If the user had actually highlighted text in the request/
                # response editor when they right-clicked (rather than just
                # right-clicking a list row), pull that exact highlighted
                # text in as the starting evidence - it's very likely the
                # payload/response snippet that convinced them this is a
                # real finding.
                bounds = invocation.getSelectionBounds()
                ctx = invocation.getInvocationContext()
                if bounds and bounds[1] > bounds[0]:
                    raw = None
                    if ctx == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                        raw = msg.getRequest()
                    elif ctx == invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
                        raw = resp
                    if raw is not None:
                        selected_text = self._helpers.bytesToString(raw[bounds[0]:bounds[1]])
                # Reported directly: "I didn't see the request and response
                # detail of the original, you can add the below box
                # request and response details captured" - a manually
                # logged finding previously only got the generic
                # "Confirmed via <tool>. METHOD url -> HTTP nnn" line, with
                # none of the actual request/response bytes, unlike the
                # automated engine's evidence which always includes a real
                # curl-command/response block. Capture the FULL raw
                # request/response here (not just a user-highlighted
                # snippet, which is the fallback above and stays empty
                # unless the user deliberately drags a selection first) so
                # every manually-logged finding gets real, original
                # request/response detail by default.
                try:
                    req_bytes = msg.getRequest()
                    if req_bytes is not None:
                        req_full_text = self._helpers.bytesToString(req_bytes)
                except Exception:
                    req_full_text = ""
                try:
                    if resp is not None:
                        resp_full_text = self._helpers.bytesToString(resp)
                except Exception:
                    resp_full_text = ""
            except Exception:
                pass

        context_label_text = "%s%s%s" % (
            tool_name, "  -  %s %s" % (method_text, url_text) if url_text else "",
            "  -  HTTP %s" % status_text if status_text else "")

        # Reported directly: "output is not a command line or request
        # response bases it just a stament" (about the automated engine's
        # WA-OTG-289 evidence, fixed earlier) and now the same complaint
        # for manual findings: "I didn't see the request and response
        # detail of the original, you can add the below box request and
        # response details captured" - cap each side at a generous but
        # bounded size so one huge response body can't make the evidence
        # field unusably long or blow up the export file.
        MAX_CAPTURE_CHARS = 4000
        capture_parts = []
        if req_full_text:
            capture_parts.append(
                "---- Request captured ----\n" + req_full_text[:MAX_CAPTURE_CHARS] +
                ("\n... (truncated)" if len(req_full_text) > MAX_CAPTURE_CHARS else ""))
        if resp_full_text:
            capture_parts.append(
                "---- Response captured ----\n" + resp_full_text[:MAX_CAPTURE_CHARS] +
                ("\n... (truncated)" if len(resp_full_text) > MAX_CAPTURE_CHARS else ""))
        captured_block = "\n\n".join(capture_parts)

        prefill_parts = ["Confirmed via %s." % tool_name]
        if url_text:
            prefill_parts.append("%s %s" % (method_text, url_text) + (" -> HTTP %s" % status_text if status_text else ""))
        if selected_text:
            prefill_parts.append("\nHighlighted evidence:\n" + selected_text[:2000])
        if captured_block:
            prefill_parts.append("\n" + captured_block)
        evidence_prefill_text = "\n".join(prefill_parts)

        self._show_log_finding_dialog(context_label_text, url_text, evidence_prefill_text, tool_name)

    def _show_log_finding_dialog(self, context_label_text, url_text, evidence_prefill_text, tool_name,
                                  default_result="FAIL"):
        """The actual checklist-ID-picker dialog (search box + JList of
        all 421 items + Result + Evidence), shared by both call sites:
        _open_log_finding_dialog (Repeater/Proxy/Intruder right-click) and
        _on_add_burp_finding_to_tracked (the Burp Scanner Findings tab's
        "Add selected to QuickChop tracked list..." button) - reported
        directly: "why burp findigns are not adding a vulnerabilityes and
        updating the KPIS" - Burp Scanner's own issues don't carry real
        WPT checklist IDs, so they can't be auto-merged into the tracked
        list/KPIs without guessing a mapping; this dialog is the
        human-in-the-loop way to confirm which checklist ID a given
        finding (from either source) actually corresponds to."""
        context_label = JLabel(context_label_text)
        context_label.setFont(context_label.getFont().deriveFont(Font.BOLD))
        context_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        search_field = JTextField(30)
        search_field.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        list_model = DefaultListModel()
        id_list = JList(list_model)
        id_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        id_list.setVisibleRowCount(9)
        list_scroll = JScrollPane(id_list)
        list_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        # Row entries: "ID - Category - Test Name" (+ a marker for the
        # ~77 IDs checklist_auto_scan.py already automates, so logging one
        # of those manually is a deliberate override, not confusion about
        # what's left to cover) - filtered live as you type (matches on
        # ID/Category/Test, same "field:value" idea as Detailed Results'
        # own search box).
        def row_label(entry):
            _id, cat, test, sev, pri = entry
            tag = "  [automated]" if _id in AUTOMATED_CHECKLIST_IDS else ""
            return "%s - %s - %s%s" % (_id, cat, test, tag)

        filtered = list(MASTER_CHECKLIST)

        def refresh_list():
            query = (search_field.getText() or "").strip().lower()
            list_model.clear()
            del filtered[:]
            for entry in MASTER_CHECKLIST:
                haystack = (entry[0] + " " + entry[1] + " " + entry[2]).lower()
                if not query or query in haystack:
                    filtered.append(entry)
            for entry in filtered[:200]:  # cap the visible list - typing narrows it further
                list_model.addElement(row_label(entry))
            if len(filtered) > 200:
                list_model.addElement("... %d more - keep typing to narrow it down ..." % (len(filtered) - 200))

        search_field.getDocument().addDocumentListener(_CallbackDocumentListener(refresh_list))
        refresh_list()

        selected_entry_holder = [None]

        def on_list_selection():
            idx = id_list.getSelectedIndex()
            if 0 <= idx < len(filtered):
                selected_entry_holder[0] = filtered[idx]
            else:
                selected_entry_holder[0] = None

        id_list.addListSelectionListener(_CallbackListSelectionListener(on_list_selection))

        result_combo = JComboBox(["FAIL", "PASS", "MANUAL", "INFO"])
        try:
            result_combo.setSelectedItem(default_result)
        except Exception:
            pass

        evidence_area = JTextArea(8, 40)
        evidence_area.setLineWrap(True)
        evidence_area.setWrapStyleWord(True)
        evidence_area.setText(evidence_prefill_text)
        evidence_scroll = JScrollPane(evidence_area)
        evidence_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setPreferredSize(Dimension(680, 560))
        panel.add(context_label)
        spacer1 = JLabel(" ")
        spacer1.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(spacer1)
        id_label = JLabel("Checklist ID (type to search %d items, [automated] = already covered by Run All Tests):"
                           % len(MASTER_CHECKLIST))
        id_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(id_label)
        panel.add(search_field)
        panel.add(list_scroll)
        spacer2 = JLabel(" ")
        spacer2.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(spacer2)
        result_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        result_row.add(JLabel("Result:"))
        result_row.add(result_combo)
        result_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(result_row)
        evidence_label = JLabel("Evidence / notes:")
        evidence_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(evidence_label)
        panel.add(evidence_scroll)

        # Reported directly: "duplicate meant i am submiting a request
        # manetiontng xxs once click out same dialog box opend again to
        # add the details agina" - root cause: clicking OK with no
        # checklist ID selected (easy to do - typing into the search box
        # rebuilds the list and clears any prior selection) used to show
        # a small warning and then just RETURN, discarding everything
        # already typed (evidence text, chosen Result, search text) since
        # the JOptionPane was already closed/disposed by that point. The
        # user then had to right-click all over again and retype from
        # scratch, which looked like "the dialog opened again empty".
        # Looping back on the SAME panel/widgets (nothing recreated, so
        # nothing typed is lost) instead of returning fixes that - the
        # user just needs to click a row in the list and hit OK again.
        while True:
            choice = JOptionPane.showConfirmDialog(self._main_panel, panel, "Log finding to QuickChop",
                                                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            if choice != JOptionPane.OK_OPTION:
                return
            entry = selected_entry_holder[0]
            if entry is None:
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "No checklist ID selected - click a row in the list above, then OK. "
                    "(Your Result/Evidence below are preserved.)",
                    EXT_NAME, JOptionPane.WARNING_MESSAGE)
                continue
            break
        self._save_manual_finding(entry, str(result_combo.getSelectedItem()),
                                   evidence_area.getText(), url_text, tool_name)

    def _save_manual_finding(self, entry, result, evidence, url, tool_name):
        cid, category, test, severity, priority = entry
        row = {
            "source_input": url or "manual", "url_role": "manual", "url": url,
            "id": cid, "category": category, "test": test, "severity": severity, "priority": priority,
            "result": result, "evidence": evidence, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "evidence_image_base64": None, "source": "Manual (%s)" % tool_name,
        }
        # Replace any existing row for this same ID (automated OR a
        # previous manual log) - one current verdict per checklist ID,
        # same "re-run replaces" behaviour as _worker_run_scan's merge for
        # automated re-runs, so re-logging a finding updates it in place
        # instead of piling up duplicate rows for the same ID.
        self._rows = [r for r in self._rows if r.get("id") != cid]
        self._rows.append(row)
        self._populate_results_table()
        self._populate_summary()
        self._main_panel.revalidate()
        self._main_panel.repaint()
        self._set_status("Logged %s (%s) as %s - %d finding(s) tracked so far." % (cid, test, result, len(self._rows)))

    # ------------------------------------------------------------------
    # Run / re-run / export
    # ------------------------------------------------------------------
    def _get_target_list(self):
        text = self._targets_area.getText() or ""
        return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]

    def _on_run_all(self, event):
        self._start_scan(only_ids=None)

    def _on_rerun_selected(self, event):
        rows = self._results_table.getSelectedRows()
        if not rows:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Select one or more rows in 'Detailed Results' first.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        ids = set()
        for r in rows:
            model_row = self._results_table.convertRowIndexToModel(r)
            cid = self._results_table_model.getValueAt(model_row, 0)
            if cid:
                ids.add(str(cid))
        if not ids:
            return
        self._start_scan(only_ids=sorted(ids))

    def _on_export(self, event):
        if not self._rows:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Nothing to export yet - run a scan and/or log a manual finding first.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Choose a folder to copy the JSON/CSV/XLSX into")
        if chooser.showSaveDialog(self._main_panel) != JFileChooser.APPROVE_OPTION:
            return
        dest_dir = chooser.getSelectedFile().getAbsolutePath()
        copied = []

        # Reported directly: "when I confirm a test XSS in Repeater/Proxy/
        # Intruder... record vulnerability list so we understand how many
        # findings have been covered" - manually-logged findings (see
        # _save_manual_finding, wired to the "Log finding to QuickChop"
        # right-click menu) only ever lived in self._rows in memory, never
        # in the .json/.csv/.xlsx files checklist_auto_scan.py itself
        # wrote to disk (those only ever knew about the automated rows) -
        # so Export used to silently drop every manual finding from what
        # actually reaches ReportSystem. This writes a fresh
        # "quickchop_full_<timestamp>.{json,csv}" pair straight from
        # self._rows (automated + manual together, whichever is current
        # right now) so manual findings actually make it into what you
        # hand off, instead of only existing inside QuickChop's own tabs.
        # Pure Jython stdlib (json/csv) - no pandas/xlsxwriter needed, so
        # this part always works regardless of the Python 3 side's
        # package situation.
        stamp = str(int(time.time()))
        full_base = os.path.join(dest_dir, "quickchop_full_%s" % stamp)
        try:
            with open(full_base + ".json", "w") as f:
                json.dump(self._rows, f, indent=2)
            with open(full_base + ".csv", "wb") as f:
                writer = csv.writer(f)
                writer.writerow(["Source", "URL", "ID", "Category", "Test", "Severity", "Priority",
                                  "Result", "Evidence", "Checked At"])
                for r in self._rows:
                    writer.writerow([
                        (r.get("source", "Automated") or "").encode("utf-8", "replace"),
                        (r.get("url", "") or "").encode("utf-8", "replace"),
                        (r.get("id", "") or "").encode("utf-8", "replace"),
                        (r.get("category", "") or "").encode("utf-8", "replace"),
                        (r.get("test", "") or "").encode("utf-8", "replace"),
                        (r.get("severity", "") or "").encode("utf-8", "replace"),
                        (r.get("priority", "") or "").encode("utf-8", "replace"),
                        (r.get("result", "") or "").encode("utf-8", "replace"),
                        (r.get("evidence", "") or "").encode("utf-8", "replace"),
                        (r.get("checked_at", "") or "").encode("utf-8", "replace"),
                    ])
            copied.append(os.path.basename(full_base + ".json"))
            copied.append(os.path.basename(full_base + ".csv"))
        except Exception as e:
            self._callbacks.printError("QuickChop combined export failed: %s" % e)

        if self._last_out_base and os.path.exists(self._last_out_base + ".json"):
            for ext in (".csv", ".json", ".xlsx", "_consolidated.csv", "_consolidated.json"):
                src = self._last_out_base + ext
                if os.path.exists(src):
                    dst = os.path.join(dest_dir, os.path.basename(src))
                    try:
                        with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
                            fdst.write(fsrc.read())
                        copied.append(os.path.basename(dst))
                    except Exception as e:
                        self._callbacks.printError("Export copy failed for %s: %s" % (src, e))

        manual_count = sum(1 for r in self._rows if (r.get("source") or "").startswith("Manual"))
        msg = ("Exported: %s -> %s (upload quickchop_full_*.json here to ReportSystem's 'Import Auto-Scan "
               "Results' page for the combined automated+manual set%s)"
               % (", ".join(copied), dest_dir,
                  " - includes %d manually-logged finding(s)" % manual_count if manual_count else ""))
        if not self._last_xlsx_ok:
            msg += ("  [No .xlsx from the automated engine this run - your Python 3 is missing "
                     "'pandas'/'xlsxwriter'; the quickchop_full_*.json/.csv above are complete either way.]")
        self._set_status(msg)

    def _start_scan(self, only_ids):
        if self._scan_running:
            JOptionPane.showMessageDialog(self._main_panel, "A scan is already running - wait for it to finish.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        targets = self._get_target_list()
        if not targets:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "No targets configured. Type one or more URLs into the Targets box, "
                                           "or click 'Pull in-scope targets from Proxy history'.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        self._scan_running = True
        running_msg = "Running%s against %d target(s)..." % (
            " (%d selected ID(s))" % len(only_ids) if only_ids else "", len(targets))
        self._set_status(running_msg)
        self._run_all_btn.setEnabled(False)
        self._rerun_selected_btn.setEnabled(False)
        self._cancel_scan_btn.setEnabled(True)
        # Summary tab's own copy of these same buttons (see
        # _build_summary_panel) - kept enabled/disabled in lockstep with
        # the Configuration tab's so neither copy can be clicked twice or
        # left stuck showing "runnable" mid-scan.
        self._summary_run_all_btn.setEnabled(False)
        self._summary_rerun_selected_btn.setEnabled(False)
        self._summary_cancel_scan_btn.setEnabled(True)
        # Reported directly: "in run all test and re-run selected below
        # add progress bar while test are running and add statement once
        # completed never know if test are performed or idle", later
        # "no line by line URL read no 5-10 test perfored and captue
        # progreess eaxly how i it was before" - checklist_auto_scan.py
        # now streams a "QUICKCHOP_ROW|..." line per finished check, and
        # _run_checklist_auto_scan reads that live and pushes batches to
        # _on_scan_progress, so the Summary tab's own progress bar
        # (driven by real pass+fail/total of the rows captured so far -
        # see _update_progress) grows for real as results come in. This
        # Configuration-tab bar has no natural percentage of its own
        # (subprocess start-up, per-target work, etc. aren't weighted),
        # so it stays indeterminate ("still going") but the status label
        # next to it is updated with a live row count each batch so it's
        # never ambiguous whether the scan is stuck or progressing.
        self._config_progress_bar.setIndeterminate(True)
        self._config_progress_bar.setString("Running...")
        self._config_status_label.setText(running_msg)
        self._reset_rows_for_scan(only_ids)
        t = threading.Thread(target=self._worker_run_scan, args=(targets, only_ids))
        t.daemon = True
        t.start()

    def _kill_scan_proc(self, reason):
        """Runs on the watchdog Timer thread (timeout) or the EDT (user
        clicked Cancel Scan) - either way, force-kill whatever
        checklist_auto_scan.py subprocess is currently running. Safe to
        call even if the process already finished on its own (proc.kill()
        on an already-exited Popen is a harmless no-op in both Jython and
        CPython)."""
        self._scan_cancelled = reason
        proc = self._scan_proc
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass

    def _on_cancel_scan(self, event):
        if not self._scan_running:
            return
        self._kill_scan_proc("cancelled by user")
        self._config_status_label.setText("Cancelling...")

    def _worker_run_scan(self, targets, only_ids):
        try:
            rows = self._run_checklist_auto_scan(targets, only_ids)
            if only_ids:
                # Merge re-run rows into existing result set (replace matching IDs, keep the rest).
                # self._rows already only holds "kept" + live-streamed-during-this-run rows at this
                # point (see _reset_rows_for_scan/_on_scan_progress) - re-filtering here is cheap and
                # makes the final swap correct/idempotent either way, landing on the authoritative
                # (screenshot-inclusive) rows read back from the JSON file rather than the streamed ones.
                kept = [r for r in self._rows if r.get("id") not in only_ids]
                self._rows = kept + rows
            else:
                self._rows = rows
            SwingUtilities.invokeLater(lambda: self._on_scan_complete(None))
        except Exception as e:
            SwingUtilities.invokeLater(lambda: self._on_scan_complete(e))

    def _reset_rows_for_scan(self, only_ids):
        """Runs on the EDT right before a scan's worker thread starts (see
        _start_scan). Clears out whatever this run is about to replace -
        ALL rows for a fresh Run All, or just the selected IDs' old rows
        for a Re-run Selected - so the incremental updates that follow
        (_on_scan_progress) build up from a clean, correct baseline
        instead of a scan's live partial results getting added on top of
        stale ones."""
        if only_ids:
            self._rows = [r for r in self._rows if r.get("id") not in only_ids]
        else:
            self._rows = []
        self._update_summary_top_cards()
        self._populate_results_table()
        self._progress_label.setText("Scanning... 0 row(s) captured so far")

    def _on_scan_progress(self, rows_batch):
        """Runs on the EDT (invoked via SwingUtilities.invokeLater from the
        scan worker thread as each small batch of QUICKCHOP_ROW lines
        arrives) - merges the batch into self._rows and refreshes just
        the cheap-to-recompute widgets (KPI cards, progress bar/label,
        Detailed Results table) so the scan visibly grows result-by-
        result instead of sitting idle until it's 100% done. The heavier
        per-category breakdowns (_refresh_worst_findings/
        _refresh_summary_coverage_table/_refresh_categories_tab) are left
        for _on_scan_complete at the end, once, on the final authoritative
        (screenshot-inclusive) row set."""
        if not rows_batch:
            return
        self._rows.extend(rows_batch)
        self._update_summary_top_cards()
        total = len(self._rows)
        present_cats = set(r.get("category", "?") for r in self._rows)
        self._progress_label.setText(
            "Scanning... %d row(s) captured so far  |  %d categor%s covered" % (
                total, len(present_cats), "y" if len(present_cats) == 1 else "ies"))
        self._populate_results_table()
        self._config_status_label.setText("Running... %d result(s) captured so far" % total)

    def _run_checklist_auto_scan(self, targets, only_ids):
        python_path = self._python_path_field.getText().strip() or "python3"

        out_dir = self._output_dir_field.getText().strip() or tempfile.gettempdir()
        # Self-extracting engine (see _materialize_engine_script) - no
        # separate checklist_auto_scan.py file to locate/configure any more.
        script_path = self._materialize_engine_script(out_dir)
        stamp = str(int(time.time()))
        out_base = os.path.join(out_dir, "burp_wpt_scan_%s" % stamp)

        url_file = os.path.join(out_dir, "burp_wpt_targets_%s.txt" % stamp)
        with open(url_file, "w") as f:
            f.write("\n".join(targets))

        cmd = [python_path, script_path, "--url-file", url_file, "--out", out_base, "--screenshot", "fail"]
        if not self._cli_tools_checkbox.isSelected():
            cmd.append("--no-cli-tools")

        cookie = self._cookie_field.getText().strip()
        if cookie:
            cmd += ["--cookie", cookie]
        extra_header = self._extra_header_field.getText().strip()
        if extra_header:
            cmd += ["--header", extra_header]
        if only_ids:
            cmd += ["--only", ",".join(only_ids)]

        self._callbacks.printOutput("Running: %s" % " ".join(cmd))
        # stderr is merged into stdout (rather than its own PIPE) because
        # this now reads stdout incrementally line-by-line below instead
        # of via proc.communicate() - communicate() drains both pipes in
        # parallel so it can't deadlock, but a manual read loop watching
        # only one pipe risks exactly that deadlock if the OTHER pipe's
        # OS buffer fills up while nobody's reading it. Merging avoids a
        # second pipe existing at all.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
        self._scan_proc = proc
        # Reported directly: "after completing the scan it crashed or
        # slow not working properly burp freezes" - proc.communicate()
        # (Jython's subprocess, like Python 2.7's, has no built-in
        # timeout= kwarg) previously blocked FOREVER if
        # checklist_auto_scan.py or a CLI tool it shells out to
        # (nmap/testssl.sh/etc.) hung against an unresponsive target -
        # the Run/Re-run buttons would then stay disabled and the
        # progress bar would spin indefinitely with no way to recover
        # short of restarting Burp. This watchdog force-kills the
        # subprocess (and _on_cancel_scan lets the user do it manually
        # via the Cancel button) instead of hanging indefinitely.
        watchdog = threading.Timer(SCAN_TIMEOUT_SECONDS, self._kill_scan_proc, args=("timed out",))
        watchdog.daemon = True
        watchdog.start()
        # Reported directly: "no line by line URL read no 5-10 test
        # perfored and captue progreess eaxly how i it was before" - read
        # stdout AS THE PROCESS RUNS (instead of blocking on
        # proc.communicate() until it exits) so each "QUICKCHOP_ROW|..."
        # line (emitted by checklist_auto_scan.py's add(), one per
        # finished check - see PROGRESS_FLUSH_EVERY above) can be handed
        # to the UI in small batches as they arrive, not all at once at
        # the very end.
        output_lines = []
        progress_batch = []

        def flush_progress_batch():
            if progress_batch:
                batch_copy = list(progress_batch)
                del progress_batch[:]
                SwingUtilities.invokeLater(lambda: self._on_scan_progress(batch_copy))

        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                output_lines.append(line)
                stripped = line.strip()
                if stripped.startswith("QUICKCHOP_ROW|"):
                    try:
                        progress_batch.append(json.loads(stripped[len("QUICKCHOP_ROW|"):]))
                    except Exception:
                        pass
                    if len(progress_batch) >= PROGRESS_FLUSH_EVERY:
                        flush_progress_batch()
            flush_progress_batch()
            proc.wait()
        finally:
            watchdog.cancel()
            self._scan_proc = None
        full_output = "".join(output_lines)
        self._callbacks.printOutput(full_output)
        if self._scan_cancelled:
            reason = self._scan_cancelled
            self._scan_cancelled = False
            raise Exception("Scan %s (checklist_auto_scan.py was force-killed)." % reason)
        if proc.returncode != 0:
            # stderr is merged into stdout above, so the tail of the combined
            # output (rather than a separate stderr string) is the best error context available.
            raise Exception("checklist_auto_scan.py exited with code %s:\n%s" % (proc.returncode, full_output[-4000:]))

        json_path = out_base + ".json"
        if not os.path.exists(json_path):
            raise Exception("Scan finished but no output JSON was found at %s" % json_path)

        # checklist_auto_scan.py degrades gracefully (CSV/JSON still get
        # written) when "pandas"/"xlsxwriter" aren't installed on whatever
        # Python 3 the field above points at - it only prints a warning to
        # stdout, which lands in Extensions' Output console, easy to miss.
        # Reported directly: "output doens contan excel" - track it here so
        # the UI itself says something instead of failing silently.
        self._last_xlsx_ok = os.path.exists(out_base + ".xlsx")

        with open(json_path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict) and "results" in data:
            data = data["results"]

        self._last_out_base = out_base
        return data

    def _on_scan_complete(self, error):
        self._scan_running = False
        self._run_all_btn.setEnabled(True)
        self._rerun_selected_btn.setEnabled(True)
        self._cancel_scan_btn.setEnabled(False)
        self._summary_run_all_btn.setEnabled(True)
        self._summary_rerun_selected_btn.setEnabled(True)
        self._summary_cancel_scan_btn.setEnabled(False)
        self._config_progress_bar.setIndeterminate(False)
        if error:
            fail_msg = "Scan failed: %s" % error
            self._config_progress_bar.setValue(0)
            self._config_progress_bar.setString("Failed")
            self._config_status_label.setText(fail_msg)
            self._set_status(fail_msg)
            self._main_panel.revalidate()
            self._main_panel.repaint()
            JOptionPane.showMessageDialog(self._main_panel, str(error), EXT_NAME, JOptionPane.ERROR_MESSAGE)
            return
        self._config_progress_bar.setValue(100)
        self._config_progress_bar.setString("Complete")
        self._clear_filter()  # don't let a stale filter hide rows from a fresh/re-run scan
        self._populate_results_table()
        self._populate_summary()
        if self._last_xlsx_ok:
            done_msg = ("Scan complete - %d row(s). Use 'Export' to write JSON/CSV/XLSX for ReportSystem import."
                         % len(self._rows))
        else:
            done_msg = (
                "Scan complete - %d row(s), but NO .xlsx was written (JSON/CSV are complete and still fine to "
                "import). Your Python 3 is missing 'pandas'/'xlsxwriter' - run: pip3 install pandas xlsxwriter "
                "(add --break-system-packages if that errors) on the SAME machine/interpreter set above, then "
                "re-run." % len(self._rows))
        self._config_status_label.setText(done_msg)
        self._set_status(done_msg)
        # Belt-and-suspenders for the same stale-repaint issue the
        # _TabChangeListener above targets: a scan can finish while the
        # user is looking at a DIFFERENT tab than the ones just repopulated
        # (Summary/Categories), so force the whole window to repaint here
        # too rather than relying only on the next tab switch to do it.
        self._main_panel.revalidate()
        self._main_panel.repaint()

    # ------------------------------------------------------------------
    # Rendering results
    # ------------------------------------------------------------------
    def _populate_results_table(self):
        self._results_table_model.setRowCount(0)
        for r in self._rows:
            self._results_table_model.addRow([
                r.get("id", ""), r.get("category", ""), r.get("test", ""),
                r.get("severity", ""), r.get("priority", ""), r.get("result", ""),
                (r.get("evidence") or "")[:300], r.get("url", ""),
                # Reported directly: "when I confirm a test XSS in Repeater/
                # Proxy/Intruder ... record vulnerability list" - rows from
                # checklist_auto_scan.py never had a "source" key at all
                # (only manually-logged rows do - see _save_manual_finding),
                # so this column reads as "Automated" for every scan-
                # produced row and shows the tool ("Manual (Repeater)" etc.)
                # for a manually-logged one.
                r.get("source", "Automated"),
            ])

    def _stats_for_categories(self, categories):
        """Totals across self._rows, optionally restricted to a list of
        category names (None = every row - the global/'All Categories'
        scope)."""
        total = 0
        passed = 0
        failed = 0
        other = 0
        for r in self._rows:
            cat = r.get("category", "?")
            if categories is not None and cat not in categories:
                continue
            total += 1
            res = r.get("result", "?")
            if res == "PASS":
                passed += 1
            elif res == "FAIL":
                failed += 1
            else:
                other += 1
        return {"total": total, "pass": passed, "fail": failed, "other": other}

    def _set_card_stats(self, total_card, pass_card, fail_card, manual_card, stats):
        total_card["value_label"].setText(str(stats["total"]))
        pass_card["value_label"].setText(str(stats["pass"]))
        fail_card["value_label"].setText(str(stats["fail"]))
        manual_card["value_label"].setText(str(stats["other"]))

    def _update_progress(self, bar, detail_label, stats):
        total = stats["total"]
        determined_pct = int(round(100.0 * (stats["pass"] + stats["fail"]) / total)) if total else 0
        bar.setValue(determined_pct)
        bar.setString("%d%%" % determined_pct)
        detail_label.setText("%d%% automated (PASS/FAIL determined)  -  %d row(s) need manual review"
                              % (determined_pct, stats["other"]))

    def _categories_covered_text(self, mode):
        # Reported directly: "owasp catagories coved is 10 byt KPI shows
        # 8" - the numerator/denominator pair needs to match whichever
        # mode is active: a plain count of distinct real categories seen
        # this scan in "all" mode (the real category set is open-ended -
        # only ~13 of the ~421 master-checklist categories are
        # automatable, so there's no single fixed denominator that's
        # always meaningful here), or "covered OWASP buckets / 10" in
        # "owasp" mode (10 is always a real, meaningful denominator).
        present_cats = set(r.get("category", "?") for r in self._rows)
        if mode == "owasp":
            covered_keys = set()
            for cat in present_cats:
                key = OWASP_CATEGORY_MAP.get(cat, OWASP_OTHER_KEY)
                if key != OWASP_OTHER_KEY:
                    covered_keys.add(key)
            return "%d / %d" % (len(covered_keys), len(OWASP_GROUPS))
        return str(len(present_cats))

    def _update_categories_top_cards(self):
        stats = self._stats_for_categories(self._cat_selected_categories)
        self._set_card_stats(self._cat_card_total, self._cat_card_pass, self._cat_card_fail,
                              self._cat_card_manual, stats)
        self._cat_card_categories["value_label"].setText(self._categories_covered_text(self._cat_mode))
        self._update_progress(self._cat_progress_bar, self._cat_progress_detail_label, stats)

    def _update_summary_top_cards(self):
        stats = self._stats_for_categories(None)
        self._set_card_stats(self._card_total, self._card_pass, self._card_fail, self._card_manual, stats)
        self._card_categories["value_label"].setText(self._categories_covered_text(self._summary_coverage_mode))
        self._update_progress(self._progress_bar, self._progress_detail_label, stats)

    def _refresh_worst_findings(self):
        # Reported directly: "add color codeing for severaity add table
        # form" - rebuilt as a real JTable (see _build_summary_panel);
        # self._worst_findings_rows keeps the exact row dict behind each
        # table row, in the SAME order they're added below, so a
        # double-click (view row -> model row, sorting-safe - see
        # _WorstFindingsDoubleClickListener) can look the full row back
        # up for the shared _show_row_detail popup.
        self._worst_findings_table_model.setRowCount(0)
        self._worst_findings_rows = []
        fails = [r for r in self._rows if r.get("result") == "FAIL"]
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        fails.sort(key=lambda r: (sev_rank.get(r.get("severity", ""), 5), r.get("id", "")))
        # Reported directly: "add slider so i can navigae down" - this
        # table now sits inside its own JScrollPane (see
        # _build_summary_panel's worst_box), so it no longer needs a tiny
        # hard cap to avoid blowing out the tab's height; 200 is just a
        # sane backstop against a truly pathological scan.
        top = fails[:200]
        for r in top:
            # Now that findings can come from either the automated engine
            # or a manually-logged Repeater/Proxy/Intruder right-click
            # (see _save_manual_finding), tag which one each row came
            # from so this list stays meaningful once both are mixed
            # together.
            self._worst_findings_table_model.addRow([
                r.get("id", ""), r.get("category", ""), r.get("test", ""),
                r.get("severity") or "Informational", r.get("source", "Automated"),
            ])
            self._worst_findings_rows.append(r)
        if len(fails) > len(top):
            self._set_status("Failed vulnerabilities table shows the top %d of %d FAIL result(s) - "
                              "see Detailed Results (filter: result=FAIL) for the rest." % (len(top), len(fails)))

    def _show_worst_finding_detail_from_event(self, event):
        view_row = self._worst_findings_table.rowAtPoint(event.getPoint())
        if view_row < 0:
            return
        model_row = self._worst_findings_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._worst_findings_rows):
            return
        self._show_row_detail(self._worst_findings_rows[model_row])

    def _refresh_summary_coverage_table(self):
        present_cats = sorted(set(KNOWN_CATEGORIES) | set(r.get("category", "?") for r in self._rows))
        self._summary_coverage_table_cats = []
        self._summary_coverage_table_labels = []
        if self._summary_coverage_mode == "owasp":
            self._summary_coverage_table_model.setColumnIdentifiers(
                ["OWASP Category", "Total", "Pass", "Fail", "Manual/Other"])
            self._summary_coverage_table_model.setRowCount(0)
            self._summary_coverage_hint.setText(
                "Double-click a row to jump to Detailed Results for every category mapped to that OWASP "
                "bucket, or use the Categories tab's OWASP Top 10 toggle to browse interactively.")
            for key, label in OWASP_GROUPS:
                cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == key]
                stats = self._stats_for_categories(cats) if cats else {"total": 0, "pass": 0, "fail": 0, "other": 0}
                self._summary_coverage_table_model.addRow(
                    [label, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._summary_coverage_table_cats.append(cats)
                self._summary_coverage_table_labels.append(label)
            other_cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == OWASP_OTHER_KEY]
            if other_cats:
                stats = self._stats_for_categories(other_cats)
                self._summary_coverage_table_model.addRow(
                    [OWASP_OTHER_LABEL, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._summary_coverage_table_cats.append(other_cats)
                self._summary_coverage_table_labels.append(OWASP_OTHER_LABEL)
        else:
            self._summary_coverage_table_model.setColumnIdentifiers(
                ["Category", "Total", "Pass", "Fail", "Manual/Other"])
            self._summary_coverage_table_model.setRowCount(0)
            self._summary_coverage_hint.setText(
                "Double-click a row to jump to Detailed Results for that category, or use the Categories "
                "tab to browse interactively.")
            for cat in present_cats:
                stats = self._stats_for_categories([cat])
                self._summary_coverage_table_model.addRow(
                    [cat, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._summary_coverage_table_cats.append([cat])
                self._summary_coverage_table_labels.append(cat)
        self._apply_coverage_table_widths(self._summary_coverage_table)

    def _refresh_categories_tab(self):
        present_cats = sorted(set(KNOWN_CATEGORIES) | set(r.get("category", "?") for r in self._rows))

        # --- left list ---
        self._populating_cat_list = True
        self._cat_list_model.clear()
        self._cat_list_keys = ["ALL"]
        self._cat_list_cats = [None]
        self._cat_list_labels = ["All Categories"]
        self._cat_list_model.addElement("All Categories")
        if self._cat_mode == "owasp":
            for key, label in OWASP_GROUPS:
                cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == key]
                stats = self._stats_for_categories(cats) if cats else {"total": 0, "pass": 0, "fail": 0, "other": 0}
                count_text = "%d/%d" % (stats["pass"], stats["total"]) if cats else "-"
                self._cat_list_model.addElement("%s  (%s)" % (label, count_text))
                self._cat_list_keys.append(key)
                self._cat_list_cats.append(cats)
                self._cat_list_labels.append(label)
            other_cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == OWASP_OTHER_KEY]
            if other_cats:
                stats = self._stats_for_categories(other_cats)
                self._cat_list_model.addElement("%s  (%d/%d)" % (OWASP_OTHER_LABEL, stats["pass"], stats["total"]))
                self._cat_list_keys.append(OWASP_OTHER_KEY)
                self._cat_list_cats.append(other_cats)
                self._cat_list_labels.append(OWASP_OTHER_LABEL)
        else:
            for cat in present_cats:
                stats = self._stats_for_categories([cat])
                self._cat_list_model.addElement("%s  (%d/%d)" % (cat, stats["pass"], stats["total"]))
                self._cat_list_keys.append(cat)
                self._cat_list_cats.append([cat])
                self._cat_list_labels.append(cat)
        self._cat_list.setSelectedIndex(0)
        self._populating_cat_list = False

        # --- right breakdown table (mirrors the same mode) ---
        self._cat_table_keys = []
        self._cat_table_cats = []
        self._cat_table_labels = []
        if self._cat_mode == "owasp":
            self._cat_table_model.setColumnIdentifiers(["OWASP Category", "Total", "Pass", "Fail", "Manual/Other"])
            self._cat_table_model.setRowCount(0)
            self._cat_note_label.setText(
                "Coverage by OWASP Top 10 bucket (categories rolled up per an illustrative mapping - confirm "
                "against ReportSystem's own classification before real engagements). The selected bucket is "
                "highlighted below - double-click any row to jump to Detailed Results for every category in it.")
            for key, label in OWASP_GROUPS:
                cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == key]
                stats = self._stats_for_categories(cats) if cats else {"total": 0, "pass": 0, "fail": 0, "other": 0}
                self._cat_table_model.addRow([label, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._cat_table_keys.append(key)
                self._cat_table_cats.append(cats)
                self._cat_table_labels.append(label)
            other_cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == OWASP_OTHER_KEY]
            if other_cats:
                stats = self._stats_for_categories(other_cats)
                self._cat_table_model.addRow(
                    [OWASP_OTHER_LABEL, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._cat_table_keys.append(OWASP_OTHER_KEY)
                self._cat_table_cats.append(other_cats)
                self._cat_table_labels.append(OWASP_OTHER_LABEL)
        else:
            self._cat_table_model.setColumnIdentifiers(["Category", "Total", "Pass", "Fail", "Manual/Other"])
            self._cat_table_model.setRowCount(0)
            self._cat_note_label.setText(
                "Coverage by category (this scan's targets/session only, not the full ReportSystem master "
                "checklist). The selected category is highlighted below - double-click any row to jump "
                "straight to Detailed Results for it.")
            for cat in present_cats:
                stats = self._stats_for_categories([cat])
                self._cat_table_model.addRow([cat, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._cat_table_keys.append(cat)
                self._cat_table_cats.append([cat])
                self._cat_table_labels.append(cat)
        self._apply_coverage_table_widths(self._cat_table)

        # Reset scope to "All Categories" any time the underlying data (or
        # the mode) changes - keeps the left list, right table, and top
        # cards all unambiguous instead of pointing at a selection that
        # may no longer exist.
        self._set_category_scope(None, "All Categories", "ALL")

    def _populate_summary(self):
        self._update_summary_top_cards()
        total = len(self._rows)
        present_cats = set(r.get("category", "?") for r in self._rows)
        self._progress_label.setText(
            "%d row(s) this scan  |  %d categor%s covered" % (
                total, len(present_cats), "y" if len(present_cats) == 1 else "ies"))

        self._refresh_summary_coverage_table()
        self._refresh_categories_tab()
        # Reported directly: "add bototm fauled vulnerabiitys below the
        # gatagory" - re-added below the Coverage table (see
        # _build_summary_panel); now reflects the unified automated +
        # manually-logged row set, same as everything else on this tab.
        self._refresh_worst_findings()

    def _set_status(self, text):
        self._status_label.setText(text)
        try:
            self._callbacks.printOutput(text)
        except Exception:
            pass


class ColoredTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False

    def getColumnClass(self, col):
        # Reported directly: "sorting now working properly sort brings
        # fail start with 2 then 13 it should list 13 first" -
        # DefaultTableModel reports every column as plain
        # java.lang.Object by default, so JTable's built-in row sorter
        # falls back to comparing values as TEXT ("2" sorts after "13"
        # lexicographically, since '2' > '1') instead of as numbers.
        # Report the actual runtime type already sitting in the column
        # (java.lang.Integer for the Total/Pass/Fail/Manual-Other count
        # columns, String elsewhere) so the sorter compares numerically
        # where it should. See the matching setDefaultRenderer(JInteger,
        # ...) calls alongside setDefaultRenderer(JObject, ...) at each
        # table using this model - without both registrations, reporting
        # Integer.class here alone would make JTable fall back to its
        # own plain built-in numeric renderer (right-aligned, no colors)
        # instead of our category/result coloring, since
        # getDefaultRenderer() resolves the EXACT class first before
        # climbing to Object.class.
        if self.getRowCount() > 0:
            value = self.getValueAt(0, col)
            if value is not None:
                # Reported directly (traceback from Burp's extension Errors
                # console): "AttributeError: 'unicode' object has no
                # attribute 'getClass'" - every row value that comes from
                # JSON (json.load/json.loads, both the final results file
                # and, since the live-progress streaming feature, every
                # in-progress QUICKCHOP_ROW batch too) is a Python `unicode`
                # object in Jython 2, not a real java.lang.Integer/String,
                # and unicode values don't expose .getClass() the way
                # Jython's `str`/native Java types do. That crashed
                # _clear_filter()'s sorter.setRowFilter(None) call (which
                # triggers this) partway through _on_scan_complete, aborting
                # the rest of it silently - looked like the scan "froze" on
                # "Running..." even though it had actually finished. Only a
                # real java.lang.Integer (the coverage tables' Total/Pass/
                # Fail/Manual-Other columns) should report its own class for
                # numeric sorting; anything else - including this unicode
                # case - safely falls through to the JObject default below.
                try:
                    return value.getClass()
                except AttributeError:
                    pass
        return JObject


class _CallbackMouseListener(MouseAdapter):
    """Wraps a zero-arg Python callable as a Java MouseListener - used by
    the clickable KPI cards (_make_stat_card's on_click) on the Summary
    and Categories tabs. Subclasses MouseAdapter directly rather than
    relying on Jython's automatic callable-to-interface coercion, which
    only applies to single-method interfaces (MouseListener has five
    methods) - same reasoning as every other MouseAdapter subclass in
    this file."""

    def __init__(self, callback):
        self._callback = callback

    def mouseClicked(self, event):
        try:
            self._callback()
        except Exception:
            pass


class _ResultsTableDoubleClickListener(MouseAdapter):
    """Double-click on a Detailed Results row to see its full, untruncated
    evidence (real curl/nmap command + response included) - the grid cell
    itself is hard-capped to 300 chars so it stays readable as a table.
    Subclasses MouseAdapter directly (same reasoning as ResultRowRenderer
    below - real Java subclassing sidesteps Jython's interface-coercion
    ambiguity for a plain object exposing a same-named method)."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._show_row_detail_from_event(event)


class _BurpFindingsDoubleClickListener(MouseAdapter):
    """Double-click a Burp Scanner Findings row for its full, untruncated
    detail - reported directly: "when I double click it is not openign
    related record like scanner page does" (i.e. unlike Detailed
    Results' own double-click -> full-evidence popup, see
    _ResultsTableDoubleClickListener above)."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._show_burp_issue_detail_from_event(event)


class _WorstFindingsDoubleClickListener(MouseAdapter):
    """Double-click a row on Summary's Failed vulnerabilities table for
    its full-evidence popup - reported directly: "add color codeing for
    severaity add table form" (the table-conversion this listener came
    with). Same shared _show_row_detail popup as Detailed Results, since
    these are real self._rows dicts, just a filtered/ranked subset - see
    _refresh_worst_findings."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._show_worst_finding_detail_from_event(event)


class _CategoryTableDoubleClickListener(MouseAdapter):
    """Double-click a category/OWASP-bucket row on the Categories tab to
    jump to Detailed Results filtered down to just it - reported
    directly: "it is not taking into the selected catagory findings...
    not allowing to land the fineld items"."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._on_category_table_double_click(event)


class _SummaryCoverageDoubleClickListener(MouseAdapter):
    """Double-click a row on the Summary tab's Coverage table to jump to
    Detailed Results filtered down to it - same idea as
    _CategoryTableDoubleClickListener above, just for the Summary tab's
    own (independent) coverage table."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._on_summary_coverage_table_double_click(event)


class _CategoryListSelectionListener(ListSelectionListener):
    """Single-click a category/OWASP-bucket in the left-side list on the
    Categories tab to rescope the top KPI cards to it, or click "All
    Categories" (index 0, the default) to go back to global totals -
    reported directly: "by default all test should pear if any catarogy
    select then only those test case shuld be apear". Subclasses the
    Java interface directly, same Jython pattern as the MouseAdapter
    listeners above."""

    def __init__(self, extender):
        self._extender = extender

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self._extender._on_category_list_selection()


class _CallbackListSelectionListener(ListSelectionListener):
    """Generic zero-arg-callback wrapper for ListSelectionListener - same
    idea as _CallbackMouseListener above, for the Log Finding dialog's
    searchable checklist-ID JList (see _open_log_finding_dialog), which
    doesn't need any extra per-listener state beyond "something got
    selected, go re-read it"."""

    def __init__(self, callback):
        self._callback = callback

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self._callback()


class _CallbackDocumentListener(DocumentListener):
    """Generic zero-arg-callback wrapper for DocumentListener - same idea
    as _SearchDocumentListener below, but reusable anywhere a text field
    just needs "text changed, go re-filter" (the Log Finding dialog's
    checklist-ID search box)."""

    def __init__(self, callback):
        self._callback = callback

    def insertUpdate(self, event):
        self._callback()

    def removeUpdate(self, event):
        self._callback()

    def changedUpdate(self, event):
        self._callback()


class _TabChangeListener(ChangeListener):
    """Reported directly: 'run and export appearing in two places when i
    go to config page and moving back to other page config page stays
    same only top findings are changing' - a stale-repaint issue where a
    tab's JScrollPane content, redrawn by a background scan thread while
    that tab wasn't the one showing, doesn't get a fresh paint once the
    user switches back to it (only individual labels updated via
    setText() force their own repaint - the surrounding panel doesn't).
    Forcing a full revalidate()+repaint() of whichever tab becomes
    selected (and the tab strip itself) any time selection changes is
    the standard fix for this class of Swing staleness."""

    def __init__(self, extender):
        self._extender = extender

    def stateChanged(self, event):
        tabs = self._extender._tabs
        tabs.revalidate()
        tabs.repaint()
        selected = tabs.getSelectedComponent()
        if selected is not None:
            selected.revalidate()
            selected.repaint()


class _ClearFilterMouseListener(MouseAdapter):
    """Click the yellow filter banner atop Detailed Results to clear an
    active category/result filter and go back to showing every row."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        self._extender._clear_filter()


class _ResultCategoryRowFilter(RowFilter):
    """Detailed Results' combined filter: an optional list of categories
    (a single category, or a whole OWASP-bucket rollup) AND an
    independent result-type ("PASS"/"FAIL"/"OTHER" grouping MANUAL+INFO+
    ERROR) AND an optional free-text search (ID/Category/Test/Evidence/
    URL, case-insensitive substring), all applied together.
    RowFilter.regexFilter() (used by the single-category filter this
    replaced) can't do multi-value-list matching or combine independent
    conditions like this, so this subclasses RowFilter directly instead
    - same Jython pattern as every other custom Swing class in this file
    (subclass the real Java class rather than lean on interface
    auto-coercion, which doesn't apply to abstract classes like
    RowFilter anyway)."""

    # Reported directly, with a screenshot: "search bar not working" -
    # typing "Result = FAIL" into the free-text search box searched for
    # that literal string across ID/Category/Test/Evidence/URL (never
    # Result), matched nothing, and looked broken - the box worked
    # exactly as built, it just didn't understand the "Column = value"
    # syntax typed into it (that syntax is what the yellow filter BANNER
    # displays when you click a KPI card/table row, which is a different,
    # already-working mechanism - see _update_filter_banner). Rather than
    # just explain that away, this teaches the search box to understand
    # it: a leading "field:value" or "field=value" token (field one of
    # id/category/test/severity/priority/result/evidence/url) routes to
    # THAT column only; anything else keeps the original multi-column
    # substring behaviour unchanged.
    _FIELD_COLUMNS = {
        "id": 0, "category": 1, "test": 2, "severity": 3,
        "priority": 4, "result": 5, "evidence": 6, "url": 7, "source": 8,
    }
    _FIELD_TOKEN_RE = re.compile(
        r'^(id|category|test|severity|priority|result|evidence|url|source)\s*[:=]\s*(.+)$')

    def __init__(self, categories, result, search_text=None):
        self._categories = set(categories) if categories else None
        self._result = result
        raw = (search_text or "").strip().lower()
        self._search_field_col = None
        self._search_text = raw
        m = self._FIELD_TOKEN_RE.match(raw)
        if m and m.group(2).strip():
            self._search_field_col = self._FIELD_COLUMNS[m.group(1)]
            self._search_text = m.group(2).strip()

    def include(self, entry):
        try:
            category = entry.getValue(1)  # RESULT_COLUMNS[1] = Category
            result = entry.getValue(5)    # RESULT_COLUMNS[5] = Result
        except Exception:
            return True
        if self._categories is not None and category not in self._categories:
            return False
        if self._result:
            if self._result == "OTHER":
                if result in ("PASS", "FAIL"):
                    return False
            elif result != self._result:
                return False
        if self._search_text:
            if self._search_field_col is not None:
                try:
                    value = entry.getValue(self._search_field_col)
                except Exception:
                    value = None
                haystack = str(value).lower() if value is not None else ""
                if self._search_text not in haystack:
                    return False
            else:
                haystack_parts = []
                for col in (0, 1, 2, 6, 7):  # ID, Category, Test, Evidence, URL
                    try:
                        value = entry.getValue(col)
                    except Exception:
                        value = None
                    if value is not None:
                        haystack_parts.append(str(value))
                haystack = " ".join(haystack_parts).lower()
                if self._search_text not in haystack:
                    return False
        return True


class _SearchDocumentListener(DocumentListener):
    """Live-filters Detailed Results as the search box's text changes -
    reported directly: "allow user to add manual search Input box".
    Subclasses javax.swing.event.DocumentListener directly (three
    methods, not a single-method interface Jython could auto-coerce a
    plain callable into) - same pattern as every other Java-interface
    listener in this file."""

    def __init__(self, extender):
        self._extender = extender

    def insertUpdate(self, event):
        self._extender._on_search_text_changed()

    def removeUpdate(self, event):
        self._extender._on_search_text_changed()

    def changedUpdate(self, event):
        self._extender._on_search_text_changed()


class ResultRowRenderer(DefaultTableCellRenderer):
    """Colors each results-table row's background by its Result column value
    (index 5), matching the PASS=green/FAIL=red/MANUAL=yellow/INFO=blue/
    ERROR=gray scheme already used in the .xlsx output, so the two views
    read the same way. Subclasses DefaultTableCellRenderer directly (the
    standard Jython pattern for a custom Swing renderer) rather than
    composing one, since Jython's automatic Python-callable-to-Java-
    interface coercion isn't guaranteed for a plain object exposing a
    same-named method - subclassing the real Java renderer class sidesteps
    that ambiguity entirely."""

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        comp.setFont(comp.getFont().deriveFont(Font.PLAIN))
        try:
            model_row = table.convertRowIndexToModel(row)
            result = table.getModel().getValueAt(model_row, 5)
            color = RESULT_COLORS.get(str(result))
            if color and not isSelected:
                comp.setBackground(color)
            elif not isSelected:
                comp.setBackground(Color.WHITE)
            # Reported directly: "add color codeing for severaity" -
            # Severity is column index 3 in RESULT_COLUMNS (see near the
            # top of this file). This keeps the row's existing
            # PASS/FAIL/etc background (set above) and additionally
            # bolds+colors just this column's TEXT by severity tier
            # (Critical -> dark red down to Low -> blue-gray), same
            # SEVERITY_ACCENT_COLORS used by the Summary tab's Failed
            # vulnerabilities table and the Checklist Reference tab, so
            # all three read as one consistent color system.
            if col == 3 and not isSelected:
                severity = table.getModel().getValueAt(model_row, 3)
                sev_color = SEVERITY_ACCENT_COLORS.get(str(severity) if severity is not None else "")
                if sev_color:
                    comp.setForeground(sev_color)
                    comp.setFont(comp.getFont().deriveFont(Font.BOLD))
            elif not isSelected:
                comp.setForeground(Color.BLACK)
        except Exception:
            pass
        return comp


class CategoryFailRenderer(DefaultTableCellRenderer):
    """Category/OWASP breakdown tables (Categories tab + Summary tab's
    Coverage table): bolds+reddens the Fail column (index 3) whenever a
    row has at least one FAIL, and bolds+greens the Pass column (index 2)
    whenever a row is fully clean (no fails, at least one pass) - a quick
    visual scan of what needs attention.

    Optionally also highlights the whole row (orange tint) when it
    matches the extender's currently-selected category/OWASP-bucket key -
    pass extender/keys_attr/selected_attr (attribute names read via
    getattr each render, since the parallel keys list and the selection
    both change after the renderer is installed) to enable this; pass
    None/None/None (as the Summary tab's coverage table does) to disable
    it and get plain color-coded columns only."""

    def __init__(self, extender=None, keys_attr=None, selected_attr=None):
        DefaultTableCellRenderer.__init__(self)
        self._extender = extender
        self._keys_attr = keys_attr
        self._selected_attr = selected_attr

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        try:
            model_row = table.convertRowIndexToModel(row)
            fail_count = int(table.getModel().getValueAt(model_row, 3) or 0)
            pass_count = int(table.getModel().getValueAt(model_row, 2) or 0)
            comp.setFont(comp.getFont().deriveFont(Font.PLAIN))
            if col == 3 and fail_count > 0:
                comp.setForeground(Color(0xA4, 0x26, 0x2C))
                comp.setFont(comp.getFont().deriveFont(Font.BOLD))
            elif col == 2 and pass_count > 0 and fail_count == 0:
                comp.setForeground(Color(0x1E, 0x7E, 0x34))
                comp.setFont(comp.getFont().deriveFont(Font.BOLD))
            elif not isSelected:
                comp.setForeground(Color.BLACK)

            is_selected_row = False
            if self._extender is not None and self._keys_attr and self._selected_attr:
                keys = getattr(self._extender, self._keys_attr, None)
                selected_key = getattr(self._extender, self._selected_attr, None)
                if keys and selected_key and selected_key != "ALL" and 0 <= model_row < len(keys):
                    is_selected_row = (keys[model_row] == selected_key)
            if not isSelected:
                comp.setBackground(Color(0xFD, 0xF0, 0xE5) if is_selected_row else Color.WHITE)
        except Exception:
            pass
        return comp


class _SeverityTextRenderer(DefaultTableCellRenderer):
    """Bolds+colors a single column's text by severity tier
    (Critical/High/Medium/Low/Informational, via SEVERITY_ACCENT_COLORS -
    see that dict's own comment for why "Information" is also mapped).
    Installed as a per-COLUMN renderer (table.getColumnModel().getColumn
    (idx).setCellRenderer(...)) rather than a table-wide default renderer,
    since the tables that use this (Checklist Reference, Summary's Failed
    vulnerabilities) don't otherwise need row-level coloring the way
    Detailed Results does (see ResultRowRenderer instead for that case).
    Reported directly: "add color codeing for severaity"."""

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        if not isSelected:
            comp.setBackground(Color.WHITE)
            color = SEVERITY_ACCENT_COLORS.get(str(value) if value is not None else "")
            if color:
                comp.setForeground(color)
                comp.setFont(comp.getFont().deriveFont(Font.BOLD))
            else:
                comp.setForeground(Color.BLACK)
                comp.setFont(comp.getFont().deriveFont(Font.PLAIN))
        return comp
