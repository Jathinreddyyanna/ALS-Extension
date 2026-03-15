### Automated Tests

- **Backend URL heuristics**
  - Run `cd ai-browser-shield/backend && npm test`.
  - Confirms backend `urlScorer` gives low scores for trusted domains and higher scores for phishing-style URLs.

- **Extension URL and download heuristics**
  - Run `cd ai-browser-shield/extension && npm test`.
  - Verifies:
    - URL scoring differentiates safe vs suspicious links.
    - Download checker flags high-risk executables and binary downloads while keeping trusted archives safe.
  - Verifies popup store behavior for:
    - Deriving current score from heuristics when no history is present.
    - Marking report submissions as successful.

### Manual QA Scripts

- **Popups**
  - Open a test page that spawns multiple popups (e.g., ad-heavy or demo page).
  - Confirm:
    - Content `popupMonitor` blocks repeated popups and shows a clear banner.
    - Background `popup_abuse` events appear in threat history in the popup.
    - Badge and overlays (if triggered) are consistent with the popup risk.

- **Redirect chains**
  - Visit a URL that redirects through several intermediate domains.
  - Confirm:
    - A redirect warning is shown when thresholds are exceeded.
    - A single `redirect_chain` event is added to local history with high risk.
    - Tabs are only auto-closed when redirects clearly look like junk (nonsense hostnames / bad TLDs).

- **Downloads (zero-trust + heuristics)**
  - With backend configured, download a high-risk file type (e.g., `.exe`) from an untrusted test domain.
  - Confirm:
    - `downloads.onCreated` triggers backend `/downloads/intercept` and shows a `DOWNLOAD_WARNING` overlay.
    - Approve/cancel flows send the correct `APPROVE_DOWNLOAD` / `CANCEL_DOWNLOAD` messages and update backend state.
  - With backend disabled, download:
    - Executable from untrusted site → high-risk warning before save.
    - Executable from trusted site → medium-risk warning.
    - Archive from trusted site → allowed with note that post-download scan will run.
  - Verify file-scan notifications for malicious vs suspicious vs safe verdicts.

- **Reporting & history**
  - From the popup:
    - Trigger a risky URL so that `url_threat` is written to history.
    - Submit a user report from the "Report" tab.
  - Confirm:
    - Current tab’s score, explanation, and source are shown in the "Score" tab.
    - New events appear in "History" with consistent `eventType`, domain, URL, risk score/level, and explanation.
    - Submitted reports appear in the community feed when backend support is available.

