# A09 AI-Assisted Detection Validation — Clarifications

The implementation request resolves the material product choices as follows.

1. **What is the deliverable?**
   - Options considered: defensive Shannon feature; detection-only benchmark; editorial report.
   - **Resolved:** defensive Shannon feature.

2. **Which surface is in v1?**
   - Options considered: web/browser lab; offline cross-platform telemetry; live cross-surface lab.
   - **Resolved:** the authorized staging web surface observed by WAF/SIEM. Endpoint, mobile, and email are excluded.

3. **Which detection platform is supported?**
   - Options considered: Splunk; Microsoft Sentinel; Elastic Security.
   - **Resolved:** Splunk only, with no generic adapter until a second provider is required.

4. **How are detections obtained?**
   - Options considered: generic alert import; webhook; vendor API.
   - **Resolved:** a least-privilege Splunk REST token and controlled searches over configured telemetry and alert indexes.

5. **What does the AI comparison measure?**
   - Options considered: fixed AI-versus-human corpus; detector coverage only; model safeguard behavior.
   - **Resolved:** five frozen, reviewed, matched fixtures per cohort. No runtime generation or adaptive bypass loop.

6. **How does a miss affect the run?**
   - Options considered: report only; configurable threshold; fail on any miss.
   - **Resolved:** configurable per-cohort threshold, defaulting to 100%. A miss fails this check but not the workflow.

7. **How is target safety enforced?**
   - Options considered: arbitrary staging routes; Shannon-hosted fixture site; dedicated target canary endpoint.
   - **Resolved:** a same-origin, relative, no-op canary path that returns HTTP 204; staging and authorization are required.

8. **How much customization is exposed?**
   - Options considered: arbitrary requests/SPL/corpora; constrained configuration; no configuration.
   - **Resolved:** operators configure origins, indexes, optional sourcetypes, wait, threshold, and path. Shannon owns all
     request fixtures and SPL construction.
