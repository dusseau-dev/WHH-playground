<div align="center">

<img src="https://raw.githubusercontent.com/KeygraphHQ/shannon/main/assets/github-banner.png" alt="Shannon — AI Pentester for Web Applications and APIs" width="100%">

# Shannon — AI Pentester by Keygraph

Shannon runs source-assisted or URL-only dynamic security assessments for web applications and APIs. <br />
Use the CLI directly or open the bundled localhost operator UI with `npx @keygraph/shannon ui`.

---

<a href="https://github.com/KeygraphHQ/shannon/discussions/categories/announcements"><img src="https://raw.githubusercontent.com/KeygraphHQ/shannon/main/assets/announcements.png" height="40" alt="Announcements"></a>
<a href="https://discord.gg/9ZqQPuhJB7"><img src="https://raw.githubusercontent.com/KeygraphHQ/shannon/main/assets/discord.png" height="40" alt="Join Discord"></a>
<a href="https://keygraph.io/"><img src="https://raw.githubusercontent.com/KeygraphHQ/shannon/main/assets/Keygraph_Button.png" height="40" alt="Visit Keygraph.io"></a>
<a href="https://www.linkedin.com/company/keygraph/"><img src="https://raw.githubusercontent.com/KeygraphHQ/shannon/main/assets/linkedin.png" height="40" alt="Follow Us on Linkedin"></a>

---

**Full README and usage guide**  
[https://github.com/KeygraphHQ/shannon#readme](https://github.com/KeygraphHQ/shannon#readme)

```bash
# Configure Anthropic, OpenAI, xAI, AWS Bedrock, or a compatible gateway.
# The wizard masks credentials and stores its config with mode 0600.
npx @keygraph/shannon setup

# URL-only dynamic assessment
npx @keygraph/shannon start --url https://your-app.example

# Source-assisted assessment
npx @keygraph/shannon start --url https://your-app.example --repo /path/to/repository

# Profiles, run controls, findings, activity, and reports
npx @keygraph/shannon ui
```

Direct configuration uses `SHANNON_AI_MODEL=<provider>:<model-id>` plus the selected provider's credential variable. Google Vertex AI is no longer supported; legacy Vertex configuration returns migration guidance to choose a supported provider or gateway. Keep credentials in the setup-managed config or a secret manager, never in `SHANNON_AI_MODEL`.

The local UI also supports the opt-in, staging-only `alerting-effectiveness` check. Configure an HTTPS no-op canary that
returns `204` plus an HTTPS Splunk management origin and least-privilege search token. Shannon stores profile tokens in
the existing Keychain/session secret store and shows cohort detection rates, latency, gap, and scenario outcomes in Run
Detail without exposing request bodies or raw Splunk events.

</div>
