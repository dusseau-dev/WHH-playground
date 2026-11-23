<div align="center">

<img src="https://raw.githubusercontent.com/KeygraphHQ/dora/main/assets/github-banner.png" alt="Dora — AI Pentester for Web Applications and APIs" width="100%">

# Dora — AI Pentester by Keygraph

Dora runs source-assisted or URL-only dynamic security assessments for web applications and APIs. <br />
Use the CLI directly or open the bundled localhost operator UI with `npx @keygraph/dora ui`.

---

<a href="https://github.com/KeygraphHQ/dora/discussions/categories/announcements"><img src="https://raw.githubusercontent.com/KeygraphHQ/dora/main/assets/announcements.png" height="40" alt="Announcements"></a>
<a href="https://discord.gg/9ZqQPuhJB7"><img src="https://raw.githubusercontent.com/KeygraphHQ/dora/main/assets/discord.png" height="40" alt="Join Discord"></a>
<a href="https://keygraph.io/"><img src="https://raw.githubusercontent.com/KeygraphHQ/dora/main/assets/Keygraph_Button.png" height="40" alt="Visit Keygraph.io"></a>
<a href="https://www.linkedin.com/company/keygraph/"><img src="https://raw.githubusercontent.com/KeygraphHQ/dora/main/assets/linkedin.png" height="40" alt="Follow Us on Linkedin"></a>

---

**Full README and usage guide**  
[https://github.com/KeygraphHQ/dora#readme](https://github.com/KeygraphHQ/dora#readme)

```bash
# Configure Anthropic, OpenAI, xAI, AWS Bedrock, or a compatible gateway.
# The wizard masks credentials and stores its config with mode 0600.
npx @keygraph/dora setup

# URL-only dynamic assessment
npx @keygraph/dora start --url https://your-app.example

# Source-assisted assessment
npx @keygraph/dora start --url https://your-app.example --repo /path/to/repository

# Profiles, run controls, findings, activity, and reports
npx @keygraph/dora ui
```

Direct configuration uses `DORA_AI_MODEL=<provider>:<model-id>` plus the selected provider's credential variable. Google Vertex AI is no longer supported; legacy Vertex configuration returns migration guidance to choose a supported provider or gateway. Keep credentials in the setup-managed config or a secret manager, never in `DORA_AI_MODEL`.

The local UI also supports the opt-in, staging-only `alerting-effectiveness` check. Configure an HTTPS no-op canary that
returns `204` plus an HTTPS Splunk management origin and least-privilege search token. Dora stores profile tokens in
the existing Keychain/session secret store and shows cohort detection rates, latency, gap, and scenario outcomes in Run
Detail without exposing request bodies or raw Splunk events.

</div>
