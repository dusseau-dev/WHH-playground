#let data = json(sys.inputs.data)
#let meta = data.report_meta
#let field(value, key, default: none) = value.at(key, default: default)
#let label(value) = value.replace("_", " ")

#set document(title: "Security Assessment Report", author: "Shannon")
#set page(
  paper: "us-letter",
  margin: (x: 0.8in, y: 0.75in),
  footer: context [
    #set text(size: 8pt, fill: rgb("#667085"))
    Shannon Security Assessment #h(1fr) #counter(page).display()
  ],
)
#set text(size: 9.5pt, fill: rgb("#182230"))
#set heading(numbering: "1.")
#show heading.where(level: 1): it => block(above: 20pt, below: 10pt)[
  #set text(size: 18pt, weight: "bold", fill: rgb("#101828"))
  #it.body
]
#show heading.where(level: 2): it => block(above: 14pt, below: 7pt)[
  #set text(size: 13pt, weight: "bold", fill: rgb("#344054"))
  #it.body
]
#show heading.where(level: 3): it => block(above: 10pt, below: 5pt)[
  #set text(size: 11pt, weight: "bold")
  #it.body
]

#align(center)[
  #v(0.8in)
  #text(size: 28pt, weight: "bold", fill: rgb("#175cd3"))[Security Assessment Report]
  #v(12pt)
  #text(size: 13pt)[#meta.target]
  #v(8pt)
  #text(fill: rgb("#667085"))[#meta.assessment_date]
]

#pagebreak()

= Executive Summary

#meta.executive_summary

- *Target:* #meta.target
- *Scope:* #meta.scope
- *Mode:* #(if meta.source_mode == "url-only" { "URL-Only" } else { "Source-Assisted" })
- *Safe demonstration:* #(if meta.safe_demonstration { "enabled" } else { "disabled" })
- *Triage:* #(if data.triage_status == "validated" { "VALIDATED" } else { "UNVALIDATED — human review required" })

#if data.triage_status == "validated" [
  #block(fill: rgb("#ecfdf3"), stroke: rgb("#12b76a"), inset: 10pt, radius: 3pt, width: 100%)[
    *VALIDATED:* Confirmed findings were reconciled with complete, unambiguous triage verdicts.
  ]
] else [
  #block(fill: rgb("#fffaeb"), stroke: rgb("#f79009"), inset: 10pt, radius: 3pt, width: 100%)[
    *UNVALIDATED:* One or more findings require human review. SARIF was not generated for this report.
  ]
]

= Coverage

#if meta.source_mode == "url-only" [
  Assessment was limited to the live target. Source code and repository code locations were not assessed.
] else [
  Source code and the live target were available. Code locations were joined from exact vulnerability-queue finding IDs.
]

#if data.not_assessed.len() > 0 [
  == Not Assessed

  Absence of findings in these incomplete classes is not a clean result:

  #for item in data.not_assessed [
    - #label(item)
  ]
]

= Confirmed Findings

#if data.findings.len() == 0 [
  _No findings passed triage validation._
] else [
  #for finding in data.findings [
    == #finding.finding_id: #finding.title

    - *Severity:* #finding.severity
    #if field(finding, "original_severity") != none [
      - *Original severity:* #finding.original_severity
    ]
    - *Category:* #finding.category
    - *OWASP:* #finding.owasp_category
    - *Vulnerable location:* #finding.vulnerable_location
    #if field(finding, "triage") != none [
      - *Triage verdict:* #field(finding.triage, "verdict", default: finding.triage.validation_state)
      #if field(finding.triage, "reason") != none [
        - *Triage rationale:* #finding.triage.reason
      ]
    ]

    === Overview

    #finding.overview

    === Impact

    #finding.impact

    === Remediation

    #finding.remediation
  ]
]

= Considered and Ruled Out

#if data.ruled_out.len() == 0 [
  _Nothing was ruled out._
] else [
  #for finding in data.ruled_out [
    == #finding.finding_id: #finding.title

    - *Category:* #finding.category
    - *Outcome:* #finding.verdict
    - *Reason:* #finding.reason
  ]
]
