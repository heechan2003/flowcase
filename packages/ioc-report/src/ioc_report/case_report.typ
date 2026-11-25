// One case on about one page, laid out like the security project's hunt write-ups. Every string arrives
// as JSON and is shown as text, so nothing from a feed or a model is ever evaluated as markup.
#let d = json(bytes(sys.inputs.report))

#set document(title: d.title)
#set page(paper: "a4", margin: (x: 2.3cm, top: 2.1cm, bottom: 2cm))
#set text(font: "New Computer Modern", size: 10pt, lang: "en", region: "AU")
#set par(justify: true, leading: 0.56em, spacing: 0.8em)

// Domain names read as names, as in the hunt write-ups; addresses stay in the text's own face.
#show regex("\\b(?:[a-z0-9-]+\\.)+[a-z]{2,}\\b"): set text(font: "DejaVu Sans Mono", size: 0.84em)
#show link: set text(fill: rgb("#1a33c4"))
#show heading.where(level: 1): set text(size: 12pt, weight: "bold")
#show heading.where(level: 1): set block(above: 1.15em, below: 0.65em)
#show heading.where(level: 2): set text(size: 10pt, weight: "bold")
#show heading.where(level: 2): set block(above: 0.95em, below: 0.55em)

#block(below: 0.6em, text(size: 16pt, weight: "bold", d.title))
#block(below: 0.2em, text(size: 9pt, d.facts))

= Executive summary
#d.summary

= Background
*Threat:* #d.threat

*Host:* #d.host

= Analysis
== Contact with the listed address
#d.contact

== #d.why_heading
#d.why

#if d.after != "" [
  == What followed the contact
  #d.after
]

= Conclusion and next steps
#d.conclusion

#v(0.5em)
#text(size: 9pt)[
  #if d.sources.len() > 0 [
    *Sources:* #d.sources.map(source => link(source.url, source.label)).join("; "). ]
  *Limits:* #d.limits
]
