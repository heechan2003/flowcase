# demo

Coming: a seeded generator for a synthetic network in Zeek's log format, with planted cases whose expected
outcome is known. `make demo` will run the whole pipeline on it: load, daily triage, IOC matching, then the
case reports. It checks every planted case against `expected.json`, and the outputs are kept in
`sample-output/`.
