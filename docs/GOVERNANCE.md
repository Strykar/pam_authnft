# Governance

pam_authnft uses a single-maintainer model. This page states who
decides what, how contributions land, and what happens if the
maintainer disappears.

## Roles and decision making

The maintainer (Avinash H. Duduskar, [@Strykar](https://github.com/Strykar))
reviews and merges changes, triages issues and security reports, cuts
releases, and owns the CI and release infrastructure. All decisions
happen in public: proposals arrive as issues or pull requests, and the
reasoning for accepting or declining them is recorded there. There is
no private decision channel for project direction.

Contributors participate through pull requests and issues. A
contribution is judged on the invariants and test requirements in
[CONTRIBUTING.txt](CONTRIBUTING.txt); there is no inner circle whose
patches are held to a different standard.

Security reports follow [SECURITY.md](../SECURITY.md) and the internal
runbook in [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md), not this page.

## Access continuity

The bus factor is currently 1 and this section exists to blunt it:

- **Named successor.** [@pointshoonya](https://github.com/pointshoonya)
  has agreed to assume stewardship of the repository and its releases
  if the maintainer is unresponsive for 60 days on a pending security
  report, or 6 months otherwise.
- **Nothing is trapped.** Every gate, test, release step and document
  lives in this repository; there is no private build machine, secret
  runbook or external service an inheritor would lack. The two
  repository secrets (Coverity, Codecov tokens) are re-issuable by any
  owner of the respective accounts and gate nothing.
- **The licence guarantees the exit.** GPL-2.0-or-later means the
  project can always be forked and continued by anyone, with or
  without the successor arrangement.

## Contribution terms

Contributions are accepted under the project licence
(GPL-2.0-or-later) with a Developer Certificate of Origin sign-off;
see the DCO section of [CONTRIBUTING.txt](CONTRIBUTING.txt).
