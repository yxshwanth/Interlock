# Trademark policy

The Apache-2.0 licence covers the code. It does not grant rights to the name "Interlock" or to project logos and artwork (Apache-2.0 section 6). This policy says what you may do without asking. It is a plain-language policy, not legal advice, and no trademark registration is claimed here.

## You may, without permission

- State accurately that your product works with, integrates with, or is built on Interlock ("compatible with Interlock", "uses Interlock for MCP egress detection").
- Refer to the project by name in articles, talks, documentation and package metadata.
- Distribute unmodified builds of the project under the name Interlock, with the LICENSE and NOTICE files intact.
- Fork the code and keep working on it, under a different name (below).

## You may not, without written permission

- Use "Interlock" or the project artwork as the name of your own product, company, service or domain in a way that suggests it is the official project or endorsed by it.
- Distribute a modified build under the name Interlock, or in a way that implies it carries the project's detection claims (corpus numbers, evidence-chain guarantees) when your changes could affect them.
- Use the project's published detection and false-positive numbers for a modified build.

## Forks and modified builds

Rename your fork and say what you changed. Keep attribution to the original project in README and NOTICE, as Apache-2.0 requires. If your change touches detection, state that the upstream corpus numbers do not apply to it until you re-run `make fp-corpus` and `make cve-corpus` on your tree.

## Questions

Open an issue or follow [SECURITY.md](SECURITY.md) for private contact. The maintainer ([GOVERNANCE.md](GOVERNANCE.md)) decides edge cases.
