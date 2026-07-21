# Security Policy

## Supported scope

Security fixes are applied to the builder on the default branch. Frida 17.16.3
is the current compatibility and verification target. Other upstream versions
are not considered supported until their source contracts, full build, and
rooted-device acceptance have been repeated.

Generated Frida binaries also include upstream and third-party code. A defect
that reproduces in an unmodified Frida build should be reported to the relevant
upstream project.

## Private reporting

Do not open a public issue for a vulnerability. Use GitHub's private
[security advisory form](https://github.com/TheQmaks/phantom-frida/security/advisories/new).

Include:

- the affected builder commit and Frida version;
- the architecture and artifact source;
- the minimal reproduction and security impact;
- sanitized logs or a proof of concept;
- whether the behavior also occurs in upstream Frida.

Do not include credentials, private application data, or persistent access to a
device. A maintainer will acknowledge the report through the advisory and
coordinate disclosure after the impact and fix have been verified.

## Testing authorization

Only run the builder and Android harness on software and devices you own or are
explicitly authorized to assess.
