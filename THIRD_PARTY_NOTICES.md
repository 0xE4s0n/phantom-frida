# Third-Party Notices

The repository's builder and test code is distributed under its MIT license.
That license does not replace the licenses of generated artifacts or downloaded
dependencies.

Build outputs contain Frida and its bundled dependencies. Frida's license text
for the supported upstream target is available in
[`COPYING` at tag 17.16.3](https://github.com/frida/frida/blob/17.16.3/COPYING).
Additional notices may be present in the exact upstream source tree and its
submodules; distributors are responsible for reviewing and preserving them.

Every published build should retain:

- `build-info.json`, including the builder, Frida, and frida-core commits;
- `SHA256SUMS` for the generated binary artifacts;
- the workflow run URL and build provenance attestation;
- applicable upstream license and notice files.

This notice describes repository provenance and is not legal advice.
