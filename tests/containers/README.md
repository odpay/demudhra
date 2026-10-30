# Run distro trust-store verification

The six container targets are Debian, Ubuntu, Fedora, Alpine, Arch Linux, and
openSUSE Tumbleweed. **NOT RUN in the build workspace.** Neither Docker nor Podman
is installed there. The GitHub Actions workflow defines the matrix but has not
been executed as part of the local build.

Run one target or the full matrix from the repository root.

```sh
sh tests/containers/run.sh --engine docker debian
sh tests/containers/run.sh --engine podman
```

The runner builds local images and runs them with networking disabled. It does
not mount the host filesystem or a container-engine socket. Image construction
uses the network to install distribution packages. No image is published.

Each image runs the fake-root CLI suite under dash and BusyBox sh where available.
It then plants the supplied default root in both a local anchor and a packaged
source. Debian, Ubuntu, and Alpine use `/usr/share/ca-certificates` with an enabled
`ca-certificates.conf` entry. Fedora uses `/usr/share/pki/ca-trust-source`, Arch
uses `/usr/share/ca-certificates/trust-source`, and SUSE uses
`/usr/share/pki/trust/anchors`. An unrelated AAA Certificate Services certificate
is a survivor in the local anchor directory. The default selection excludes it. The native
check runs the real updater, proves dry run leaves trust files unchanged, applies
the tool, and verifies the selected DER hash is absent from generated output.
It checks that AAA remains and that backups include an undo script. The harness restores the packaged source bytes to simulate a package reinstall.
A second native update must keep the selected certificate absent, using the
Debian configuration blacklist or the distribution distrust directory. A second apply must
succeed without another removal.

`native.py` refuses to run without the marker baked into the disposable image,
root inside that image, and the `/work` repository location. Do not run it directly
on a host. Only the disposable container is authorized for native apply.

The images use current distribution tags. These checks test behavior against the
packages available at image build time. They do not reproduce historic package
versions or verify macOS keychain behavior.

Every test command has a 45-second timeout. Image builds also stop after 45 seconds;
a timeout is an incomplete run and must be recorded as NOT RUN.
