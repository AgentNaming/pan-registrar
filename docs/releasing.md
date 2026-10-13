# Releasing

1. Set the version in `Cargo.toml` (and run `cargo build` so `Cargo.lock` agrees), add a section to
   `CHANGELOG.md`, and merge to `main` with CI green.
2. Tag the merge commit `v<version>` and push the tag:

   ```bash
   git tag -a v0.2.0 -m "pan-registrar 0.2.0" && git push origin v0.2.0
   ```

3. The release workflow checks that the tag matches `Cargo.toml`, builds the image, pushes
   `ghcr.io/<owner>/pan-registrar:<version>` (the owner is this repository's, in lower case), and writes the
   GitHub release from the changelog section.

There is no `latest` tag: a deployment names the version it runs. A published version is never rebuilt
or moved.
