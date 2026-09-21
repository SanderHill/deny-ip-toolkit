# Releasing

This checklist is for project maintainers.

1. Confirm the working tree is clean and all tests pass.
2. Review open security reports and release-blocking issues.
3. Update `__version__` in `deny_ip_toolkit.py`.
4. Move relevant entries from `Unreleased` into a dated changelog section.
5. Commit the release preparation as `Prepare vX.Y.Z`.
6. Create an annotated `vX.Y.Z` tag from the release commit.
7. Create a GitHub release whose notes match the changelog.
8. Verify the release archive contains no blocklist data, credentials, private
   URLs, or generated output.
9. Start the next `Unreleased` section when development resumes.

Version numbers follow [Semantic Versioning](https://semver.org/).
