# Contributing to @abgov/verifiable-credentials

## Commit message convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

**All PR titles must follow the conventional commit format**, since we use squash-merge and the PR title becomes the commit message on `main`. Individual commit messages within a PR are not enforced.

### Format

```
type(scope): short description
```

`scope` is optional.

### Types

| Type       | When to use                                     | Release impact |
|------------|-------------------------------------------------|----------------|
| `fix`      | Bug fix                                         | patch bump     |
| `feat`     | New feature                                     | minor bump     |
| `feat!`    | Breaking change                                 | major bump     |
| `chore`    | Maintenance, dependency updates, tooling        | no release     |
| `docs`     | Documentation only                              | no release     |
| `refactor` | Code restructure without behaviour change       | no release     |
| `test`     | Adding or updating tests                        | no release     |
| `style`    | Formatting, whitespace                          | no release     |
| `perf`     | Performance improvement                         | patch bump     |
| `ci`       | CI/CD workflow changes                          | no release     |
| `build`    | Build system or external dependency changes     | no release     |

### Breaking changes

Add `!` after the type, or include a `BREAKING CHANGE:` footer:

```
feat!: remove deprecated resolveAlbertaWallet signature

BREAKING CHANGE: the second argument has been removed; callers must update.
```

### Examples

```
fix: handle empty issuer metadata gracefully
feat(sdjwt): add support for array disclosures
chore: upgrade jose to v6
docs: update README install instructions
refactor(openid-federation): extract discovery cache logic
```

## Release process

Releases are managed automatically by [release-please](https://github.com/googleapis/release-please):

1. Merge one or more PRs with conventional commit titles to `main`.
2. release-please opens (or updates) a **Release PR** accumulating all changes and computing the next version.
3. Review the Release PR — it shows the `CHANGELOG.md` diff and proposed version.
4. **Merge the Release PR** when you're ready to cut a release.
5. release-please creates the git tag and GitHub Release automatically.
6. The publish workflow fires and publishes to npm.

> **Tip:** leave the Release PR open to batch multiple changes into one release.

## Local setup

```bash
# Activate the commit message template
git config commit.template .gitmessage

# Install dependencies
corepack enable
yarn install
```
