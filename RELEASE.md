# Release Strategy

## Overview

**stooge** uses a two-branch release strategy:
- **`main`** - Active development branch with latest features
- **`release`** - Stable release branch for production use

Docker Hub automatically builds images from the `release` branch, ensuring users get tested, stable versions.

## Branch Strategy

```mermaid
gitGraph
    commit id: "Initial commit"
    branch release
    checkout main
    commit id: "Feature A"
    commit id: "Feature B"
    commit id: "Feature C"
    checkout release
    merge main tag: "v1.0.0"
    checkout main
    commit id: "Feature D"
    commit id: "Bug fix"
    commit id: "Feature E"
    checkout release
    merge main tag: "v1.1.0"
    checkout main
    commit id: "Feature F"
```

## Workflow

### Daily Development (main branch)

1. **Develop features** on `main` branch
2. **Test thoroughly** with `make test` and `make run`
3. **Commit frequently** with descriptive messages
4. **Push to main** when features are complete

### Creating a Release (release branch)

When `main` is stable and ready for release:

1. **Run release target**:
   ```bash
   make release
   ```

2. **What happens**:
   - Switches to `release` branch
   - Rebases `release` onto `main` (brings in all new commits)
   - Force-pushes to GitHub (with lease protection)
   - Switches back to `main`
   - Docker Hub automatically rebuilds image

3. **Docker Hub builds**:
   - Detects push to `release` branch
   - Builds fresh Docker image as `deanturpin/stooge:latest`
   - Stable release available to users

   Note: `main` branch also auto-builds as `deanturpin/stooge:devel` for developers

## Release Cadence

- **Development**: Continuous on `main`
- **Releases**: As needed when features are stable
- **Hotfixes**: Can be applied directly to `release`, then merged back to `main`

## Docker Hub Integration

Current configuration:
- **Source repository**: `github.com/deanturpin/stooge`
- **Build rules**:
  - `release` branch → `latest` tag (stable releases)
  - `main` branch → `devel` tag (development builds)
  - Git tags → Version-specific tags (optional)

## Version Tagging

After running `make release`, optionally tag the release:

```bash
git switch release
git tag -a v1.0.0 -m "Release version 1.0.0 - Auto-refresh TUI with protocol colours"
git push origin v1.0.0
git switch main
```

Docker Hub will automatically build tagged versions.

## Rollback Strategy

If a release has issues:

1. **Identify last good commit** on `release` branch
2. **Reset release branch**:
   ```bash
   git switch release
   git reset --hard <last-good-commit>
   git push --force-with-lease
   git switch main
   ```

3. **Docker Hub rebuilds** from rolled-back state

## Docker Images

Two images are automatically built:

### `deanturpin/stooge:latest` (Stable)
- Built from `release` branch
- Recommended for production use
- Only updated via `make release`
- Thoroughly tested features

```bash
docker pull deanturpin/stooge:latest
docker run --rm -it -v $(PWD):/data deanturpin/stooge:latest /data/capture.pcapng
```

### `deanturpin/stooge:devel` (Development)
- Built from `main` branch
- Latest features and fixes
- May contain experimental code
- Automatic builds on every push to main

```bash
docker pull deanturpin/stooge:devel
docker run --rm -it -v $(PWD):/data deanturpin/stooge:devel /data/capture.pcapng
```

## Benefits

✅ **Stable releases** - Users get tested code from `release`
✅ **Development preview** - Try latest features with `devel` tag
✅ **Rapid development** - No restrictions on `main` branch
✅ **Clean history** - Rebase keeps linear history
✅ **Automated builds** - Docker Hub handles deployment
✅ **Easy rollback** - Force-push previous state if needed

## Best Practices

1. **Test before release** - Ensure `main` is stable
2. **Use descriptive commits** - Clear history on `release`
3. **Tag versions** - Mark significant releases
4. **Communicate changes** - Update CHANGELOG.md
5. **Monitor Docker Hub** - Verify builds succeed

## Example Release Session

```bash
# Develop on main
git switch main
# ... make changes ...
git add -A
git commit -m "Add IPv6 packet parsing support"
git push

# When ready to release
make test        # Verify tests pass
make run         # Manual testing
make release     # Push to release branch

# Optionally tag
git switch release
git tag -a v1.2.0 -m "IPv6 support added"
git push origin v1.2.0
git switch main
```

## Troubleshooting

**Rebase conflicts during `make release`**:
```bash
git switch release
git rebase main
# Resolve conflicts manually
git rebase --continue
git push --force-with-lease
git switch main
```

**Docker Hub build failed**:
- Check GitHub Actions/Docker Hub logs
- Verify Dockerfile builds locally: `make build-clean`
- Fix issues on `main`, then re-run `make release`

## See Also

- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines
- [Docker Hub](https://hub.docker.com/r/deanturpin/stooge) - Image repository
