---
title: Git notes
---

## Repository metadata

```bash
git config user.name <username>     # Set new user's name
git config user.email <email>       # Set new user's email
```

## Branches

```bash
git checkout -b <branch-name>       # Create new branch and switch to it
```

## Commits

```bash
git log                             # Show commits
git show <commit-id>                # Show commit changes
```

## Remote repositories

```bash
git remote -v                       # List all remote repos
git remote add <name> <repo-url>    # Add new remote repo
git remote set-url <name> <new-url> # Change repo's URL
```
