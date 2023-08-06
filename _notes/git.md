---
title: Git notes
---

- [1. Settings](#1-settings)
  - [1.1. Global](#11-global)
  - [1.2. Repository](#12-repository)
- [2. Branches](#2-branches)
- [3. Commits](#3-commits)
- [4. Remote repositories](#4-remote-repositories)

## 1. Settings

### 1.1. Global

```bash
git config --global user.name <username>
git config --global user.email <email>
```

### 1.2. Repository

```bash
git config user.name <username>     # Set new user's name
git config user.email <email>       # Set new user's email
```

## 2. Branches

```bash
git checkout -b <branch-name>       # Create new branch and switch to it
```

## 3. Commits

```bash
git log                             # Show commits
git show <commit-id>                # Show commit changes
```

## 4. Remote repositories

```bash
git remote -v                       # List all remote repos
git remote add <name> <repo-url>    # Add new remote repo
git remote set-url <name> <new-url> # Change repo's URL
```
