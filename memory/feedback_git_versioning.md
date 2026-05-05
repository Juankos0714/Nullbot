---
name: Git versioning is user-managed
description: Never run git commands (commit, branch, push, checkout, etc.) — the user handles all version control
type: feedback
---

Never create commits, branches, pushes, or any other git operations.

**Why:** The user explicitly manages version control themselves and does not want Claude touching the git history at all.

**How to apply:** Skip any git step in a workflow. If a task naturally ends with "commit the changes", stop before that step and tell the user what files were changed instead.
