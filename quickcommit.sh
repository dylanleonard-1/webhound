#!/bin/bash

# Remove stale git lock
rm -f .git/index.lock

# Show status
git status

echo ""
echo "Enter commit message:"
read msg

# Add real project files only
git add scanner/
git add .gitignore

# Commit + push
git commit -m "$msg"
git push
