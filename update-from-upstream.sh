#!/bin/bash
set -e

echo "Fetching latest changes from upstream..."
git fetch upstream

echo "Switching to main and merging upstream changes..."
git checkout main
git merge upstream/main
git push origin main

echo "Switching to your custom branch and rebasing onto updated main..."
git checkout rival-it-custom
git rebase main

echo "Pushing your updated custom branch..."
git push origin rival-it-custom

echo "Update complete!" 