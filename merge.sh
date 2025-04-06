#!/bin/bash
# This script merges the develop branch into the master branch and creates a tag with the provided version number.
# Usage: ./merge.sh <version_number>
# Example: ./merge.sh v1.0.0
# Check if a version number is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <version_number>"
  exit 1
fi
# Check if the version number is valid
if ! [[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: Version number must be in the format vX.X.X (e.g., v1.0.0)"
  exit 1
fi
# Check if the script is run from the root of the repository
if [ ! -d ".git" ]; then
  echo "Error: This script must be run from the root of the repository."
  exit 1
fi
git checkout master
git merge --no-ff develop
git tag -a $1
git push origin master
git push origin --tags
git checkout develop
