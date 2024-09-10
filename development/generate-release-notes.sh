#!/bin/sh

# Generate release notes based on the latest tag
LAST_TAG=$(git describe --tags --abbrev=0)
RELEASE_NOTES=$(git log ${LAST_TAG}..HEAD --oneline)

# Output release notes
echo "## Release Notes\n\n$RELEASE_NOTES"