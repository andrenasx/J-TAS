#!/bin/sh -l

# Working directory
cd /gaction

# Run the detector
python src/analyse.py "$1" "$2"

# Copy the results to the repository workspace
mv results.sarif /github/workspace
