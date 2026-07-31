#!/usr/bin/env bash
set -e

echo "Running Doctor check..."
./lab-runner doctor

echo "Listing Projects..."
./lab-runner projects list

echo "Smoke test passed!"
