#!/bin/bash

mkdir $1

cd $1

mkdir recon
mkdir exploit
mkdir report
mkdir dumps

echo "# Report: $1" > ./report/$1.md 
echo "## Executive Summary" >> ./report/$1.md
echo "## Reconaissance" >> ./report/$1.md
echo "## Foothold" >> ./report/$1.md
echo "## Privilege Escalation" >> ./report/$1.md
echo "## Appendix" >> ./report/$1.md
echo "### Proofs" >> ./report/$1.md
echo "### Credentials" >> ./report/$1.md
