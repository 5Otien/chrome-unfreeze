#!/bin/sh
# Builds dist/chrome-unfreeze, a single executable file (a Python zipapp).
set -e
cd "$(dirname "$0")"
rm -rf build dist
mkdir -p build/app dist
cp -r chrome_unfreeze build/app/
find build/app -name __pycache__ -prune -exec rm -rf {} +
printf 'import sys\nfrom chrome_unfreeze.cli import main\nsys.exit(main())\n' > build/app/__main__.py
python3 -m zipapp build/app -p "/usr/bin/env python3" -c -o dist/chrome-unfreeze
rm -rf build
echo "dist/chrome-unfreeze"
