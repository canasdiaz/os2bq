#!/bin/bash

python3 -m venv ./virtual-env
source ./virtual-env/bin/activate
pip install -r requirements.txt -q
python clean_up_indices.py