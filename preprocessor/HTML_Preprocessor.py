# GOAL: Carry out AST Generation using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os
from collections import defaultdict

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
html = get_language('html')
parser = get_parser('html')

def preprocess_html(code):
    return code.decode('utf-8')


