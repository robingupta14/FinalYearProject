# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
cpp_lang = get_language('c_sharp')
parser = get_parser('c_sharp')

# 2) Import removal
def remove_using(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    cleaned_code = re.sub(r'^\s*using\s+[\w\.]+;\s*$', '', code_str, flags=re.MULTILINE)
    return cleaned_code.encode('utf-8')

# 3)  Comment removal. C Sharp has docstrings.
def remove_comments(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'/\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

def remove_docstrings(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'///\s*<[^>]+>.*?(?=\n)', '', code_str, flags=re.DOTALL)
    code_str = re.sub(r'///.*', '', code_str)
    return code_str.encode('utf-8')

# 4) Exception line removal, Print removal.
def remove_exception_and_print_text(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'\bConsole\.WriteLine\s*\(.*?\)\s*;', '', code_str)
    code_str = re.sub(r'\bConsole\.Write\s*\(.*?\)\s*;', '', code_str)
    code_str = re.sub(r'(throw\s+new\s+\w+\s*\()\s*".*?"(\s*\))', r'\1\2', code_str)
    return code_str.encode('utf-8')

# 5) Renaming


# 7) Actual Preprocessing Functions
def pretty_print_node(node, code_bytes, indent=0):
    indent_str = '  ' * indent
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace').strip().replace('\n', '\\n')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text}'")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)


def preprocess_csharp(code):
    importless_code = remove_using(code)
    commentless_code = remove_comments(importless_code)
    documentationless_code = remove_docstrings(commentless_code)
    cleaned_code = remove_exception_and_print_text(documentationless_code)
    # folded_code = fold_constants(cleaned_code)
    tree = parser.parse(cleaned_code)

    # declared_ids = set()
    # collect_declared_identifiers(tree.root_node, folded_code, declared_ids)
    # print(f"declared ids: {declared_ids}")
    # rename_map = {}
    # rename_identifiers(tree.root_node, folded_code, declared_ids, rename_map)
    # print(f"rename map: {rename_map}")
    # processed_code = replace_identifiers(folded_code, rename_map)

    pretty_print_node(tree.root_node, cleaned_code)

    return cleaned_code.decode('utf-8')

code = b"""
using System;

// ok ok
/* OK ? */

/// this function skibidi
public class HelloWorld
{
    public static void Main(string[] args)
    {
        Console.WriteLine ("popbop");
        return 42;
    }
}
"""

print(preprocess_csharp(code))