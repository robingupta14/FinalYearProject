# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
cpp_lang = get_language('c_sharp')
parser = get_parser('c_sharp')

def pretty_print_node(node, code_bytes, indent=0):
    indent_str = '  ' * indent
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace').strip().replace('\n', '\\n')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text}'")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)

def preprocess_csharp(code):
    # importless_code = remove_using(code)
    # expanded_code = expand_and_remove_macros(importless_code)
    # cleaned_code = remove_comments(expanded_code)
    # folded_code = fold_constants(cleaned_code)
    tree = parser.parse(code)

    # declared_ids = set()
    # collect_declared_identifiers(tree.root_node, folded_code, declared_ids)
    # print(f"declared ids: {declared_ids}")
    # rename_map = {}
    # rename_identifiers(tree.root_node, folded_code, declared_ids, rename_map)
    # print(f"rename map: {rename_map}")
    # processed_code = replace_identifiers(folded_code, rename_map)

    pretty_print_node(tree.root_node, code)

    return code.decode('utf-8')

code = b"""
using System;

public class HelloWorld
{
    public static void Main(string[] args)
    {
        Console.WriteLine ("popbop");
    }
}
"""

print(preprocess_csharp(code))