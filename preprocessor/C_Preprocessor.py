# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
    # comments, documentation, -> delete comment nodes; c doesn't have docstrings.
    # Can't safely remove prints and exception strings in C because they can cause segfaults -> that is a CWE.

from tree_sitter import Language, Parser
import subprocess
import tempfile
import re
import os

C_LANGUAGE = Language('/mnt/c/Users/robpi/Desktop/FYP/FinalYearProject/parsers/c-parser.so', 'c')
parser = Parser()
parser.set_language(C_LANGUAGE)

# 2) Macro Expansion is the process of replacing referential definitions with the actual value.
def expand_and_remove_macros(code_bytes):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as tmp_file:
        tmp_file.write(code_bytes)
        tmp_file_path = tmp_file.name
    try:
        result = subprocess.run(
            ["clang", "-E", tmp_file_path],
            capture_output=True,
            text=True
        )
        expanded_code_str = result.stdout
        cleaned_code_str = re.sub(r'^\s*#.*$', '', expanded_code_str, flags=re.MULTILINE)
        return cleaned_code_str.encode('utf-8')

    finally:
        os.remove(tmp_file_path)

def remove_comments(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'/\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

def pretty_print_node(node, code_bytes, indent=0):
    indent_str = '  ' * indent
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text.strip()}'")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)

# 3) Renaming - Traverse the AST and use a symbol table for scope management
# 4) Constant folding - Use own symbol table while traversing AST. 
# 5) Constant expressions - 2 + 4 -> 6, have own evaluator.

def preprocess_c(code):
    expanded_code = expand_and_remove_macros(code)
    cleaned_code = remove_comments(expanded_code)
    tree = parser.parse(cleaned_code)
    pretty_print_node(tree.root_node, cleaned_code)

code = b"""
# define VALUE 42
// bury it i wont let
/* you bury it i wont let you smother it i wont let you murder it our time is running out */
int main() {
    int x = VALUE;
    return x;
}
"""
preprocess_c(code)