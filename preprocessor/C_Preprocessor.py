# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
    # comments, documentation, -> delete comment nodes; c doesn't have docstrings.
    # Can't safely remove prints and exception strings in C because they can cause segfaults -> that is a CWE.

from tree_sitter import Language, Parser
import subprocess
import tempfile
import re
import os
import operator

C_LANGUAGE = Language('/mnt/c/Users/robpi/Desktop/FYP/FinalYearProject/parsers/c-parser.so', 'c')
parser = Parser()
parser.set_language(C_LANGUAGE)
# Macro expansion using clang -E
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

# Remove comments
def remove_comments(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'/\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

# Fully evaluate constant expressions
BIN_OPS = {
    '+': operator.add,
    '-': operator.sub,
    '*': operator.mul,
    '/': operator.floordiv,
    '%': operator.mod
}

def extract_expression(node, code_bytes):
    """ Recursively reconstruct a constant expression from AST. """
    if node.type == 'parenthesized_expression':
        return f"({extract_expression(node.children[1], code_bytes)})"
    elif node.type == 'binary_expression':
        left = extract_expression(node.child_by_field_name("left"), code_bytes)
        right = extract_expression(node.child_by_field_name("right"), code_bytes)
        op = extract_expression(node.child_by_field_name("operator"), code_bytes)
        return f"({left} {op} {right})"
    elif node.type == 'number_literal':
        return code_bytes[node.start_byte:node.end_byte].decode()
    elif node.type == '+':
        return '+'
    elif node.type == '-':
        return '-'
    elif node.type == '*':
        return '*'
    elif node.type == '/':
        return '/'
    elif node.type == '%':
        return '%'
    else:
        return code_bytes[node.start_byte:node.end_byte].decode()

def fold_constants(node, code_bytes, replacements):
    if node.type == 'binary_expression':
        expr_str = extract_expression(node, code_bytes)
        try:
            value = str(eval(expr_str))
            replacements.append((node.start_byte, node.end_byte, value))
        except Exception:
            pass
    for child in node.children:
        fold_constants(child, code_bytes, replacements)

def apply_constant_folding(code_bytes, replacements):
    new_code = bytearray()
    last_index = 0
    for start, end, value in sorted(replacements, key=lambda x: x[0]):
        new_code.extend(code_bytes[last_index:start])
        new_code.extend(value.encode())
        last_index = end
    new_code.extend(code_bytes[last_index:])
    return bytes(new_code)

# Identifier renaming (unchanged from your version)
def rename_identifiers(node, code_bytes, rename_map):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    if node.type == "identifier":
        parent = node.parent
        is_function_name = (
            parent is not None and
            parent.type == "function_declarator" and
            parent.child_by_field_name("declarator") == node
        )
        if is_function_name:
            if node_text not in rename_map:
                rename_map[node_text] = f"fn_{len(rename_map)}"
        else:
            if node_text not in rename_map:
                rename_map[node_text] = f"var_{len(rename_map)}"
    for child in node.children:
        rename_identifiers(child, code_bytes, rename_map)

def replace_identifiers(code_bytes, rename_map):
    code_str = code_bytes.decode()
    for old_name, new_name in rename_map.items():
        code_str = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, code_str)
    return code_str.encode()

# Main pipeline
def preprocess_c(code):
    expanded = expand_and_remove_macros(code)
    no_comments = remove_comments(expanded)

    tree = parser.parse(no_comments)
    replacements = []
    fold_constants(tree.root_node, no_comments, replacements)
    folded = apply_constant_folding(no_comments, replacements)

    rename_map = {}
    tree = parser.parse(folded)
    rename_identifiers(tree.root_node, folded, rename_map)
    renamed = replace_identifiers(folded, rename_map)

    return renamed.decode()

# Test code
code = b"""
#define VALUE 42
int main() {
    int x = (VALUE + VALUE) * VALUE + 5;
    return x;
}
"""

print(preprocess_c(code))