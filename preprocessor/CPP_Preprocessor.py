# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os


# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
cpp_lang = get_language('cpp')
parser = get_parser('cpp')

# 2) Macro Expansion.
def expand_and_remove_macros(code_bytes):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".cpp") as tmp_file:
        tmp_file.write(code_bytes)
        tmp_file_path = tmp_file.name
    try:
        result = subprocess.run(
            ["clang++", "-E", tmp_file_path],
            capture_output=True,
            text=True
        )
        expanded_code_str = result.stdout
        cleaned_code_str = re.sub(r'^\s*#.*$', '', expanded_code_str, flags=re.MULTILINE)
        return cleaned_code_str.encode('utf-8')
    finally:
        os.remove(tmp_file_path)

# 3)  Comment removal. C++ doesn't have docstrings.
# Can't safely remove prints and exception strings in C because they can cause segfaults -> that is a CWE.
def remove_comments(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'/\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')


# 4) Renaming - Traverse the AST and use a symbol table for scope management. C++ has classes, name spaces as well.
def rename_identifiers(node, code_bytes, rename_map):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent

    if node.type == "identifier":
        is_function_name = (
            parent is not None and (
                (parent.type == "function_declarator" and parent.child_by_field_name("declarator") == node) or
                (parent.type == "function_definition" and parent.child_by_field_name("declarator") == node)
            )
        )
        is_method_name = (
            parent is not None and parent.type == "field_declaration" and
            parent.child_by_field_name("declarator") == node
        )

        if is_function_name or is_method_name:
            if node_text not in rename_map:
                rename_map[node_text] = f"fn_{len(rename_map)}"
        else:
            if node_text not in rename_map:
                rename_map[node_text] = f"var_{len(rename_map)}"

    elif node.type == "type_identifier":
        is_struct_like = parent and parent.type in {
            "struct_specifier", "class_specifier", "enum_specifier"
        }
        if is_struct_like:
            if node_text not in rename_map:
                rename_map[node_text] = f"struct_{len(rename_map)}"

    for child in node.children:
        rename_identifiers(child, code_bytes, rename_map)

def replace_identifiers(code_bytes, rename_map):
    code_str = code_bytes.decode('utf-8', errors='replace')
    for old_name, new_name in rename_map.items():
        code_str = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, code_str)
    return code_str.encode('utf-8')

# 6) Actual preprocessing functions

def pretty_print_node(node, code_bytes, indent=0):
    indent_str = '  ' * indent
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace').strip().replace('\n', '\\n')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text}'")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)

def preprocess_cpp(code):
    expanded_code = expand_and_remove_macros(code)
    cleaned_code = remove_comments(expanded_code)
    # folded_code = fold_constants(cleaned_code)
    tree = parser.parse(cleaned_code)

    rename_map = {}
    tree = parser.parse(cleaned_code)
    rename_identifiers(tree.root_node, cleaned_code, rename_map)
    renamed_code = replace_identifiers(cleaned_code, rename_map)

    pretty_print_node(tree.root_node, renamed_code)

    return renamed_code.decode('utf-8')

code = b"""
# define VALUE 42
#include <iostream>
# hello world ewfdwe
int main() {
    int x = VALUE * VALUE;
    std::cout << x << std::endl;
    return 0;
}
"""

print(preprocess_cpp(code))
