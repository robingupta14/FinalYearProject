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


# 3) Renaming - Traverse the AST and use a symbol table for scope management
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
                new_name = f"fn_{len(rename_map)}"
                rename_map[node_text] = new_name
            print(f"Renaming function: {node_text} -> {rename_map[node_text]}")
        else:
            if node_text not in rename_map:
                new_name = f"var_{len(rename_map)}"
                rename_map[node_text] = new_name
            print(f"Renaming variable: {node_text} -> {rename_map[node_text]}")

    for child in node.children:
        rename_identifiers(child, code_bytes, rename_map)

def replace_identifiers(code_bytes, rename_map):
    code_str = code_bytes.decode('utf-8', errors='replace')
    for old_name, new_name in rename_map.items():
        code_str = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, code_str)
    return code_str.encode('utf-8')

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

# 4) Constant folding - Use own symbol table while traversing AST. 
# 5) Constant expressions - 2 + 4 -> 6, have own evaluator.

def evaluate_binary_expression(node, code_bytes):
    if node.type != 'binary_expression':
        return None

    left = node.child_by_field_name('left')
    right = node.child_by_field_name('right')
    operator = node.child_by_field_name('operator')

    try:
        left_val = int(code_bytes[left.start_byte:left.end_byte].decode('utf-8'))
        right_val = int(code_bytes[right.start_byte:right.end_byte].decode('utf-8'))
        op = code_bytes[operator.start_byte:operator.end_byte].decode('utf-8')

        if op == '+':
            return str(left_val + right_val)
        elif op == '-':
            return str(left_val - right_val)
        elif op == '*':
            return str(left_val * right_val)
        elif op == '/':
            return str(left_val // right_val)
        elif op == '%':
            return str(left_val % right_val)
    except Exception:
        return None
    return None

def fold_constants(node, code_bytes, replacements):
    if node.type == 'binary_expression':
        result = evaluate_binary_expression(node, code_bytes)
        if result is not None:
            replacements.append((node.start_byte, node.end_byte, result))
    for child in node.children:
        fold_constants(child, code_bytes, replacements)

def apply_constant_folding(code_bytes, replacements):
    new_code = bytearray()
    last_index = 0
    for start, end, result in sorted(replacements, key=lambda x: x[0]):
        new_code.extend(code_bytes[last_index:start])
        new_code.extend(result.encode('utf-8'))
        last_index = end
    new_code.extend(code_bytes[last_index:])
    return bytes(new_code)

def preprocess_c(code):
    expanded_code = expand_and_remove_macros(code)
    cleaned_code = remove_comments(expanded_code)
    tree = parser.parse(cleaned_code)

    replacements = []
    fold_constants(tree.root_node, cleaned_code, replacements)
    folded_code = apply_constant_folding(cleaned_code, replacements)

    rename_map = {}
    tree = parser.parse(folded_code)
    rename_identifiers(tree.root_node, folded_code, rename_map)
    renamed_code = replace_identifiers(folded_code, rename_map)

    pretty_print_node(tree.root_node, folded_code)

    return renamed_code.decode('utf-8')

code = b"""
# define VALUE 42
// bury it i wont let
/* you bury it i wont let you smother it i wont let you murder it our time is running out */
int main() {
    int x = (VALUE + VALUE) * VALUE;
    return x;
}
"""
print(preprocess_c(code))