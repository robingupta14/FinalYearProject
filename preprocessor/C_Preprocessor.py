# GOAL: Carry out AST Generation using the generated Parser from Tree-sitter:
from tree_sitter import Language, Parser
import subprocess
import tempfile
import re
import os
from collections import defaultdict

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
C_LANGUAGE = Language('/mnt/c/Users/robpi/Desktop/FYP/FinalYearProject/parsers/c-parser.so', 'c')
parser = Parser()
parser.set_language(C_LANGUAGE)

# 2) Macro Expansion and Library removal

def remove_includes(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    cleaned_code = re.sub(r'^\s*#\s*include\s+[<"].*[>"].*$', '', code_str, flags=re.MULTILINE)
    return cleaned_code.encode('utf-8')

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

# 3)  Comment removal. C doesn't have docstrings.
# Can't safely remove prints and exception strings in C because they can cause segfaults -> that is a CWE.
def remove_comments(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'/\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

def label_code(code_bytes, tree):
    declared_ids = defaultdict(list)
    rename_map = {}
    scope_stack = []

    def enter_scope():
        scope_stack.append(set())
    def exit_scope():
        scope_stack.pop()
    def current_scope_level():
        return len(scope_stack)
    def record_declaration(name, kind):
        declared_ids[name].append((kind, current_scope_level()))
        scope_stack[-1].add(name)

    def collect_and_label(node):
        node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
        parent = node.parent

        if node.type == 'compound_statement':
            enter_scope()

        if node.type == "identifier":
            if parent:
                if parent.type == "function_declarator" and parent.child_by_field_name("declarator") == node:
                    record_declaration(node_text, "func")
                elif parent.type == "enumerator":
                    record_declaration(node_text, "enum")
                elif parent.type in ("init_declarator", "parameter_declaration"):
                    record_declaration(node_text, "var")

        elif node.type == "type_identifier":
            if parent and parent.type == "struct_specifier":
                record_declaration(node_text, "struct")
            elif parent and parent.type == "enum_specifier":
                record_declaration(node_text, "enumtype")

        for child in node.children:
            collect_and_label(child)

        if node.type == 'compound_statement':
            exit_scope()

    enter_scope()
    collect_and_label(tree.root_node)
    exit_scope()

    for name, kind_levels in declared_ids.items():
        for idx, (kind, _) in enumerate(kind_levels):
            label = f"{kind}_{name}"
            key = (kind, name)
            if key not in rename_map:
                rename_map[key] = label

    return rename_map

def collect_declared_identifiers(node, code_bytes, declared_ids):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent

    if node.type == "identifier":
        if parent and parent.type in ("init_declarator", "parameter_declaration", "enumerator"):
            declared_ids.add(node_text)

        elif parent and parent.type == "function_declarator" and parent.child_by_field_name("declarator") == node:
            declared_ids.add(node_text)

        elif parent and parent.type == "enum_specifier":
            declared_ids.add(node_text)

    elif node.type == "type_identifier":
        if parent and parent.type in ("struct_specifier", "enum_specifier"):
            declared_ids.add(node_text)

    for child in node.children:
        collect_declared_identifiers(child, code_bytes, declared_ids)

def rename_identifiers(node, code_bytes, declared_ids, rename_map):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    if node_text in declared_ids and node_text not in rename_map:
        if node.type == "identifier":
            parent = node.parent
            if parent and parent.type == "function_declarator" and parent.child_by_field_name("declarator") == node:
                rename_map[node_text] = f"fn_{len(rename_map)}"
            elif parent and parent.type == "enumerator":
                rename_map[node_text] = f"enum_{len(rename_map)}"
            else:
                rename_map[node_text] = f"var_{len(rename_map)}"

        elif node.type == "type_identifier":
            parent = node.parent
            if parent and parent.type == "struct_specifier":
                rename_map[node_text] = f"struct_{len(rename_map)}"
            elif parent and parent.type == "enum_specifier":
                rename_map[node_text] = f"enumtype_{len(rename_map)}"

    for child in node.children:
        rename_identifiers(child, code_bytes, declared_ids, rename_map)

def replace_identifiers(code_bytes, rename_map, tree):
    result = []
    last_byte = 0

    def get_kind(node):
        parent = node.parent
        if node.type == "identifier":
            if parent:
                if parent.type == "function_declarator" and parent.child_by_field_name("declarator") == node:
                    return "func"
                elif parent.type == "enumerator":
                    return "enum"
                elif parent.type in ("init_declarator", "parameter_declaration"):
                    return "var"
        elif node.type == "type_identifier":
            if parent and parent.type == "struct_specifier":
                return "struct"
            elif parent and parent.type == "enum_specifier":
                return "enumtype"
        return None

    def visit(node):
        nonlocal last_byte

        for child in node.children:
            visit(child)

        if node.type in ("identifier", "type_identifier"):
            kind = get_kind(node)
            if kind:
                original_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
                replacement = rename_map.get((kind, original_text))
                if replacement:
                    result.append(code_bytes[last_byte:node.start_byte])
                    result.append(replacement.encode('utf-8'))
                    last_byte = node.end_byte

    visit(tree.root_node)
    result.append(code_bytes[last_byte:])
    return b''.join(result)


# 5) Constant folding - 2 + 4 -> 6, have own evaluator.

def evaluate_expression(node, code_bytes):
    if node.type == 'parenthesized_expression':
        return evaluate_expression(node.children[1], code_bytes)

    if node.type == 'number_literal':
        try:
            return int(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
        except ValueError:
            return None

    if node.type == 'binary_expression':
        left = evaluate_expression(node.child_by_field_name('left'), code_bytes)
        right = evaluate_expression(node.child_by_field_name('right'), code_bytes)
        operator_node = node.child_by_field_name('operator')
        op = code_bytes[operator_node.start_byte:operator_node.end_byte].decode('utf-8')

        try:
            if left is not None and right is not None:
                if op == '+':
                    return left + right
                elif op == '-':
                    return left - right
                elif op == '*':
                    return left * right
                elif op == '/':
                    return left // right if right != 0 else None
                elif op == '%':
                    return left % right if right != 0 else None
                elif op == '<<':
                    return left << right
                elif op == '>>':
                    return left >> right
                elif op == '|':
                    return left | right
                elif op == '&':
                    return left & right
                elif op == '^':
                    return left ^ right
        except Exception:
            return None
    return None

def collect_constant_folds(node, code_bytes, replacements):
    value = evaluate_expression(node, code_bytes)
    if value is not None:
        replacements.append((node.start_byte, node.end_byte, str(value)))
        return

    for child in node.children:
        collect_constant_folds(child, code_bytes, replacements)

def apply_replacements(code_bytes, replacements):
    replacements = sorted(replacements, key=lambda x: x[0])
    new_code = bytearray()
    last_index = 0

    for start, end, result in replacements:
        new_code.extend(code_bytes[last_index:start])
        new_code.extend(result.encode('utf-8'))
        last_index = end

    new_code.extend(code_bytes[last_index:])
    return bytes(new_code)

def fold_constants(code: bytes):
    tree = parser.parse(code)
    root = tree.root_node

    replacements = []
    collect_constant_folds(root, code, replacements)

    folded_code = apply_replacements(code, replacements)
    return folded_code

# 6) Actual preprocessing functions
def pretty_print_node(node, code_bytes, indent=0):
    indent_str = '  ' * indent
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text.strip()}'")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)

def preprocess_c(code):
    importless_code = remove_includes(code)
    expanded_code = expand_and_remove_macros(importless_code)
    cleaned_code = remove_comments(expanded_code)
    folded_code = fold_constants(cleaned_code)

    tree = parser.parse(folded_code)
    rename_map = label_code(folded_code, tree)
    labeled_code = replace_identifiers(folded_code, rename_map, tree)
    labeled_tree = parser.parse(labeled_code)

    declared_ids = set()
    collect_declared_identifiers(labeled_tree.root_node, labeled_code, declared_ids)
    rename_identifiers(labeled_tree.root_node, labeled_code, declared_ids, rename_map)
    # print(rename_map)
    obfuscated_code = replace_identifiers(labeled_code, rename_map, labeled_tree)

    return obfuscated_code.decode('utf-8')


# NOTE THAT WE DON'T RESOLVE VARIABLE ASSIGNMENTS TO OTHER RESOLVED VARIABLES IN OUR C CODE IN THE CONSTANT
# FOLDING PHASE!! THIS IS BECAUSE VARIABLES MAY BE FREED OR NOT IN HEAP MEMORY - THIS COULD LEAD TO CWE'S THAT
# WE OBSCURE BY EXPANDING. SINCE WE ARE NOT TRACKING FREEING AND ALLOCATING LOGIC AND ETC!

code = b"""
# define VALUE 42
// bury it i wont let
/* you bury it i wont let you smother it i wont let you murder it our time is running out */
include <stdlib.h>
struct Hello {};

enum Stuffs {
 E, B, C
};

int x() {
    int x = (VALUE + VALUE) * VALUE;
    printf("%d", x);
    if (x > 0) {
       int x = 19;
       int y = x + x;
    }

    return x
}
"""

print(preprocess_c(code))