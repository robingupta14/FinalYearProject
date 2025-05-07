# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
cpp_lang = get_language('cpp')
parser = get_parser('cpp')

# 2) Macro Expansion and Library removal

def remove_includes(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    cleaned_code = re.sub(r'^\s*#\s*include\s+[<"].*[>"].*$', '', code_str, flags=re.MULTILINE)
    return cleaned_code.encode('utf-8')

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
def collect_declared_identifiers(node, code_bytes, declared_ids):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent

    if node.type == "identifier":
        if parent and parent.type in ("init_declarator", "parameter_declaration", "enumerator"):
            declared_ids.add(node_text)

        elif parent and parent.type == "function_declarator" and parent.child_by_field_name("declarator") == node:
            declared_ids.add(node_text)

        elif parent and parent.type in ("class_specifier", "struct_specifier"):
            declared_ids.add(node_text)

    elif node.type == "type_identifier":
        if parent and parent.type in ("class_specifier", "struct_specifier", "enum_specifier"):
            declared_ids.add(node_text)
    
    elif node.type == "namespace_identifier":
        if parent.type in ("namespace_definition"):
            declared_ids.add(node_text)
    for child in node.children:
        collect_declared_identifiers(child, code_bytes, declared_ids)

def rename_identifiers(node, code_bytes, declared_ids, rename_map):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent

    if node_text in declared_ids and node_text not in rename_map:
        print(node.type)
        if node.type == "declaration_list" or node.type == "namespace_identifier":
            if (parent.type == "namespace_definition"):
                rename_map[node_text] = f"ns_{len(rename_map)}"
        if node.type == "identifier":
            is_function_name = (
                parent and parent.type == "function_declarator" and
                parent.child_by_field_name("declarator") == node
            )
            is_class_name = parent and parent.type == "class_specifier"
            if is_function_name:
                rename_map[node_text] = f"fn_{len(rename_map)}"
            elif is_class_name:
                rename_map[node_text] = f"class_{len(rename_map)}"
            elif parent and parent.type == "enumerator":
                rename_map[node_text] = f"enum_{len(rename_map)}"
            else:
                rename_map[node_text] = f"var_{len(rename_map)}"

        elif node.type == "type_identifier":
            if parent and parent.type == "class_specifier":
                rename_map[node_text] = f"class_{len(rename_map)}"
            elif parent and parent.type == "enum_specifier":
                rename_map[node_text] = f"enumtype_{len(rename_map)}"
            else:
                rename_map[node_text] = f"struct_{len(rename_map)}"

    for child in node.children:
        rename_identifiers(child, code_bytes, declared_ids, rename_map)

def replace_identifiers(code_bytes, rename_map):
    code_str = code_bytes.decode('utf-8', errors='replace')
    for old_name, new_name in rename_map.items():
        code_str = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, code_str)
    return code_str.encode('utf-8')

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
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace').strip().replace('\n', '\\n')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text}'")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)

def preprocess_cpp(code):
    importless_code = remove_includes(code)
    expanded_code = expand_and_remove_macros(importless_code)
    cleaned_code = remove_comments(expanded_code)
    folded_code = fold_constants(cleaned_code)
    tree = parser.parse(folded_code)

    declared_ids = set()
    collect_declared_identifiers(tree.root_node, folded_code, declared_ids)
    # print(f"declared ids: {declared_ids}")
    rename_map = {}
    rename_identifiers(tree.root_node, folded_code, declared_ids, rename_map)
    # print(f"rename map: {rename_map}")
    processed_code = replace_identifiers(folded_code, rename_map)

    # pretty_print_node(tree.root_node, processed_code)

    return processed_code.decode('utf-8')


code = b"""
# define VALUE 42
# include <iostream>

class Hehe {

};

enum Stuffs {
 E, B, C
};

// hello world ewfdwe
namespace trolladwqadwqdqwdwqdqmos {
    void func(int x, int y) {
        std::cout << "tr" << std::endl;
    }
}

int main() {
    trolladwqadwqdqwdwqdqmos::func();
    Hehe two;
    int x = VALUE * VALUE;
    std::cout << x << std::endl;
    return 0;
}
"""

print(preprocess_cpp(code))