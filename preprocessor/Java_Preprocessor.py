# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os
from collections import defaultdict

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
java_lang = get_language('java')
parser = get_parser('java') 

# 2) Import removal
def remove_using(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    cleaned_code = re.sub(r'^\s*import\s+[\w\.]+;\s*$', '', code_str, flags=re.MULTILINE)
    return cleaned_code.encode('utf-8')

# 3)  Comment removal.
def remove_comments(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'/\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

def remove_docstrings(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'/\*\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

# 4) Exception line removal, Print removal.
def remove_exception_and_print_text(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'\bSystem\.out\.\w+\s*\(.*?\);\s*', '', code_str)
    code_str = re.sub(r'\b\w+\.printStackTrace\s*\(\);\s*', '', code_str)
    code_str = re.sub(r'catch\s*\(\s*\w+\s+\w+\s*\)\s*\{\s*(System\.out\.\w+\s*\(.*?\);\s*)+\}', '', code_str, flags=re.DOTALL)

    return code_str.encode('utf-8')

# 5) Renaming

# 6) Constant folding - 2 + 4 -> 6, have own evaluator.
def evaluate_expression(node, code_bytes):
    if node.type == 'parenthesized_expression':
        return evaluate_expression(node.children[1], code_bytes)

    if node.type == 'integer_literal' or node.type == 'real_literal' or node.type == 'boolean_literal':
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


# 7) Actual Preprocessing Functions
def pretty_print_node(node, code_bytes, indent=0):
    indent_str = '  ' * indent
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace').strip().replace('\n', '\\n')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text}', {node.type}")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)

def preprocess_java(code):
    importless_code = remove_using(code)
    commentless_code = remove_comments(importless_code)
    documentationless_code = remove_docstrings(commentless_code)
    cleaned_code = remove_exception_and_print_text(documentationless_code)
    folded_code = fold_constants(cleaned_code)

    tree = parser.parse(folded_code)
    # rename_map = label_code(folded_code, tree)
    # labeled_code = replace_identifiers(folded_code, rename_map, tree)
    # labeled_tree = parser.parse(labeled_code)

    # declared_ids = set()
    # collect_declared_identifiers(labeled_tree.root_node, labeled_code, declared_ids)
    # rename_identifiers(labeled_tree.root_node, labeled_code, declared_ids, rename_map)
    # # print(rename_map)
    # obfuscated_code = replace_identifiers(labeled_code, rename_map, labeled_tree)
    #pretty_print_node(labeled_tree.root_node, obfuscated_code)
    return folded_code.decode('utf-8')



code = b"""
package example;
import java.util.HashMap;

public class Test {
    private int counter = 0;
    public static final String NAME = "Test";

    public static void main(String[] args) {
        int counter = 5; // Local shadowing
        System.out.println("Hello, World!");

        Test t = new Test();
        t.increment();

        try {
            int result = divide(10, 0);
        } catch (ArithmeticException e) {
            e.printStackTrace();
        }
    }

    public void increment() {
        counter++;
    }

    public static int divide(int a, int b) {
        if (b == 0) {
            throw new ArithmeticException("Cannot divide by zero");
        }
        return a / b;
    }

    // Loop test
    public void loopExample() {
        for (int i = 0; i < 3; i++) {
            System.out.println(i);
        }
    }

    /* Method with similar 
     parameter names */
    public void setValues(int counter, String NAME) {
        this.counter = counter;
        System.out.println(NAME);
    }
}
"""

print(preprocess_java(code))