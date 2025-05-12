# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os
from collections import defaultdict

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
cpp_lang = get_language('python')
parser = get_parser('python')

# 2) Main Guard and Library removal

def remove_imports(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    cleaned_code = re.sub(r'^\s*(import|from)\s+.+$', '', code_str, flags=re.MULTILINE)
    return cleaned_code.encode('utf-8')

def remove_main_guard(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    cleaned_code = re.sub(
        r'(?s)if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:\s*\n(?:\s+.+\n?)*',
        '',
        code_str
    )
    return cleaned_code.encode('utf-8')

# 3)  Comment removal. Python++ doesn't have docstrings.
def remove_comments_and_docstrings(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'#.*', '', code_str)
    code_str = re.sub(r'("""|\'\'\')(.*?)\1', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

# 4) Exception String and Print removal.
def remove_exception_and_print_text(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'print\s*\(\s*f?["\'].*?["\']\s*\)', 'print()', code_str)
    code_str = re.sub(r'(raise\s+\w+\s*)\(\s*f?["\'].*?["\']\s*\)', r'\1()', code_str)
    code_str = re.sub(r'(logger\.\w+\s*)\(\s*f?["\'].*?["\']\s*\)', r'\1()', code_str)

    return code_str.encode('utf-8')


# 5) Renaming - Traverse the AST and use a symbol table for scope management. C++ has classes, name spaces as well.


# 6) Constant folding - 2 + 4 -> 6, have own evaluator.

# one of the only reasons to love python... the eval function is a cheatcode!!!!!
def evaluate_expression(node, code_bytes):
    try:
        expr = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
        allowed = {'__builtins__': None}
        return eval(expr, allowed)
    except Exception:
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

# 7) Actual preprocessing functions

def pretty_print_node(node, code_bytes, indent=0):
    indent_str = '  ' * indent
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace').strip().replace('\n', '\\n')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text}'")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)

def preprocess_python(code):
    importless_code = remove_imports(code)
    commentless_code = remove_comments_and_docstrings(importless_code)
    main_guardless_code = remove_main_guard(commentless_code)
    cleaned_code = remove_exception_and_print_text(main_guardless_code)
    folded_code = fold_constants(cleaned_code)

    #tree = parser.parse(folded_code)
    #pretty_print_node(tree.root_node, folded_code)

    return folded_code.decode('utf-8')

code = b"""
import math as m
from os import path as p

def f(a, b=1+2):
 x = a + b
 def g(y): return y * x
 with open('f') as f2:
  for i, j in [(1,2)]:
   pass
 try:
  1/0
 except ZeroDivisionError as e:
  print(e)
 return [k for k in range(5)]

class C(Base):
 val = 10
 def method(self, z):
  self.x = z
  def inner():
   nonlocal z
   return lambda w: w + z
"""
print(preprocess_python(code).strip()) 