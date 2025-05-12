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

# 2) Macro Expansion and Library removal


# 3)  Comment removal. C++ doesn't have docstrings.
# Can't safely remove prints and exception strings in C because they can cause segfaults -> that is a CWE.

# 4) Renaming - Traverse the AST and use a symbol table for scope management. C++ has classes, name spaces as well.


# 5) Constant folding - 2 + 4 -> 6, have own evaluator.

# 6) Actual preprocessing functions

def pretty_print_node(node, code_bytes, indent=0):
    indent_str = '  ' * indent
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace').strip().replace('\n', '\\n')
    print(f"{indent_str}{node.type} [{node.start_point} - {node.end_point}] → '{node_text}'")
    for child in node.children:
        pretty_print_node(child, code_bytes, indent + 1)

def preprocess_python(code):
    return code.decode('utf-8')

code = b"""
# define VALUE 42
# include <iostream>

class Hehe {

};

enum Stuffs {
 E, B, C
};

// hello world ewfdwe
namespace a {
    void func(int x, int y) {
        std::cout << "tr" << std::endl;
    }
}

int x(int x) {
    a::func(1, 2);
    Hehe two = NULL;
    int x = VALUE * VALUE;
    std::cout << x << std::endl;
    return x;
}
"""

print(preprocess_python(code))