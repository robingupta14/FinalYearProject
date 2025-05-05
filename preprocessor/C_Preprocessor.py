# Renaming 
    # Traverse the AST and use a symbol table for scope management

# Expansion is the process of replacing referential definitions with the actual value.
    # Clang -E for macro expansion

# Constant folding - Use own symbol table while traversing AST. 
# Constant expressions - 2 + 4 -> 6, have your own evaluator.

# Loop canonicalization - if the software exists for it already.

# Task	Tool / Approach
# Macro expansion	clang -E for C/C++, or Roslyn for C#
# Identifier renaming	Tree-sitter AST + symbol table
# Constant folding	Custom AST evaluation



# 1) Carry out AST Generation  using the generated Parser from Tree-sitter:
# Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
    # comments, documentation, -> delete comment nodes; c doesn't have docstrings.
    # Can't safely remove prints and exception strings in C because they can cause segfaults -> that is a CWE.
from tree_sitter import Language, Parser
import re

C_LANGUAGE = Language('/mnt/c/Users/robpi/Desktop/FYP/FinalYearProject/parsers/c-parser.so', 'c')
parser = Parser()
parser.set_language(C_LANGUAGE)

def remove_c_comments(code_bytes):
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



code = b"""
int main() {
    int x = 42;
    return x;
}
"""

code2 = b"""
// bury it i wont let
/* you bury it
   i wont let you
*/
/* smother it 
   i wont let you 
   murder it
   our time is running out */
int main() {
    int x = 42;
    return x;
}
"""

# tree = parser.parse(code)
# pretty_print_node(tree.root_node, code)

cleaned_code_str = remove_c_comments(code2)
tree = parser.parse(cleaned_code_str)
pretty_print_node(tree.root_node, cleaned_code_str)