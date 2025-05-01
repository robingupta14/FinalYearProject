# Extraneous whitespace, formatting -> Not stored in tree sitter ASTs
    # comments, documentation, -> delete comment nodes; c doesn't have docstrings.
    # Can't safely remove prints and exception strings in C because they can cause segfaults -> that is a CWE.
  
# Renaming 
    # Traverse the AST and use a symbol table for scope management

# Expansion is the process of replacing referential definitions with the actual value.
    # Clang -E for macro expansion

# Constant folding - Use own symbol table while traversing AST. 
# Constant expressions - 2 + 4 -> 6, have your own evaluator.

# Loop canonicalization - if the software exists for it already.

# Tools That Help
# Task	Tool / Approach
# AST parsing	Tree-sitter
# Macro expansion	clang -E for C/C++, or Roslyn for C#
# Identifier renaming	Tree-sitter AST + symbol table
# Constant folding	Custom AST evaluation
# Loop canonicalization	Custom AST transformation