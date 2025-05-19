# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import re
from collections import defaultdict

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
php_lang = get_language('php')
parser = get_parser('php')

# 2) Remove imports
def remove_imports(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    alias_map = {}
    lines = code_str.split('\n')
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(('include', 'include_once', 'require', 'require_once')):
            continue
        elif stripped.startswith('namespace '):
            continue
        elif stripped.startswith('use '):
            parts = stripped[4:].rstrip(';').split()
            if 'as' in parts:
                original = parts[0]
                alias = parts[2]
                alias_map[alias] = original
            else:
                lib = parts[0]
                name = lib.split('\\')[-1]
                alias_map[name] = lib
        else:
            cleaned_lines.append(line)

    cleaned_code = '\n'.join(cleaned_lines)
    for alias, full_name in alias_map.items():cleaned_code = re.sub(
            rf'\b{re.escape(alias)}\b(?=\s*::)',
            full_name.replace('\\', r'\\'),  
            cleaned_code
        )

    return cleaned_code.encode('utf-8')

# 3)  Comment removal.
def remove_comments(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'#.*', '', code_str)
    code_str = re.sub(r'/\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

def remove_docblocks(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'/\*\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

# 4) Exception line removal, Print removal.
def remove_exception_and_print_text(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'\b(echo|print)\s+[^;]+;', '', code_str)
    code_str = re.sub(r'(throw\s+new\s+\w+)\s*\(\s*".*?"\s*\)', r'\1()', code_str)
    code_str = re.sub(r'(new\s+\w+)\s*\(\s*".*?"\s*\)', r'\1()', code_str)
    code_str = re.sub(r'(catch\s*\(\s*\w+\s+\$\w+\s*\))\s*\{.*?\}', r'\1 {}', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

# 5) Renaming
def label_code(code_bytes, tree):
    declared_ids = defaultdict(list)
    rename_map = {}
    scope_stack = []
    counters = defaultdict(int)

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

        if node.type in ('block', 'class_declaration', 'interface_declaration', 'enum_declaration', 'function_definition'):
            enter_scope()

        if node.type == 'name':
            if parent:
                if (parent.parent and parent.parent.type == "subscript_expression"): 
                    pass
                elif parent.type == 'function_call_expression' or parent.type == "method_call_expression" or parent.type == "scoped_call_expression":
                    pass
                elif parent.type == 'const_element':
                    record_declaration(node_text, "var")
                elif parent.type == 'formal_parameter':
                    record_declaration(node_text, "param")
                elif parent.type == 'variable_declarator':
                    record_declaration(node_text, "var")
                elif parent.type == 'field_declaration':
                    record_declaration(node_text, "field")
                elif parent.type == 'class_declaration' or parent.type == 'object_creation_expression':
                    record_declaration(node_text, "class")
                elif parent.type == 'enum_declaration':
                    record_declaration(node_text, "enum")
                elif parent.type == 'interface_declaration':
                    record_declaration(node_text, "interface")
                elif parent.type == 'method_declaration' or parent.type == "function_definition":
                    record_declaration(node_text, "fn")
                else:
                    record_declaration(node_text, "var")

        elif node.type == "qualified_name":
            if parent and parent.type == "package_declaration":
                record_declaration(node_text, "package")

        for child in node.children:
            collect_and_label(child)

        if node.type in ('block', 'class_declaration', 'interface_declaration', 'enum_declaration', 'function_declaration'):
            exit_scope()

    enter_scope()
    collect_and_label(tree.root_node)
    exit_scope()

    for name, kind_levels in declared_ids.items():
        for kind, _ in kind_levels:
            key = (kind, name)
            if key not in rename_map:
                rename_map[key] = f"{kind}_{counters[kind]}"
                counters[kind] += 1

    return rename_map

def replace_identifiers(code_bytes, rename_map, tree):
    result = []
    last_byte = 0

    def get_kind(node):
        parent = node.parent
        if node.type == "name":
            if parent:
                if parent.type == "const_element":
                    return "var"
                elif parent.type == "function_definition":
                    return "fn"
                elif parent.type == "class_declaration" or parent.type == "object_creation_expression":
                    return "class"
                elif parent.type == "parameters":
                    return "var"
                elif parent.type == "variable_declarator":
                    return "var"
                elif parent.type == "class_definition":
                    return "class"
                elif parent.type == "struct_declaration":
                    return "struct"
                elif parent.type == "enum_declaration":
                    return "enumtype"
                elif parent.type == "enum_member_declaration":
                    return "enum"
                elif parent.type == "interface_declaration":
                    return "interface"
                elif parent.type == "scoped_call_expression":
                    if parent.child(2) == node:
                        return "fn"
                    else:
                        return "class"
                elif parent.type == "method_declaration" or parent.type == "function_call_expression" or parent.type == "member_call_expression":
                    return "fn"
                else:
                    return "var"

        return None

    def visit(node):
        nonlocal last_byte
        for child in node.children:
            visit(child)

        if node.type in ("name", "qualified_name"):
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

def collect_declared_identifiers(node, code_bytes, declared_ids):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent

    if node.type == "name":
        if parent and parent.type in (
            "const_element",
            "variable_declarator",
            "field_declaration",
            "function_definition",
            "object_creation_expression",
            "method_declaration",
            "class_declaration",
            "interface_declaration",
            "function_call_expression",
            "scoped_call_expression"
            "member_call_expression"
        ):
            declared_ids.add(node_text)
        elif parent and parent.type == "parameter":
            declared_ids.add(parent.child(1).text.decode('utf-8', errors='replace'))

    elif node.type == "qualified_name":
        if parent and parent.type == "package_declaration":
            declared_ids.add(node.text.decode('utf-8', errors='replace'))

    for child in node.children:
        collect_declared_identifiers(child, code_bytes, declared_ids)

def rename_identifiers(node, code_bytes, declared_ids, rename_map):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent
    if node_text in declared_ids and node_text not in rename_map:   
        if node.type == "name":
            is_const = parent and parent.type == "const_element"
            is_function = (
                parent and parent.type == "function_definition" and parent.child_by_field_name("name") == node
            ) 
            is_method = parent and parent.type =="method_declaration"
            is_enum = parent and parent.type == "enum_declaration"
            is_param = parent and parent.type == "parameter"
            is_field = parent and parent.type == "field_declaration"
            is_interface = parent and parent.type == "interface_declaration"
            is_call = parent and parent.type == "function_call_expression" or (parent and parent.type == "member_call_expression") or (parent and parent.type == "scoped_call_expression")
            if is_const:
                rename_map[node_text] = f"const_{len(rename_map)}"
            elif is_function or is_method or is_call:
                rename_map[node_text] = f"fn_{len(rename_map)}"
            elif is_enum:
                rename_map[node_text] = f"enum_{len(rename_map)}"
            elif is_param:
                rename_map[node_text] = f"param_{len(rename_map)}"
            elif is_field:
                rename_map[node_text] = f"field_{len(rename_map)}"
            elif is_interface:
                rename_map[node_text] = f"interface_{len(rename_map)}"
            else:
                rename_map[node_text] = f"var_{len(rename_map)}"
                

    for child in node.children:
        rename_identifiers(child, code_bytes, declared_ids, rename_map)

# 6) Constant folding - 2 + 4 -> 6, have own evaluator.
def evaluate_expression(node, code_bytes):
    if node.type == 'parenthesized_expression':
        return evaluate_expression(node.children[1], code_bytes)

    if node.type == 'integer':
        try:
            return int(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
        except ValueError:
            return None

    if node.type == 'float':
        try:
            return float(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
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

def preprocess_php(code):
    importless_code = remove_imports(code)
    commentless_code = remove_comments(importless_code)
    documentationless_code = remove_docblocks(commentless_code)
    cleaned_code = remove_exception_and_print_text(documentationless_code)
    folded_code = fold_constants(cleaned_code)

    tree = parser.parse(folded_code)
    #pretty_print_node(tree.root_node, folded_code)
    
    rename_map = label_code(folded_code, tree)
    # print(f"rens {rename_map}")
    labeled_code = replace_identifiers(folded_code, rename_map, tree)
    labeled_tree = parser.parse(labeled_code)   

    declared_ids = set()
    collect_declared_identifiers(labeled_tree.root_node, labeled_code, declared_ids)
    rename_identifiers(labeled_tree.root_node, labeled_code, declared_ids, rename_map)
    obfuscated_code = replace_identifiers(labeled_code, rename_map, labeled_tree)

    # print(f"rens {rename_map}")
    # print(f"decls {declared_ids}")

    return obfuscated_code.decode('utf-8')

code = b"""
<?php
class MyClass {
  public static $count = 0;
  private $name;
  function __construct($name) {
    $this->name = $name;
  }
  function greet() {
    global $globalVar;
    echo "Hello $this->name\n";
  }
  static function inc() {
    self::$count++;
  }
}

function add($a, $b) {
  return $a + $b;
}

$a = $_GET['a'] ?? 1;
$b = $_POST['b'] ?? 2;
$c = add($a, $b);
$obj = new MyClass("World");

$obj->greet();
MyClass::inc();
echo "Sum is $c\n";
$c = 32+2+(4+2.0)
?>
"""

preprocess_php(code)