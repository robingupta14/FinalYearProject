# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os
from collections import defaultdict

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
csharp_lang = get_language('c_sharp')
parser = get_parser('c_sharp')

# 2) Import removal
def remove_using(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    cleaned_code = re.sub(r'^\s*using\s+[\w\.]+;\s*$', '', code_str, flags=re.MULTILINE)
    return cleaned_code.encode('utf-8')

# 3)  Comment removal. C Sharp has docstrings.
def remove_comments(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'/\*.*?\*/', '', code_str, flags=re.DOTALL)
    return code_str.encode('utf-8')

def remove_docstrings(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'///\s*<[^>]+>.*?(?=\n)', '', code_str, flags=re.DOTALL)
    code_str = re.sub(r'///.*', '', code_str)
    return code_str.encode('utf-8')

# 4) Exception line removal, Print removal.
def remove_exception_and_print_text(code_bytes):
    code_str = code_bytes.decode('utf-8', errors='replace')
    code_str = re.sub(r'\bConsole\.WriteLine\s*\(.*?\)\s*;', '', code_str)
    code_str = re.sub(r'\bConsole\.Write\s*\(.*?\)\s*;', '', code_str)
    code_str = re.sub(r'\blogger\.Log\s*\(.*?\)\s*;', '', code_str)
    code_str = re.sub(r'(throw\s+new\s+\w+\s*\()\s*".*?"(\s*\))', r'\1\2', code_str)
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

        if node.type in ('block', 'class_declaration', 'struct_declaration', 'interface_declaration', 'enum_declaration'):
            enter_scope()

        if node.type == 'identifier':
            if parent:
                if parent.type == 'method_declaration' and parent.child_by_field_name("name") == node:
                    record_declaration(node_text, "fn")
                elif parent.type == 'parameter':
                    record_declaration(parent.child(1).text.decode('utf-8', errors='replace'), "var")
                elif parent.type == 'variable_declarator':
                    record_declaration(node_text, "var")
                elif parent.type == 'field_declaration':
                    record_declaration(node_text, "field")
                elif parent.type == 'class_declaration':
                    record_declaration(node_text, "class")
                elif parent.type == 'struct_declaration':
                    record_declaration(node_text, "struct")
                elif parent.type == 'enum_declaration':
                    record_declaration(node_text, "enumtype")
                elif parent.type == 'enum_member_declaration':
                    record_declaration(node_text, "enum")
                elif parent.type == 'interface_declaration':
                    record_declaration(node_text, "interface")

        elif node.type == "qualified_name":
            if parent and parent.type == "namespace_declaration":
                record_declaration(node_text, "ns")

        for child in node.children:
            collect_and_label(child)

        if node.type in ('block', 'class_declaration', 'struct_declaration', 'interface_declaration', 'enum_declaration'):
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
        if node.type == "identifier":
            if parent:
                if parent.type == "method_declaration" and parent.child_by_field_name("name") == node:
                    return "fn"
                elif parent.type == "parameter":
                    return "var"
                elif parent.type == "variable_declarator":
                    return "var"
                elif parent.type == "field_declaration":
                    return "field"
                elif parent.type == "class_declaration":
                    return "class"
                elif parent.type == "struct_declaration":
                    return "struct"
                elif parent.type == "enum_declaration":
                    return "enumtype"
                elif parent.type == "enum_member_declaration":
                    return "enum"
                elif parent.type == "interface_declaration":
                    return "interface"
                else:
                    return "var"

        elif node.type == "qualified_name":
            if parent and parent.type == "namespace_declaration":
                return "ns"

        return None

    def visit(node):
        nonlocal last_byte
        for child in node.children:
            visit(child)

        if node.type in ("identifier", "qualified_name"):
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

    if node.type == "identifier":
        if parent and parent.type in (
            "enum_declaration",
            "enum_member_declaration",
            "variable_declarator",
            "field_declaration",
            "method_declaration",
            "class_declaration",
            "interface_declaration",
            "struct_declaration",
            "assignment_expression"
        ):
            declared_ids.add(node_text)
        elif parent and parent.type in ("function_definition") and parent.child_by_field_name("declarator") == node:
            declared_ids.add(node_text)
        elif parent and parent.type in ("parameter"):
            declared_ids.add(parent.child(1).text.decode('utf-8', errors='replace'))

        # elif parent and parent.type in ("class_specifier", "struct_specifier"):
        #     declared_ids.add(node_text)
    
    # elif node.type == "modifier":
    #     if parent and parent.type in (
    #         "method_declaration", "class_declaration", "field_declaration", "constructor_declaration", "variable_declaration"
    #     ):
    #         declared_ids.add(node_text)

    elif node.type == "type_identifier":
        if parent and parent.type in ("class_specifier", "struct_specifier", "enum_specifier"):
            declared_ids.add(node_text)
    
    elif node.type == "qualified_name":
        if parent and parent.type in ("namespace_declaration"):
            declared_ids.add(node.text.decode('utf-8', errors='replace'))

    for child in node.children:
        collect_declared_identifiers(child, code_bytes, declared_ids)

def rename_identifiers(node, code_bytes, declared_ids, rename_map):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent

    # print(f"{node_text}, {declared_ids}")

    if node_text in declared_ids and node_text not in rename_map:   
        print(f"my text: {node_text}")
        if node.type == "identifier":
            is_function = (
                parent and parent.type in ("function_declarator", "function_definition") and
                parent.child_by_field_name("declarator") == node
            )

            is_struct = parent and parent.type == "struct_declaration"
            is_class = parent and parent.type == "class_declaration"
            is_enum_type = parent and parent.type == "enum_declaration"
            is_enum = parent and parent.type == "enum_member_declaration"
            is_param = parent and parent.type == "parameter"
            is_field = parent and parent.type == "field_declaration"
            is_interface = parent and parent.type == "interface_declaration"
            is_method = parent and parent.type == "method_declaration"

            if is_struct:
                rename_map[node_text] = f"struct_{len(rename_map)}"
            elif is_function:
                rename_map[node_text] = f"fn_{len(rename_map)}"
            elif is_class:
                rename_map[node_text] = f"class_{len(rename_map)}"
            elif is_enum_type:
                rename_map[node_text] = f"enumtype_{len(rename_map)}"
            elif is_enum:
                rename_map[node_text] = f"enum_{len(rename_map)}"
            elif is_param:
                rename_map[node_text] = f"var_{len(rename_map)}"
            elif is_field:
                rename_map[node_text] = f"field_{len(rename_map)}"
            elif is_interface:
                rename_map[node_text] = f"interface_{len(rename_map)}"
            elif is_method:
                rename_map[node_text] = f"method_{len(rename_map)}"
            else:
                rename_map[node_text] = f"var_{len(rename_map)}"
        
        elif node.type == "field_declaration":
            rename_map[node_text] = f"field_{len(rename_map)}"

        elif node.type == "qualified_name":
            if parent and parent.type in ("namespace_declaration"):
                rename_map[node_text] = f"ns_{len(rename_map)}"

        elif node.type == "type_identifier":
            if parent and parent.type == "class_specifier":
                rename_map[node_text] = f"class_{len(rename_map)}"
            else:
                rename_map[node_text] = f"type_{len(rename_map)}"

    for child in node.children:
        rename_identifiers(child, code_bytes, declared_ids, rename_map)

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

def preprocess_csharp(code):
    importless_code = remove_using(code)
    commentless_code = remove_comments(importless_code)
    documentationless_code = remove_docstrings(commentless_code)
    cleaned_code = remove_exception_and_print_text(documentationless_code)
    folded_code = fold_constants(cleaned_code)

    tree = parser.parse(folded_code)
    rename_map = label_code(folded_code, tree)

    print(rename_map)
    #pretty_print_node(tree.root_node, folded_code)
    labeled_code = replace_identifiers(folded_code, rename_map, tree)
    labeled_tree = parser.parse(labeled_code)

    rename_map = {}
    declared_ids = set()
    collect_declared_identifiers(labeled_tree.root_node, labeled_code, declared_ids)

    print(declared_ids)
    rename_identifiers(labeled_tree.root_node, labeled_code, declared_ids, rename_map)

    print(rename_map)

    obfuscated_code = replace_identifiers(labeled_code, rename_map, labeled_tree)

    return obfuscated_code.decode('utf-8')
code = b"""
    void Log(String message)

"""

code = b"""
using System;
using System.Collections.Generic;

namespace MyApp.Core {

    public enum LogLevel
    {
        Info,
        Warning,
        Error
    }

    public struct Point
    {
        public int X;
        public int Y;
    }

    public interface ILogger {
        void Log(String message)
    }

    public class Processor
    {
        private ILogger logger;

        public Processor(ILogger logger)
        {
            this.logger = logger;
        }

        public void booger(String e) {
        }

        public int Compute(Point point, LogLevel level)
        {
            int result = point.X + point.Y;

            switch (level)
            {
                case LogLevel.Info:
                    logger.Log("Info level computation");
                    break;
                case LogLevel.Warning:
                    logger.Log("Warning level computation");
                    break;
                case LogLevel.Error:
                    logger.Log("Error level computation");
                    break;
            }

            return result;
        }

        public static int x(string[] args)
        {
            int x = 42 * 42 + 42;   
            ILogger logger = new Logger();
            Processor processor = new Processor(logger);
            Point p = new Point { X = 10, Y = 20 };
            int output = processor.Compute(p, LogLevel.Warning);
            Console.WriteLine("Result: " + output);
            return x;
        }
    }
}
"""

code = b"""
public ILogger logger;
public void process(ILogger log)
{
    this.logger = log;
}

"""

print(preprocess_csharp(code).strip())