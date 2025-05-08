# GOAL: Carry out AST Generation  using the generated Parser from Tree-sitter:
from tree_sitter_languages import get_language, get_parser
import tempfile
import subprocess
import re
import os

# 1) Extraneous whitespace, formatting -> Removed by this step as it's not stored in Tree-sitter ASTs.
cpp_lang = get_language('c_sharp')
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
    code_str = re.sub(r'(throw\s+new\s+\w+\s*\()\s*".*?"(\s*\))', r'\1\2', code_str)
    return code_str.encode('utf-8')

# 5) Renaming
def collect_declared_identifiers(node, code_bytes, declared_ids):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent

    if node.type == "identifier":
        if parent and parent.type in (
            "init_declarator",
            "parameter_declaration",
            "enum_declaration",
            "variable_declarator",
            "field_declaration",
            "method_declaration",
            "class_declaration"
        ):
            declared_ids.add(node_text)

        elif parent and parent.type in ("function_declarator", "function_definition") and parent.child_by_field_name("declarator") == node:
            declared_ids.add(node_text)

        elif parent and parent.type in ("class_specifier", "struct_specifier"):
            declared_ids.add(node_text)
    
    elif node.type == "modifier":
        if parent and parent.type in (
            "method_declaration",
        ):
            declared_ids.add(node_text)

    elif node.type == "type_identifier":
        if parent and parent.type in ("class_specifier", "struct_specifier", "enum_specifier"):
            declared_ids.add(node_text)

    elif node.type == "namespace_identifier":
        if parent and parent.type == "namespace_definition":
            declared_ids.add(node_text)

    for child in node.children:
        collect_declared_identifiers(child, code_bytes, declared_ids)

def rename_identifiers(node, code_bytes, declared_ids, rename_map):
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
    parent = node.parent

    if node_text in declared_ids and node_text not in rename_map:
        if node.type == "namespace_identifier":
            if parent and parent.type == "namespace_definition":
                rename_map[node_text] = f"ns_{len(rename_map)}"
         
        elif node.type == "identifier":
            is_function = (
                parent and parent.type in ("function_declarator", "function_definition") and
                parent.child_by_field_name("declarator") == node
            )

            is_class = parent and parent.type == "class_specifier"
            is_enum = parent and parent.type == "enum_declaration"
            is_param = parent and parent.type == "parameter_declaration"
            is_field = parent and parent.type == "field_declaration"

            if is_function:
                rename_map[node_text] = f"fn_{len(rename_map)}"
            elif is_class:
                rename_map[node_text] = f"class_{len(rename_map)}"
            elif is_enum:
                rename_map[node_text] = f"enum_{len(rename_map)}"
            elif is_param:
                rename_map[node_text] = f"param_{len(rename_map)}"
            elif is_field:
                rename_map[node_text] = f"field_{len(rename_map)}"
            else:
                rename_map[node_text] = f"var_{len(rename_map)}"

        elif node.type == "type_identifier":
            if parent and parent.type == "enum_member_declaration":
                rename_map[node_text] = f"enumtype_{len(rename_map)}"
            elif parent and parent.type == "class_specifier":
                rename_map[node_text] = f"class_{len(rename_map)}"
            else:
                rename_map[node_text] = f"type_{len(rename_map)}"

    for child in node.children:
        rename_identifiers(child, code_bytes, declared_ids, rename_map)


def replace_identifiers(code_bytes, rename_map):
    code_str = code_bytes.decode('utf-8', errors='replace')
    for old_name, new_name in sorted(rename_map.items(), key=lambda x: -len(x[0])):
        code_str = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, code_str)
    return code_str.encode('utf-8')

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
    # folded_code = fold_constants(cleaned_code)
    tree = parser.parse(cleaned_code)

    declared_ids = set()
    collect_declared_identifiers(tree.root_node, cleaned_code, declared_ids)
    print(f"declared ids: {declared_ids}")
    rename_map = {}
    rename_identifiers(tree.root_node, cleaned_code, declared_ids, rename_map)
    print(f"rename map: {rename_map}")
    processed_code = replace_identifiers(cleaned_code, rename_map)

    pretty_print_node(tree.root_node, processed_code)

    return processed_code.decode('utf-8')

code = b"""
using System;
using System.Collections.Generic;

namespace MyApp.Core
{
    public interface ILogger
    {
    }

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

    public class Logger : ILogger
    {
        private string logPrefix = "LOG:";

        public void Log(string message)
        {
            Console.WriteLine($"{logPrefix} {message}");
        }
    }

    public class Processor
    {
        private ILogger logger;

        public Processor(ILogger logger)
        {
            this.logger = logger;
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

        public static void Main(string[] args)
        {
            ILogger logger = new Logger();
            Processor processor = new Processor(logger);
            Point p = new Point { X = 10, Y = 20 };
            int output = processor.Compute(p, LogLevel.Warning);
            Console.WriteLine("Result: " + output);
        }
    }
}
"""

print(preprocess_csharp(code))