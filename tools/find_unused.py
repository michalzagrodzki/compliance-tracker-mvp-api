import ast
import os
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple


EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
}


@dataclass(frozen=True)
class FunctionDefInfo:
    module: str
    qualname: str  # e.g., module:class.method or module:function
    kind: str  # "function" or "method"
    lineno: int
    has_decorators: bool


def iter_python_files(root: str) -> List[str]:
    py_files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune excluded dirs
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                py_files.append(os.path.join(dirpath, fname))
    return py_files


def module_path(root: str, file_path: str) -> str:
    rel = os.path.relpath(file_path, root)
    if rel.endswith("/__init__.py"):
        rel = rel[: -len("/__init__.py")]
    elif rel.endswith(".py"):
        rel = rel[: -len(".py")]
    return rel.replace(os.sep, ".")


def collect_defs(tree: ast.AST, module: str) -> List[FunctionDefInfo]:
    defs: List[FunctionDefInfo] = []

    class DefVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # type: ignore[override]
            # Only top-level functions are added here; methods handled in ClassDef
            if isinstance(getattr(node, "parent", None), ast.Module):
                defs.append(
                    FunctionDefInfo(
                        module=module,
                        qualname=f"{module}:{node.name}",
                        kind="function",
                        lineno=node.lineno,
                        has_decorators=bool(node.decorator_list),
                    )
                )
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # type: ignore[override]
            if isinstance(getattr(node, "parent", None), ast.Module):
                defs.append(
                    FunctionDefInfo(
                        module=module,
                        qualname=f"{module}:{node.name}",
                        kind="function",
                        lineno=node.lineno,
                        has_decorators=bool(node.decorator_list),
                    )
                )
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:  # type: ignore[override]
            for body_item in node.body:
                if isinstance(body_item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defs.append(
                        FunctionDefInfo(
                            module=module,
                            qualname=f"{module}:{node.name}.{body_item.name}",
                            kind="method",
                            lineno=body_item.lineno,
                            has_decorators=bool(body_item.decorator_list),
                        )
                    )
            self.generic_visit(node)

    # Attach parent links for top-level detection
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            setattr(child, "parent", parent)

    DefVisitor().visit(tree)
    return defs


def collect_name_attr_usage(tree: ast.AST) -> Tuple[Set[str], Set[str]]:
    names: Set[str] = set()
    attrs: Set[str] = set()

    class UseVisitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:  # type: ignore[override]
            names.add(node.id)
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:  # type: ignore[override]
            attrs.add(node.attr)
            self.generic_visit(node)

    UseVisitor().visit(tree)
    return names, attrs


def is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def main() -> None:
    root = os.getcwd()
    files = iter_python_files(root)

    all_defs: List[FunctionDefInfo] = []
    names_used: Set[str] = set()
    attrs_used: Set[str] = set()

    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                src = f.read()
            tree = ast.parse(src, filename=path)
        except Exception:
            continue

        mod = module_path(root, path)
        all_defs.extend(collect_defs(tree, mod))
        n_used, a_used = collect_name_attr_usage(tree)
        names_used.update(n_used)
        attrs_used.update(a_used)

    # Heuristics: consider functions/methods with decorators as used (e.g., FastAPI routes)
    # Consider dunder methods as used
    # Consider anything whose name appears in names_used/attrs_used as used
    unused: List[FunctionDefInfo] = []
    for d in all_defs:
        # Extract the last component: function or method name
        last_name = d.qualname.split(":", 1)[1]
        simple = last_name.split(".")[-1]

        if d.has_decorators:
            continue
        if is_dunder(simple):
            continue
        if simple in names_used or simple in attrs_used:
            continue

        unused.append(d)

    # Print results grouped by module
    if not unused:
        print("No unused candidates found by heuristic.")
        return

    print("Unused method/function candidates (heuristic):")
    for d in sorted(unused, key=lambda x: (x.module, x.qualname, x.lineno)):
        # Skip reporting for this helper script itself
        if d.module.startswith("tools.find_unused"):
            continue
        print(f"- {d.kind}: {d.qualname} (line {d.lineno})")


if __name__ == "__main__":
    main()
