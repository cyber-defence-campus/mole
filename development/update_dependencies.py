import json
import os
from pathlib import Path

import tomli  # For parsing TOML files


def extract_dependencies(pyproject_path):
    """Extract pip dependencies from pyproject.toml file."""
    with open(pyproject_path, "rb") as f:
        try:
            pyproject_data = tomli.load(f)
        except Exception as e:
            print(f"Error parsing pyproject.toml: {e}")
            return []

    # Check for dependencies in different possible locations
    dependencies = []

    # Check for project.dependencies (PEP 621 format)
    if "project" in pyproject_data and "dependencies" in pyproject_data["project"]:
        dependencies.extend(pyproject_data["project"]["dependencies"])

    # Check for tool.poetry.dependencies (Poetry format)
    elif "tool" in pyproject_data and "poetry" in pyproject_data["tool"]:
        poetry_deps = pyproject_data["tool"]["poetry"].get("dependencies", {})
        # Filter out python dependency and convert dict to requirements format
        for pkg, version in poetry_deps.items():
            if pkg != "python":
                if isinstance(version, str):
                    dependencies.append(f"{pkg}=={version}")
                elif isinstance(version, dict) and "version" in version:
                    dependencies.append(f"{pkg}=={version['version']}")
                else:
                    dependencies.append(pkg)

    # Check for tool.flit.metadata.requires (Flit format)
    elif "tool" in pyproject_data and "flit" in pyproject_data["tool"]:
        if "metadata" in pyproject_data["tool"]["flit"]:
            flit_deps = pyproject_data["tool"]["flit"]["metadata"].get("requires", [])
            dependencies.extend(flit_deps)

    return sorted(dependencies)


def update_plugin_json(plugin_json_path, dependencies):
    """Update the dependencies field in plugin.json"""
    try:
        with open(plugin_json_path, "r") as f:
            plugin_data = json.load(f)

        # Update the dependencies field
        if "dependencies" not in plugin_data:
            plugin_data["dependencies"] = {}

        plugin_data["dependencies"]["pip"] = dependencies

        # Write back to the file
        with open(plugin_json_path, "w") as f:
            json.dump(plugin_data, f, indent=2)

        print(f"Updated dependencies in {plugin_json_path}")
    except Exception as e:
        print(f"Error updating plugin.json: {e}")


def main():
    # Get the directory of the current script
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    # pyproject.toml and plugin.json are in the parent folder of the script
    parent_dir = script_dir.parent
    pyproject_path = parent_dir / "pyproject.toml"
    plugin_json_path = parent_dir / "plugin.json"

    if not pyproject_path.exists():
        print("Error: pyproject.toml not found")
        return

    if not plugin_json_path.exists():
        print("Error: plugin.json not found")
        return

    dependencies = extract_dependencies(pyproject_path)
    update_plugin_json(plugin_json_path, dependencies)


if __name__ == "__main__":
    main()
