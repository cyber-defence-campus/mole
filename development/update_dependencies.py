from typing import List
import json
import os
import pathlib
import tomli


def extract_dependencies(pyproject_path: pathlib.Path) -> List[str]:
    """Extract pip dependencies from pyproject.toml file."""
    with open(pyproject_path, "rb") as f:
        try:
            pyproject_data = tomli.load(f)
        except Exception as e:
            print(f"Error parsing pyproject.toml: {str(e):s}")
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
                    dependencies.append(f"{pkg:s}=={version:s}")
                elif isinstance(version, dict) and "version" in version:
                    dependencies.append(f"{pkg:s}=={version['version']:s}")
                else:
                    dependencies.append(pkg)

    # Check for tool.flit.metadata.requires (Flit format)
    elif "tool" in pyproject_data and "flit" in pyproject_data["tool"]:
        if "metadata" in pyproject_data["tool"]["flit"]:
            flit_deps = pyproject_data["tool"]["flit"]["metadata"].get("requires", [])
            dependencies.extend(flit_deps)

    return sorted(dependencies)


def update_plugin_json(plugin_json_path: pathlib.Path, dependencies: List[str]) -> None:
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

        print(f"Updated dependencies in '{str(plugin_json_path):s}'")
    except Exception as e:
        print(f"Error updating plugin.json: {str(e):s}")
    return


def create_requirements_txt(
    requirements_path: pathlib.Path, dependencies: List[str]
) -> None:
    """Create a requirements.txt file from the dependencies"""
    try:
        with open(requirements_path, "w") as f:
            for dep in dependencies:
                f.write(f"{dep:s}\n")
        print(f"Created requirements.txt at '{str(requirements_path):s}'")
    except Exception as e:
        print(f"Error creating requirements.txt: {str(e):s}")
    return


def main() -> None:
    # Get the directory of the current script
    script_dir = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
    # pyproject.toml and plugin.json are in the parent folder of the script
    pyproject_path = script_dir.parent / "pyproject.toml"
    requirements_path = script_dir.parent / "requirements.txt"

    if not pyproject_path.exists():
        print("Error: pyproject.toml not found")
        return

    dependencies = extract_dependencies(pyproject_path)

    # Create requirements.txt
    create_requirements_txt(requirements_path, dependencies)
    return


if __name__ == "__main__":
    main()
