import json
import os


def readme_to_json_string(readme_filename="README.md"):
    """
    Reads the README file and returns its content as a JSON-escaped string.

    Args:
        readme_filename (str): The name of the README file.
                               Assumes it's in the same directory as the script.

    Returns:
        str: The JSON-escaped string content of the README file (including quotes),
             or None if the file cannot be read.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    readme_path = os.path.join(parent_dir, readme_filename)

    if not os.path.exists(readme_path):
        print(f"Error: File not found at {readme_path}")
        return None

    try:
        with open(readme_path, "r", encoding="utf-8") as f:
            content = f.read()
        # Use json.dumps to correctly escape the string for JSON embedding
        # This returns a string *including* the surrounding quotes.
        # Find the first occurrence of '#' indicating a heading
        start_index = content.find("#")
        print(f"Start index of first heading: {start_index}")
        if start_index != -1:
            # Take content from the first heading onwards
            filtered_content = content[start_index:]
        else:
            # If no heading found, use the original content
            filtered_content = content

        json_string = json.dumps(filtered_content)
        return json_string
    except Exception as e:
        print(f"Error reading or processing file {readme_path}: {e}")
        return None


def update_plugin_json(readme_content):
    """
    Updates the longdescription attribute in the plugin.json file.

    Args:
        readme_content (str): The README content to use for longdescription

    Returns:
        bool: True if successful, False otherwise
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    plugin_json_path = os.path.join(parent_dir, "plugin.json")

    if not os.path.exists(plugin_json_path):
        print(f"Error: plugin.json not found at {plugin_json_path}")
        return False

    try:
        # Read the existing plugin.json
        with open(plugin_json_path, "r", encoding="utf-8") as f:
            plugin_data = json.load(f)

        # Update the longdescription attribute
        plugin_data["longdescription"] = readme_content

        # Write back to the file with pretty formatting
        with open(plugin_json_path, "w", encoding="utf-8") as f:
            json.dump(plugin_data, f, indent=2)

        print(f"Successfully updated longdescription in {plugin_json_path}")
        return True
    except Exception as e:
        print(f"Error updating plugin.json: {e}")
        return False


if __name__ == "__main__":
    json_escaped_readme_with_quotes = readme_to_json_string()

    if json_escaped_readme_with_quotes:
        # We need the raw content *without* the extra quotes added by the first json.dumps
        # because we are embedding it into another JSON structure.
        # json.loads will remove the outer quotes and unescape the content.
        readme_content = json.loads(json_escaped_readme_with_quotes)

        # Update the plugin.json file instead of printing
        update_plugin_json(readme_content)
    else:
        # Error message already printed by readme_to_json_string
        pass
