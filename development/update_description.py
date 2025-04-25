from typing import Optional
import json
import os
import re


def readme_to_json_string(
    readme_filename="README.md", save_test_file=True
) -> Optional[str]:
    """
    Reads the README file and returns its content as a JSON-escaped string.
    Only keeps the first section content and removes all other sections.

    Args:
        readme_filename (str): The name of the README file.
        save_test_file (bool): Whether to save a test file with processed
                               content.

    Returns:
        str: The JSON-escaped string content of the README file (including
             quotes), or None if the file cannot be read.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    readme_path = os.path.join(parent_dir, readme_filename)

    if not os.path.exists(readme_path):
        print(f"Error: File '{readme_path:s}' not found")
        return None

    try:
        with open(readme_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Find the first occurrence of '#' indicating a heading (the root heading)
        start_index = content.find("#")
        if start_index != -1:
            # Find the end of the first heading (next newline)
            end_of_first_heading = content.find("\n", start_index)
            if end_of_first_heading != -1:
                # Skip the root heading and start from the next line
                filtered_content = content[end_of_first_heading + 1 :].lstrip()
            else:
                # If no newline after heading (unlikely), use original content
                filtered_content = content
        else:
            # If no heading found, use the original content
            filtered_content = content

        # Find the second heading (which marks the end of first section)
        second_heading_index = filtered_content.find("\n#")
        if second_heading_index != -1:
            # Only keep content up to the second heading
            processed_content = filtered_content[:second_heading_index].strip()
        else:
            # If no second heading, keep all content
            processed_content = filtered_content

        # Replace markdown links [text](url) with just the text
        processed_content = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", processed_content)

        # Save the processed content to a test file if requested
        if save_test_file:
            test_file_path = os.path.join("/tmp", "processed_readme.md")
            with open(test_file_path, "w", encoding="utf-8") as test_file:
                test_file.write(processed_content)
            print(f"Saved processed markdown to '{test_file_path:s}'")

        # Use json.dumps to correctly escape the string for JSON embedding
        json_string = json.dumps(processed_content)
        return json_string
    except Exception as e:
        print(f"Error reading or processing file '{readme_path:s}': {str(e):s}")
        return None


def update_plugin_json(readme_content: str) -> bool:
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
        print(f"Error: plugin.json not found at '{plugin_json_path:s}'")
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

        print(f"Successfully updated longdescription in '{plugin_json_path:s}'")
        return True
    except Exception as e:
        print(f"Error updating plugin.json: {str(e):s}")
        return False


if __name__ == "__main__":
    json_escaped_readme_with_quotes = readme_to_json_string()

    if json_escaped_readme_with_quotes:
        # We need the raw content *without* the extra quotes added by the first
        # json.dumps because we are embedding it into another JSON structure.
        # json.loads will remove the outer quotes and unescape the content.
        readme_content = json.loads(json_escaped_readme_with_quotes)

        # Update the plugin.json file instead of printing
        update_plugin_json(readme_content)
    else:
        # Error message already printed by readme_to_json_string
        pass
