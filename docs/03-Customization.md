# Customization
This section documents extension points within *Mole* that allow users to customize and extend its analysis and UI behavior.
## Path Grouping Strategy
To implement a custom path grouping strategy, follow these steps:
1. Create a new subclass of [`PathGrouper`](../mole/grouping/__init__.py#L17) within the [grouping](../mole/grouping/) package.
2. There is no need to register the strategy manually - its name will be detected dynamically.
3. Define a key tuple with the following fields:
  - `display_name`: A string shown to users in the tree view.
  - `internal_id`: A unique identifier for the group.
  - `level`: Specifies the group's depth in the tree view hierarchy.

**Note**: You can also inherit from existing strategies. For an example, see [`CallgraphPathGrouper`](../mole/grouping/call_graph.py#L10).

----------------------------------------------------------------------------------------------------
[Back-To-README](../README.md#documentation)