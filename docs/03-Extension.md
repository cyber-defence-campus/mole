# Extension
## Path Grouping Strategy
To implement a custom path grouping strategy:
1. Create a new subclass of `PathGrouper` in the grouping package.
2. Your strategy name will be dynamically detected, so no need to manually add it to the `001-settings.yml` file.
3. Define your key tuple by specifying the following values:
  - `display_name`: A `str` that users will see in the tree view.
  - `internal_id`: A key for uniquely identifying each group.
  - `level`: Determines the group's depth level in the tree view hierarchy.
**Note**: You can inherit from existing strategies (see `CallgraphPathGrouper` for an example).
----------------------------------------------------------------------------------------------------
[Go-Back](../README.md#documentation)