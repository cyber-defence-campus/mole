"""
This package contains implementations to group paths. All `PathGrouper` subclasses are imported
here to be discovered dynamically.
"""
from __future__  import annotations
from ..core.data import Path
from abc         import ABC, abstractmethod
from typing      import Dict, List, Tuple, Type
import importlib
import inspect
import os
import pkgutil
import sys


class PathGrouper(ABC):
    """
    This class is an abstract base class for path grouping strategies. Implementations should
    provide logic for how paths are organized in a tree structure.
    """
    
    @abstractmethod
    def get_group_keys(self, path: Path) -> List[Tuple[str, str, int]]:
        """
        This method returns a list of hierarchy keys for organizing paths. Each key is a tuple of
        (display_name, internal_id, level). The level indicates the depth in the tree (0=root,
        1=first level, etc.).
        
        Args:
            path: `Path` object to be grouped
            
        Returns:
            List of tuples containing (display_name, internal_id, level)
        """
        raise NotImplementedError
    
    @abstractmethod
    def get_strategy_name(self) -> str:
        """
        This method returns the name of this grouping strategy. This should match the corresponding
        strategy constant.
        """
        raise NotImplementedError

    @staticmethod
    def get_all_subclasses() -> List[Type['PathGrouper']]:
        """
        This method recursively returns all subclasses of `PathGrouper`.
        
        Returns:
            List of `PathGrouper` subclass types
        """
        all_subclasses = []
        for subclass in PathGrouper.__subclasses__():
            all_subclasses.append(subclass)
            all_subclasses.extend(subclass.__subclasses__())
        return all_subclasses

    @staticmethod
    def get_strategy_map() -> Dict[str, PathGrouper]:
        """
        This method returns a mapping of all available strategy names to their implementations.
        Dynamically discovers all `PathGrouper` subclasses.
        
        Returns:
            Dictionary mapping strategy names to `PathGrouper` instances
        """
        strategy_map = {"None": None}
        # Find all PathGrouper subclasses and instantiate them
        for cls in PathGrouper.get_all_subclasses():
            # Skip the abstract base class itself
            if cls == PathGrouper or inspect.isabstract(cls):
                continue
            try:
                instance = cls()
                strategy_map[instance.get_strategy_name()] = instance
            except Exception as e:
                print(f"Error instantiating {cls.__name__:s}: {str(e):s}", file=sys.stderr)
        return strategy_map

def get_all_grouping_strategies() -> List[str]:
    """
    This method returns a list of all available strategy names.
    
    Returns:
        List of strategy names as strings
    """
    return list(PathGrouper.get_strategy_map().keys())

def get_grouper(strategy: str) -> PathGrouper:
    """
    This method is a factory method to create a grouper based on the strategy.
    
    Args:
        strategy: The strategy name
        
    Returns:
        An instance of the appropriate `PathGrouper` implementation or None if the strategy is
        invalid
    """
    return PathGrouper.get_strategy_map().get(strategy, None)

# Dynamically import all modules in this package after the `PathGrouper` class is defined
package_dir = os.path.dirname(__file__)
for (_, module_name, _) in pkgutil.iter_modules([package_dir]):
    # Skip importing this module to avoid circular imports
    if module_name != "__init__":
        importlib.import_module(f"{__name__:s}.{module_name:s}")