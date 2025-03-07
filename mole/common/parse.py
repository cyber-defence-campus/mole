from .log   import Logger
from lark   import Lark, Token, Transformer, v_args
from typing import Callable


class LogicalExpressionParser:
    """
    This class parses logical expressions.
    """

    grammar = """
    start: expr

    ?expr: term ("or" term)* -> or_expr
    ?term: factor ("and" factor)* -> and_expr
    ?factor: atom
          | "not" factor -> not_expr
          | "(" expr ")"
    ?atom: "True" -> true
         | "true" -> true
         | "False" -> false
         | "false" -> false
         | "i" "==" value -> eq
         | "i" "!=" value -> neq
         | "i" ">" value -> gt
         | "i" "<" value -> lt
         | "i" ">=" value -> ge
         | "i" "<=" value -> le
         | "i" -> var

    ?value: "-" NUMBER -> neg_number
      | NUMBER -> number

    %import common.NUMBER
    %import common.WS
    %ignore WS
    """

    def __init__(
            self,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a parser for logical expressions.
        """
        self._tag = tag
        self._log = log
        self._parser = Lark(
            grammar=self.grammar,
            parser="lalr",
            transformer=LogicalExpressionTransformer()
        )
        return
    
    def parse(self, expr: str) -> Callable[[int], bool]:
        """
        This method parses a logical exression.
        """
        try:
            e = self._parser.parse(expr).children[0]
            def f(i):
                return eval(e)
            return f
        except Exception as e:
            self._log.warn(self._tag, f"Failed to parse expression '{expr}': {str(e):s}")
        return lambda i: False
    

@v_args(inline=True)
class LogicalExpressionTransformer(Transformer):
    """
    This class convers Lark trees into logical expressions.
    """

    def or_expr(self, *exprs: str) -> str:
        """
        This method adds 'or' logic.
        """
        return f"({') or ('.join(exprs):s})"

    def and_expr(self, *exprs: str) -> str:
        """
        This method adds 'and' logic.
        """
        return f"({') and ('.join(exprs):s})"

    def not_expr(self, expr: str) -> str:
        """
        This method adds 'not' logic.
        """
        return f"not ({expr:s})"

    def eq(self, value: str) -> str:
        """
        This method adds '==' logic.
        """
        return f"i == {value:s}"

    def neq(self, value: str) -> str:
        """
        This method adds '!=' logic.
        """
        return f"i != {value:s}"

    def gt(self, value: str) -> str:
        """
        This method adds '>' logic.
        """
        return f"i > {value:s}"

    def lt(self, value: str) -> str:
        """
        This method adds '<' logic.
        """
        return f"i < {value:s}"

    def ge(self, value: str) -> str:
        """
        This method adds '>=' logic.
        """
        return f"i >= {value:s}"

    def le(self, value: str) -> str:
        """
        This method adds '<=' logic.
        """
        return f"i <= {value:s}"

    def var(self) -> str:
        """
        This method adds variables logic.
        """
        return "i"
    
    def neg_number(self, t: Token) -> str:
        """
        This method adds numbers logic.
        """
        return f"-{t.value:s}"

    def number(self, t: Token) -> str:
        """
        This method adds numbers logic.
        """
        return f"{t.value:s}"
    
    def true(self) -> str:
        """
        This method adds 'True' logic.
        """
        return "True"
    
    def false(self) -> str:
        """
        This method adds 'False' logic.
        """
        return "False"
