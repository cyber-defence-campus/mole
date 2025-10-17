from __future__ import annotations
from mole.common.parse import LogicalExpressionParser
import pytest


@pytest.fixture
def parser():
    """Provides a LogicalExpressionParser instance."""
    return LogicalExpressionParser()


class TestLogicalExpressionParser:
    """
    This class implements unit tests for parsing logical expressions.
    """

    def test_true(self, parser) -> None:
        f = parser.parse("True")
        assert f(0), "True, where i= 0"
        assert f(1), "True, where i= 1"
        assert f(-1), "True, where i=-1"
        f = parser.parse("true")
        assert f(0), "true, where i= 0"
        assert f(1), "true, where i= 1"
        assert f(-1), "true, where i=-1"
        f = parser.parse("TrUe")
        assert f is None, "TrUe"

    def test_false(self, parser) -> None:
        f = parser.parse("False")
        assert not f(0), "False, where i= 0"
        assert not f(1), "False, where i= 1"
        assert not f(-1), "False, where i=-1"
        f = parser.parse("false")
        assert not f(0), "false, where i= 0"
        assert not f(1), "false, where i= 1"
        assert not f(-1), "false, where i=-1"
        f = parser.parse("FaLsE")
        assert f is None, "FaLsE"

    def test_eq(self, parser) -> None:
        f = parser.parse("i==0")
        assert f(0), "i==0, where i= 0"
        assert not f(1), "i==0, where i= 1"
        assert not f(-1), "i==0, where i=-1"
        f = parser.parse("i == 1")
        assert not f(0), "i == 1, where i= 0"
        assert f(1), "i == 1, where i= 1"
        assert not f(-1), "i == 1, where i=-1"
        f = parser.parse("i  ==  -1")
        assert not f(0), "i  ==  -1, where i= 0"
        assert not f(1), "i  ==  -1, where i= 1"
        assert f(-1), "i  ==  -1, where i=-1"

    def test_neq(self, parser) -> None:
        f = parser.parse("i!=0")
        assert not f(0), "i!=0, where i= 0"
        assert f(1), "i!=0, where i= 1"
        assert f(-1), "i!=0, where i=-1"
        f = parser.parse("i != 1")
        assert f(0), "i != 1, where i= 0"
        assert not f(1), "i != 1, where i= 1"
        assert f(-1), "i != 1, where i=-1"
        f = parser.parse("i  !=  -1")
        assert f(0), "i  !=  -1, where i= 0"
        assert f(1), "i  !=  -1, where i= 1"
        assert not f(-1), "i  !=  -1, where i=-1"

    def test_gt(self, parser) -> None:
        f = parser.parse("i>0")
        assert not f(0), "i>0, where i= 0"
        assert f(1), "i>0, where i= 1"
        assert not f(-1), "i>0, where i=-1"
        f = parser.parse("i > 1")
        assert not f(0), "i > 1, where i= 0"
        assert not f(1), "i > 1, where i= 1"
        assert not f(-1), "i > 1, where i=-1"
        f = parser.parse("i  >  -1")
        assert f(0), "i  >  -1, where i= 0"
        assert f(1), "i  >  -1, where i= 1"
        assert not f(-1), "i  >  -1, where i=-1"

    def test_lt(self, parser) -> None:
        f = parser.parse("i<0")
        assert not f(0), "i<0, where i= 0"
        assert not f(1), "i<0, where i= 1"
        assert f(-1), "i<0, where i=-1"
        f = parser.parse("i < 1")
        assert f(0), "i < 1, where i= 0"
        assert not f(1), "i < 1, where i= 1"
        assert f(-1), "i < 1, where i=-1"
        f = parser.parse("i  <  -1")
        assert not f(0), "i  <  -1, where i= 0"
        assert not f(1), "i  <  -1, where i= 1"
        assert not f(-1), "i  <  -1, where i=-1"

    def test_ge(self, parser) -> None:
        f = parser.parse("i>=0")
        assert f(0), "i>=0, where i= 0"
        assert f(1), "i>=0, where i= 1"
        assert not f(-1), "i>=0, where i=-1"
        f = parser.parse("i >= 1")
        assert not f(0), "i >= 1, where i= 0"
        assert f(1), "i >= 1, where i= 1"
        assert not f(-1), "i >= 1, where i=-1"
        f = parser.parse("i  >=  -1")
        assert f(0), "i  >=  -1, where i= 0"
        assert f(1), "i  >=  -1, where i= 1"
        assert f(-1), "i  >=  -1, where i=-1"

    def test_le(self, parser) -> None:
        f = parser.parse("i<=0")
        assert f(0), "i<=0, where i= 0"
        assert not f(1), "i<=0, where i= 1"
        assert f(-1), "i<=0, where i=-1"
        f = parser.parse("i <= 1")
        assert f(0), "i <= 1, where i= 0"
        assert f(1), "i <= 1, where i= 1"
        assert f(-1), "i <= 1, where i=-1"
        f = parser.parse("i  <=  -1")
        assert not f(0), "i  <=  -1, where i= 0"
        assert not f(1), "i  <=  -1, where i= 1"
        assert f(-1), "i  <=  -1, where i=-1"

    def test_not_expr(self, parser) -> None:
        f = parser.parse("not i<=0")
        assert not f(0), "not i<=0, where i= 0"
        assert f(1), "not i<=0, where i= 1"
        assert not f(-1), "not i<=0, where i=-1"
        f = parser.parse("not i <= 1")
        assert not f(0), "not i <= 1, where i= 0"
        assert not f(1), "not i <= 1, where i= 1"
        assert not f(-1), "not i <= 1, where i=-1"
        f = parser.parse("not i  <=  -1")
        assert f(0), "not i  <=  -1, where i= 0"
        assert f(1), "not i  <=  -1, where i= 1"
        assert not f(-1), "not i  <=  -1, where i=-1"

    def test_and(self, parser) -> None:
        f = parser.parse("(not i<=0) and (True)")
        assert not f(0), "(not i<=0) and (True), where i= 0"
        assert f(1), "(not i<=0) and (True), where i= 1"
        assert not f(-1), "(not i<=0) and (True), where i=-1"
        f = parser.parse("(not i <= 1) and False")
        assert not f(0), "(not i <= 1) and False, where i= 0"
        assert not f(1), "(not i <= 1) and False, where i= 1"
        assert not f(-1), "(not i <= 1) and False, where i=-1"
        f = parser.parse("(not i  <=  -1) and (i<=1)")
        assert f(0), "(not i  <=  -1) and (i<=1), where i= 0"
        assert f(1), "(not i  <=  -1) and (i<=1), where i= 1"
        assert not f(-1), "(not i  <=  -1) and (i<=1), where i=-1"

    def test_or(self, parser) -> None:
        f = parser.parse("(not i<=0) or (True)")
        assert f(0), "(not i<=0) or (True), where i= 0"
        assert f(1), "(not i<=0) or (True), where i= 1"
        assert f(-1), "(not i<=0) or (True), where i=-1"
        f = parser.parse("(not i <= 1) or False")
        assert not f(0), "(not i <= 1) or False, where i= 0"
        assert not f(1), "(not i <= 1) or False, where i= 1"
        assert not f(-1), "(not i <= 1) or False, where i=-1"
        f = parser.parse("(not i  <=  -1) or (i<=1)")
        assert f(0), "(not i  <=  -1) or (i<=1), where i= 0"
        assert f(1), "(not i  <=  -1) or (i<=1), where i= 1"
        assert f(-1), "(not i  <=  -1) or (i<=1), where i=-1"

    def test_exprs(self, parser) -> None:
        f = parser.parse("i>1 or i==0")
        assert f(0), "i>1 or i==0, where i= 0"
        assert not f(1), "i>1 or i==0, where i= 1"
        assert not f(-1), "i>1 or i==0, where i=-1"
        f = parser.parse("i>1 or i==0 and i!=-1")
        assert f(0), "i>1 or i==0 and i!=-1, where i= 0"
        assert not f(1), "i>1 or i==0 and i!=-1, where i= 1"
        assert not f(-1), "i>1 or i==0 and i!=-1, where i=-1"
        f = parser.parse("i>0 and i<=1 or i==-1")
        assert not f(0), "i>0 and i<=1 or i==-1, where i= 0"
        assert f(1), "i>0 and i<=1 or i==-1, where i= 1"
        assert f(-1), "i>0 and i<=1 or i==-1, where i=-1"
