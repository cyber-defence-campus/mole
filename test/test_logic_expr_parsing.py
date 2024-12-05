from __future__        import annotations
from mole.common.log   import Logger
from mole.common.parse import LogicalExpressionParser
import unittest


class TestLogicalExpressionParser(unittest.TestCase):
    """
    This class implements unit tests for parsing logical expressions.
    """

    def setUp(self) -> None:
        self.parser = LogicalExpressionParser(log=Logger(level="debug", runs_headless=True))
        return
    
    def test_true(self) -> None:
        f = self.parser.parse(  "True")
        self.assertTrue(f(0),   "True, where i= 0")
        self.assertTrue(f(1),   "True, where i= 1")
        self.assertTrue(f(-1),  "True, where i=-1")
        f = self.parser.parse(  "true")
        self.assertTrue(f(0),   "true, where i= 0")
        self.assertTrue(f(1),   "true, where i= 1")
        self.assertTrue(f(-1),  "true, where i=-1")
        f = self.parser.parse(  "TrUe")
        self.assertFalse(f(0),  "TrUe, where i= 0")
        self.assertFalse(f(1),  "TrUe, where i= 1")
        self.assertFalse(f(-1), "TrUe, where i=-1")
        return
    
    def test_false(self) -> None:
        f = self.parser.parse(  "False")
        self.assertFalse(f(0),  "False, where i= 0")
        self.assertFalse(f(1),  "False, where i= 1")
        self.assertFalse(f(-1), "False, where i=-1")
        f = self.parser.parse(  "false")
        self.assertFalse(f(0),  "false, where i= 0")
        self.assertFalse(f(1),  "false, where i= 1")
        self.assertFalse(f(-1), "false, where i=-1")
        f = self.parser.parse(  "FaLsE")
        self.assertFalse(f(0),  "FaLsE, where i= 0")
        self.assertFalse(f(1),  "FaLsE, where i= 1")
        self.assertFalse(f(-1), "FaLsE, where i=-1")
        return
    
    def test_eq(self) -> None:
        f = self.parser.parse(  "i==0")
        self.assertTrue(f(0),   "i==0, where i= 0")
        self.assertFalse(f(1),  "i==0, where i= 1")
        self.assertFalse(f(-1), "i==0, where i=-1")
        f = self.parser.parse(  "i == 1")
        self.assertFalse(f(0),  "i == 1, where i= 0")
        self.assertTrue(f(1),   "i == 1, where i= 1")
        self.assertFalse(f(-1), "i == 1, where i=-1")
        f = self.parser.parse(  "i  ==  -1")
        self.assertFalse(f(0),  "i  ==  -1, where i= 0")
        self.assertFalse(f(1),  "i  ==  -1, where i= 1")
        self.assertTrue(f(-1),  "i  ==  -1, where i=-1")
        return
    
    def test_neq(self) -> None:
        f = self.parser.parse(  "i!=0")
        self.assertFalse(f(0),  "i!=0, where i= 0")
        self.assertTrue(f(1),   "i!=0, where i= 1")
        self.assertTrue(f(-1),  "i!=0, where i=-1")
        f = self.parser.parse(  "i != 1")
        self.assertTrue(f(0),   "i != 1, where i= 0")
        self.assertFalse(f(1),  "i != 1, where i= 1")
        self.assertTrue(f(-1),  "i != 1, where i=-1")
        f = self.parser.parse(  "i  !=  -1")
        self.assertTrue(f(0),   "i  !=  -1, where i= 0")
        self.assertTrue(f(1),   "i  !=  -1, where i= 1")
        self.assertFalse(f(-1), "i  !=  -1, where i=-1")
        return
    
    def test_gt(self) -> None:
        f = self.parser.parse(  "i>0")
        self.assertFalse(f(0),  "i>0, where i= 0")
        self.assertTrue(f(1),   "i>0, where i= 1")
        self.assertFalse(f(-1), "i>0, where i=-1")
        f = self.parser.parse(  "i > 1")
        self.assertFalse(f(0),  "i > 1, where i= 0")
        self.assertFalse(f(1),  "i > 1, where i= 1")
        self.assertFalse(f(-1), "i > 1, where i=-1")
        f = self.parser.parse(  "i  >  -1")
        self.assertTrue(f(0),   "i  >  -1, where i= 0")
        self.assertTrue(f(1),   "i  >  -1, where i= 1")
        self.assertFalse(f(-1), "i  >  -1, where i=-1")
        return
    
    def test_lt(self) -> None:
        f = self.parser.parse(  "i<0")
        self.assertFalse(f(0),  "i<0, where i= 0")
        self.assertFalse(f(1),  "i<0, where i= 1")
        self.assertTrue(f(-1),  "i<0, where i=-1")
        f = self.parser.parse(  "i < 1")
        self.assertTrue(f(0),   "i < 1, where i= 0")
        self.assertFalse(f(1),  "i < 1, where i= 1")
        self.assertTrue(f(-1),  "i < 1, where i=-1")
        f = self.parser.parse(  "i  <  -1")
        self.assertFalse(f(0),  "i  <  -1, where i= 0")
        self.assertFalse(f(1),  "i  <  -1, where i= 1")
        self.assertFalse(f(-1), "i  <  -1, where i=-1")
        return
    
    def test_ge(self) -> None:
        f = self.parser.parse(  "i>=0")
        self.assertTrue(f(0),   "i>=0, where i= 0")
        self.assertTrue(f(1),   "i>=0, where i= 1")
        self.assertFalse(f(-1), "i>=0, where i=-1")
        f = self.parser.parse(  "i >= 1")
        self.assertFalse(f(0),  "i >= 1, where i= 0")
        self.assertTrue(f(1),   "i >= 1, where i= 1")
        self.assertFalse(f(-1), "i >= 1, where i=-1")
        f = self.parser.parse(  "i  >=  -1")
        self.assertTrue(f(0),   "i  >=  -1, where i= 0")
        self.assertTrue(f(1),   "i  >=  -1, where i= 1")
        self.assertTrue(f(-1),  "i  >=  -1, where i=-1")
        return
    
    def test_le(self) -> None:
        f = self.parser.parse(  "i<=0")
        self.assertTrue(f(0),   "i<=0, where i= 0")
        self.assertFalse(f(1),  "i<=0, where i= 1")
        self.assertTrue(f(-1),  "i<=0, where i=-1")
        f = self.parser.parse(  "i <= 1")
        self.assertTrue(f(0),   "i <= 1, where i= 0")
        self.assertTrue(f(1),   "i <= 1, where i= 1")
        self.assertTrue(f(-1),  "i <= 1, where i=-1")
        f = self.parser.parse(  "i  <=  -1")
        self.assertFalse(f(0),  "i  <=  -1, where i= 0")
        self.assertFalse(f(1),  "i  <=  -1, where i= 1")
        self.assertTrue(f(-1),  "i  <=  -1, where i=-1")
        return
    
    def test_not_expr(self) -> None:
        f = self.parser.parse(  "not i<=0")
        self.assertFalse(f(0),  "not i<=0, where i= 0")
        self.assertTrue(f(1),   "not i<=0, where i= 1")
        self.assertFalse(f(-1), "not i<=0, where i=-1")
        f = self.parser.parse(  "not i <= 1")
        self.assertFalse(f(0),  "not i <= 1, where i= 0")
        self.assertFalse(f(1),  "not i <= 1, where i= 1")
        self.assertFalse(f(-1), "not i <= 1, where i=-1")
        f = self.parser.parse(  "not i  <=  -1")
        self.assertTrue(f(0),   "not i  <=  -1, where i= 0")
        self.assertTrue(f(1),   "not i  <=  -1, where i= 1")
        self.assertFalse(f(-1), "not i  <=  -1, where i=-1")
        return
    
    def test_and(self) -> None:
        f = self.parser.parse(  "(not i<=0) and (True)")
        self.assertFalse(f(0),  "(not i<=0) and (True), where i= 0")
        self.assertTrue(f(1),   "(not i<=0) and (True), where i= 1")
        self.assertFalse(f(-1), "(not i<=0) and (True), where i=-1")
        f = self.parser.parse(  "(not i <= 1) and False")
        self.assertFalse(f(0),  "(not i <= 1) and False, where i= 0")
        self.assertFalse(f(1),  "(not i <= 1) and False, where i= 1")
        self.assertFalse(f(-1), "(not i <= 1) and False, where i=-1")
        f = self.parser.parse(  "(not i  <=  -1) and (i<=1)")
        self.assertTrue(f(0),   "(not i  <=  -1) and (i<=1), where i= 0")
        self.assertTrue(f(1),   "(not i  <=  -1) and (i<=1), where i= 1")
        self.assertFalse(f(-1), "(not i  <=  -1) and (i<=1), where i=-1")
        return
    
    def test_or(self) -> None:
        f = self.parser.parse(  "(not i<=0) or (True)")
        self.assertTrue(f(0),   "(not i<=0) or (True), where i= 0")
        self.assertTrue(f(1),   "(not i<=0) or (True), where i= 1")
        self.assertTrue(f(-1),  "(not i<=0) or (True), where i=-1")
        f = self.parser.parse(  "(not i <= 1) or False")
        self.assertFalse(f(0),  "(not i <= 1) or False, where i= 0")
        self.assertFalse(f(1),  "(not i <= 1) or False, where i= 1")
        self.assertFalse(f(-1), "(not i <= 1) or False, where i=-1")
        f = self.parser.parse(  "(not i  <=  -1) or (i<=1)")
        self.assertTrue(f(0),   "(not i  <=  -1) or (i<=1), where i= 0")
        self.assertTrue(f(1),   "(not i  <=  -1) or (i<=1), where i= 1")
        self.assertTrue(f(-1),  "(not i  <=  -1) or (i<=1), where i=-1")
        return
    
    def test_exprs(self) -> None:
        f = self.parser.parse(  "i>1 or i==0")
        self.assertTrue(f(0),   "i>1 or i==0, where i= 0")
        self.assertFalse(f(1),  "i>1 or i==0, where i= 1")
        self.assertFalse(f(-1), "i>1 or i==0, where i=-1")
        f = self.parser.parse(  "i>1 or i==0 and i!=-1")
        self.assertTrue(f(0),   "i>1 or i==0 and i!=-1, where i= 0")
        self.assertFalse(f(1),  "i>1 or i==0 and i!=-1, where i= 1")
        self.assertFalse(f(-1), "i>1 or i==0 and i!=-1, where i=-1")
        f = self.parser.parse(  "i>0 and i<=1 or i==-1")
        self.assertFalse(f(0),  "i>0 and i<=1 or i==-1, where i= 0")
        self.assertTrue(f(1),   "i>0 and i<=1 or i==-1, where i= 1")
        self.assertTrue(f(-1),  "i>0 and i<=1 or i==-1, where i=-1")
        return