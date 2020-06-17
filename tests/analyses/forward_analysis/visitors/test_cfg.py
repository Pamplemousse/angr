# pylint: disable=no-self-use
import os
from unittest import mock, TestCase

from claripy.utils.orderedset import OrderedSet

from angr.analyses.cfg.cfg_utils import CFGUtils
from angr.analyses.forward_analysis.visitors.cfg import CFGVisitor
from angr.knowledge_plugins.cfg.cfg_node import CFGNode
from angr.project import Project

# disabled since binaries-private is not checked out for angr CI

class TestCFGVisitor(TestCase):
    def setUp(self) -> None:
        binary_path = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', '..', 'binaries-private', 'operation-mango',
            'air-live-bu-2015', 'cgi_test.cgi'
        )
        project = Project(binary_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()

        self.printf = cfg.kb.functions.function(name='printf', plt=False)
        self.printf_node = cfg.model.get_all_nodes(self.printf.addr)[0]

    def disable_successors_of_a_node_delegate_the_logic_to_the_CFGNode_successor(self):
        with mock.patch.object(CFGVisitor, 'reset'):
            with mock.patch.object(CFGNode, 'successors', new_callable=mock.PropertyMock) as mock_successors:
                addr, size, cfg = 1, None, None
                node = CFGNode(0x42, addr, size, cfg, block_id=1)

                cfg_visitor = CFGVisitor(None)
                _ = cfg_visitor.successors(node)

                mock_successors.assert_called_once_with()

    def disable_predecessors_of_a_node_delegate_the_logic_to_the_CFGNode_predecessor(self):
        with mock.patch.object(CFGVisitor, 'reset'):
            with mock.patch.object(CFGNode, 'predecessors', new_callable=mock.PropertyMock) as mock_predecessors:
                addr, size, cfg = 1, None, None
                node = CFGNode(0x42, addr, size, cfg, block_id=1)

                cfg_visitor = CFGVisitor(None)
                _ = cfg_visitor.predecessors(node)

                mock_predecessors.assert_called_once_with()
