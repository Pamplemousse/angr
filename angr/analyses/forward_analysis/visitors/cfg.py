from typing import List, Union

from angr.analyses.cfg.cfg_utils import CFGUtils
from angr.analyses.forward_analysis.visitors.graph import GraphVisitor
from angr.block import Block
from angr.knowledge_plugins.cfg import CFGModel, CFGNode


class CFGVisitor(GraphVisitor):
    """
    Visit a given Control Flow Graph.
    """
    def __init__(self, cfg: CFGModel):
        """
        :param cfg: The CFG to visit.
        """
        super(CFGVisitor, self).__init__()
        self._cfg = cfg
        self.reset()

    @property
    def cfg(self):
        return self._cfg

    def successors(self, node) -> List[CFGNode]:
        """
        :return: The list of successors of a given node.
        """
        return node.successors

    def predecessors(self, node) -> List[CFGNode]:
        """
        :return: The list of predecessors of a given node.
        """
        return node.predecessors

    def sort_nodes(self, nodes=None) -> List[CFGNode]:
        """
        Get "top-level" nodes to start the recursive analysis from.
        """
        sorted_nodes = list(filter(
            lambda n: self._cfg.graph.in_degree(n) == 0,
            self._cfg.graph.nodes()
        ))

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes

    def revisit_successors(self, _, include_self=True):
        """
        A <ForwardAnalysis> on a CFG happen recursively:
        * The top-level analysis (for which this class is used) should not forcefully revisit any nodes;
        * The children analyses will use <Function> visitors that will revisit as they please.
        """
        pass
