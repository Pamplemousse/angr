from functools import reduce

from angr.analyses.cfg.cfg_utils import CFGUtils
from angr.analyses.forward_analysis.visitors.graph import GraphVisitor


class SliceVisitor(GraphVisitor):
    """
    Visit the slice of a given graph.

    :param SliceToSink slice:
        A slice, representing a graph where all paths are leading to a sink.
    :param angr.knowledge_plugins.cfg.cfg_model.CFGModel cfg:
        The CFG represented by the slice.
    """
    def __init__(self, slice_to_visit, cfg):
        super(SliceVisitor, self).__init__()
        self._slice = slice_to_visit
        self._cfg = cfg

        self.reset()


    @property
    def cfg(self):
        return self._cfg


    def _successors(self, node):
        return self._slice.transitions.get(node.addr, [])

    def successors(self, node):
        """
        :return List[CFGNode]: The list of successors of a given node.
        """
        return reduce(
            lambda acc, addr: acc + self._cfg.get_all_nodes(addr),
            self._successors(node),
            []
        )


    def _predecessors(self, node):
        transitions_to_node = list(filter(
            lambda x: node.addr in x[1],
            self._slice.transitions.items()
        ))

        if len(transitions_to_node) == 0:
            return []

        origins, _ = zip(*transitions_to_node)
        return list(origins)

    def predecessors(self, node):
        """
        :return List[CFGNode]: The list of predecessors of a given node.
        """
        return reduce(
            lambda acc, addr: acc + self._cfg.get_all_nodes(addr),
            self._predecessors(node),
            []
        )


    def sort_nodes(self, nodes=None):
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.cfg.graph)

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes


    def remove_from_sorted_nodes(self, visited_blocks):
        """
        :param List<Block|CFGNode> visited_blocks: A list of visited blocks, to remove from the list of things to visit.

        Remove visited nodes from the iherited `_sorted_nodes` attribute.
        """

        visited_addresses = list(map(
            lambda n: n.addr,
            visited_blocks
        ))

        nodes_to_remove = list(filter(
            lambda n: n.addr in visited_addresses,
            self._sorted_nodes
        ))

        for n in nodes_to_remove:
            self._sorted_nodes.remove(n)
