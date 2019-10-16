def slice_graph(graph, slice_to_sink):
    """
    Slice a graph, keeping only the transitions and nodes present in the <SliceToSink> representation.

    *Note* that this function mutates the graph passed as an argument.

    :param networkx.DiGraph graph: The graph to slice.
    :param angr.analyses.slice_to_sink slice_to_sink:
        The representation of the slice, containing the data to update the CFG from.

    :return networkx.DiGraph: The sliced graph.
    """

    def _edge_in_slice_transitions(transitions, edge):
        if edge[0].addr not in transitions.keys():
            return False
        return edge[1].addr in slice_to_sink.transitions[edge[0].addr]

    original_edges = graph.edges()
    edges_to_remove = list(filter(
        lambda edge: not _edge_in_slice_transitions(slice_to_sink.transitions, edge),
        original_edges
    ))

    original_nodes = graph.nodes()
    nodes_to_remove = list(filter(
        lambda node: node.addr not in slice_to_sink.nodes,
        original_nodes
    ))

    graph.remove_edges_from(edges_to_remove)
    graph.remove_nodes_from(nodes_to_remove)

    return graph
