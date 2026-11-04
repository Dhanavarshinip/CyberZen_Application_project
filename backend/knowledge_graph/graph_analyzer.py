"""
Graph Analyzer & Louvain Community Clustering for CyberThreat AI (SHIELD Module 2).

Implements:
1. Provenance Graph Construction from filtered anomalous logs
2. Initial Infection Point (Socket) Identification
3. Suspicious Forward and Backward Causal Tag Propagation
4. Non-infected & Dead-end Terminal Node Pruning
5. Louvain Community Detection to cluster coordinated attack processes
"""

from typing import Dict, Any, List, Set, Tuple
import networkx as nx
from networkx.algorithms.community import louvain_communities


class GraphAnalyzer:
    """
    SHIELD Module 2: Analyzes process-object interactions, traces socket infections,
    prunes non-propagating terminal objects, and groups suspicious activities into Louvain communities.
    """

    def __init__(self):
        self.raw_graph = nx.MultiDiGraph()
        self.reduced_graph = nx.MultiDiGraph()
        self.communities: List[Set[str]] = []

    def build_provenance_graph(self, logs: List[Dict[str, Any]]) -> nx.MultiDiGraph:
        """
        Constructs a directed provenance graph G = (V, E) where:
        Nodes = processes (p_i) and objects (o_i)
        Edges = events (e_i) linking process and object
        """
        G = nx.MultiDiGraph()

        for log in logs:
            p_node = f"proc:{log.get('process_id')}:{log.get('process_name')}"
            o_node = str(log.get("object_id", ""))
            e_type = str(log.get("event_type", "EVENT"))

            G.add_node(p_node, node_type="PROCESS", name=log.get("process_name"), pid=log.get("process_id"))
            
            # Determine object node type
            if o_node.startswith("socket:"):
                obj_type = "SOCKET"
            elif o_node.startswith("file:"):
                obj_type = "FILE"
            else:
                obj_type = "ENTITY"

            G.add_node(o_node, node_type=obj_type, data=log.get("object_data"))

            # Direct edges based on causality:
            # - SOCKET_CONNECT: Socket -> Process or Process -> Socket
            # - FILE_READ / PROCESS_EXEC: File -> Process
            # - FILE_WRITE: Process -> File
            if e_type in ("SOCKET_CONNECT", "FILE_READ"):
                G.add_edge(o_node, p_node, event_type=e_type, log=log)
            elif e_type == "PROCESS_EXEC" and o_node.startswith("file:"):
                G.add_edge(o_node, p_node, event_type=e_type, log=log)
            else:
                G.add_edge(p_node, o_node, event_type=e_type, log=log)

            # Process hierarchy fork edge if parent PID exists
            ppid = log.get("parent_process_id")
            if ppid:
                for existing_node in list(G.nodes):
                    if existing_node.startswith(f"proc:{ppid}:"):
                        G.add_edge(existing_node, p_node, event_type="PROCESS_FORK", log=log)

        self.raw_graph = G
        return G

    def identify_infection_points(self, G: nx.MultiDiGraph) -> Set[str]:
        """
        Finds initial infection points (external network communication interfaces / sockets).
        """
        infection_points = set()
        for node, attrs in G.nodes(data=True):
            if attrs.get("node_type") == "SOCKET":
                # Check if socket is an external connection
                if not any(local in node for local in ["127.0.0.1", "localhost", "internal-share.local"]):
                    infection_points.add(node)
        return infection_points

    def propagate_suspicious_tags(self, G: nx.MultiDiGraph, infection_points: Set[str]) -> Set[str]:
        """
        Propagates suspicious tags along causal provenance flows from infection points.
        """
        tagged_nodes = set(infection_points)
        queue = list(infection_points)

        # Forward propagation
        while queue:
            curr = queue.pop(0)
            for neighbor in G.successors(curr):
                if neighbor not in tagged_nodes:
                    tagged_nodes.add(neighbor)
                    queue.append(neighbor)

        # Predecessor lineage propagation
        rev_queue = list(tagged_nodes)
        while rev_queue:
            curr = rev_queue.pop(0)
            for pred in G.predecessors(curr):
                if pred not in tagged_nodes:
                    tagged_nodes.add(pred)
                    rev_queue.append(pred)

        return tagged_nodes

    def prune_and_reduce_graph(self, G: nx.MultiDiGraph, tagged_nodes: Set[str]) -> nx.MultiDiGraph:
        """
        Prunes untagged nodes and dead-end terminal file nodes.
        Preserves external outbound sockets (exfiltration channels) and active processes.
        """
        subG = G.subgraph(tagged_nodes).copy()
        
        # Iteratively prune terminal file objects that have out-degree == 0
        # Preserves scripts, DLLs, and exfiltration targets
        nodes_to_remove = []
        for n, attrs in subG.nodes(data=True):
            if attrs.get("node_type") == "FILE" and subG.out_degree(n) == 0:
                n_lower = n.lower()
                if not any(ext in n_lower for ext in [".vbs", ".bat", ".dll", ".xls", ".uue", ".txt", "onedrive", "factura", "login data"]):
                    nodes_to_remove.append(n)

        subG.remove_nodes_from(nodes_to_remove)
        self.reduced_graph = subG
        return subG

    def extract_louvain_communities(self, G_reduced: nx.MultiDiGraph) -> List[List[Dict[str, Any]]]:
        """
        Applies the Louvain algorithm to partition the reduced graph into tightly interacting communities.
        Returns list of event clusters for each community.
        """
        if len(G_reduced.nodes) == 0:
            return []

        # Convert to undirected graph for Louvain modularity optimization
        undirected_G = G_reduced.to_undirected()
        
        try:
            # NetworkX built-in Louvain community detection
            communities_sets = louvain_communities(undirected_G, seed=42)
        except Exception:
            # Fallback to connected components if Louvain encounters isolated graphs
            communities_sets = list(nx.connected_components(undirected_G))

        community_events_list = []
        for comm in communities_sets:
            events_in_comm = []
            seen_eids = set()
            for u, v, data in G_reduced.edges(data=True):
                if u in comm or v in comm:
                    log_entry = data.get("log")
                    if log_entry:
                        eid = log_entry.get("event_id")
                        if eid and eid not in seen_eids:
                            seen_eids.add(eid)
                            events_in_comm.append(log_entry)
            
            if events_in_comm:
                # Sort chronologically
                events_in_comm.sort(key=lambda x: x.get("timestamp", ""))
                community_events_list.append(events_in_comm)

        return community_events_list

    def process(self, logs: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Full pipeline execution: Raw logs -> Provenance Graph -> Tag -> Prune -> Louvain Communities."""
        G = self.build_provenance_graph(logs)
        inf_points = self.identify_infection_points(G)
        
        if not inf_points:
            # If no external socket is direct ancestor, treat all flagged nodes as candidates
            tagged = set(G.nodes())
        else:
            tagged = self.propagate_suspicious_tags(G, inf_points)

        G_red = self.prune_and_reduce_graph(G, tagged)
        return self.extract_louvain_communities(G_red)
