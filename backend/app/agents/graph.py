"""LangGraph wiring for the multi-agent triage pipeline.

supervisor → threat_intel → triage ─┬─(benign, confident)→ reporter → END
                                    └─(otherwise)────────→ response → reporter → END
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .nodes import AgentContext, SOCState, make_nodes


def build_graph(ctx: AgentContext):
    nodes = make_nodes(ctx)
    graph = StateGraph(SOCState)
    for name, fn in nodes.items():
        graph.add_node(name, fn)
    graph.add_edge(START, "supervisor")
    graph.add_edge("supervisor", "threat_intel")
    graph.add_edge("threat_intel", "triage")
    graph.add_conditional_edges("triage", lambda s: s["route"], {"respond": "response", "report": "reporter"})
    graph.add_edge("response", "reporter")
    graph.add_edge("reporter", END)
    return graph.compile()
