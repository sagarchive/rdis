"""Example tool plugin: count call edges. `rdis BIN --tool count_calls` or the MCP tool `plugin_count_calls`."""
from rdis import plugins

RDIS_API = 1


def count_calls(program, top=3):
    sizes = sorted(((len(f.calls), program.display(a) or hex(a)) for a, f in program.functions.items()), reverse=True)
    return {"functions": len(program.functions), "call_edges": sum(n for n, _ in sizes),
            "busiest": [{"function": name, "calls": n} for n, name in sizes[:top]]}


plugins.register_tool("count_calls", count_calls, "Count call edges and list the busiest callers")
