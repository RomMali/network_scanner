"""Legacy heuristic seeds. Prefer backend.logic.inspectors on the NFQUEUE path."""
from backend.logic.inspectors import inspect_dos, reset_inspectors

__all__ = ["inspect_dos", "reset_inspectors"]
