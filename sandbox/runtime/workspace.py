import os
from pathlib import Path

class WorkspaceAccessDeniedError(Exception):
    pass

class SafeWorkspace:
    """
    A workspace abstraction that enforces path containment.
    Prevents path traversal and absolute paths outside the agent's workspace.
    """
    def __init__(self, agent_id: str, base_dir: str):
        self.agent_id = agent_id
        # Resolve to an absolute path immediately
        self.base_dir = Path(base_dir).resolve()

        self.base_dir.mkdir(parents=True, exist_ok=True)

    def get_safe_path(self, target_path: str | Path) -> Path:
        """
        Resolves the given path and ensures it falls strictly within the base_dir.
        """
        target = Path(target_path)

        # If absolute, verify it is inside base_dir
        if target.is_absolute():
            resolved = target.resolve()
        else:
            resolved = (self.base_dir / target).resolve()

        # Check if the resolved path starts with the base directory
        try:
            resolved.relative_to(self.base_dir)
        except ValueError:
            raise WorkspaceAccessDeniedError(
                f"Agent '{self.agent_id}' attempted to access outside its workspace: {target_path}"
            )

        return resolved

    def read_text(self, filename: str | Path, encoding: str = "utf-8") -> str:
        safe_path = self.get_safe_path(filename)
        if not safe_path.exists():
            raise FileNotFoundError(f"File not found: {filename}")
        if not safe_path.is_file():
            raise ValueError(f"Not a file: {filename}")
        return safe_path.read_text(encoding=encoding)

    def write_text(self, filename: str | Path, content: str, encoding: str = "utf-8") -> Path:
        safe_path = self.get_safe_path(filename)
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        safe_path.write_text(content, encoding=encoding)
        return safe_path
