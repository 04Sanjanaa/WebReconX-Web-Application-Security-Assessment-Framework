from typing import List, Dict
from webreconx.core.finding import Finding

class BaseCheck:
    def __init__(self):
        pass

    def run(self, url: str, headers: Dict[str, str], body: str, mode: str = "passive") -> List[Finding]:
        """
        Executes the security check against the page metadata and contents.
        Returns a list of Finding objects.
        """
        raise NotImplementedError("Subclasses must implement run")
