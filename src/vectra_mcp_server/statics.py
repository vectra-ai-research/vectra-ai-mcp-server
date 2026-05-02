from enum import Enum
from typing import Optional, Literal

class DetectionCategory(Enum):
    CNC = "command"
    BOTNET = "botnet"
    RECON = "Reconnaissance"
    LATERAL = "lateral"
    EXFILTRATION = "exfiltration"
    INFO = "info"