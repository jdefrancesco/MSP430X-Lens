"""Binary Ninja plugin package for MSP430X firmware analysis.

Binary Ninja imports this package when the checkout is installed as a user
plugin. Importing the architecture first makes the mapped MSP430F5438 BinaryView
able to register its default platform during startup.
"""

from __future__ import annotations

from .msp430x_arch import register_msp430x_architecture
from .msp430f5438_memory_map import register_msp430f5438_binary_view

__all__ = (
    "register_msp430x_architecture",
    "register_msp430f5438_binary_view",
)
