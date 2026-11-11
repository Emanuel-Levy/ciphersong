"""
Alias de compatibilidade para LiveMicrophoneService.
Permite importação direta de ciphersong.services.microphone ou ciphersong.services.microphone_stream.
"""

from __future__ import annotations

from ciphersong.services.microphone_stream import AudioInputDevice, LiveMicrophoneService

__all__ = ["AudioInputDevice", "LiveMicrophoneService"]
