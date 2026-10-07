import math
import numpy as np

class PreTLSEntropyEngine:
    """Calculates Pre-TLS Shannon Entropy (E_io) on raw Virtual File System buffers."""
    
    @staticmethod
    def calculate_entropy(buffer_bytes: bytes) -> float:
        if not buffer_bytes or len(buffer_bytes) == 0:
            return 0.0
        
        # Convert buffer to numpy array for fast hardware-accelerated histogram evaluation
        arr = np.frombuffer(buffer_bytes, dtype=np.uint8)
        _, counts = np.unique(arr, return_counts=True)
        
        probabilities = counts / len(arr)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        
        # Normalize entropy within range [0.0, 8.0]
        return float(entropy)

    @staticmethod
    def evaluate_vfs_risk_modifier(entropy: float) -> float:
        """
        Maps raw entropy H into normalized E_io risk term:
        - Plaintext/Admin Streams (H < 4.0) -> E_io approx 0.0 - 0.2
        - Obfuscated/Base64/C2 Streams (H > 6.0) -> E_io approx 0.6 - 1.0
        """
        if entropy < 4.0:
            return 0.05
        elif 4.0 <= entropy <= 6.0:
            return 0.35
        else: # High Entropy (Encrypted C2 / Obfuscated Shellcode)
            return 0.85
