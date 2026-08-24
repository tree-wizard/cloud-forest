"""Claude tool loop: reads source, forms hypotheses, executes attacks.

Untrusted-data fencing lives here — tool results are wrapped and labeled before
reaching the model. Implemented in phase 4.
"""
