"""AI gateway: provider adapters, redaction, prompt templates, structured output.

Has no action-execution capability (AI-5, threat model LLM06): no provider receives tools, and
the package may not import the connector runner, workflow worker or API (import-linter).
"""

__version__ = "0.4.0"
