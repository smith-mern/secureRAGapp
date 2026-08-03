"""Retrieval-augmented generation chain.

Orchestrates a query end to end: validate input, retrieve scoped chunks from the
vectorstore, assemble the prompt, call Claude, filter the output, and return the
answer with its sources.

Retrieved text is data, never instructions. It is delimited in the prompt and
the system prompt states that document content cannot change the model's
directives — the model's operating rules come only from the system prompt.

Uses the Anthropic SDK with claude-opus-5.
"""
