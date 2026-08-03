"""Prompt injection defense.

Screens text on its way into the model's context — both the user's query and
the chunks the retriever returns. Retrieved documents are the harder case: an
attacker who can get a document indexed controls text that lands in the prompt
without ever talking to the API.

Looks for instruction-shaped content in data positions (role overrides,
"ignore previous", tool or exfiltration requests), and marks or strips it.
Detection is best effort and is not the only defense — prompt structure in
rag_chain and output filtering are the other two layers.
"""
