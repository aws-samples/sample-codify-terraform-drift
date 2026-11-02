"""The write path: the GitHub client, the publisher, and the MCP tool surface.

The tools here run **in-process**, driven by :mod:`driftcode.agent` over a direct Bedrock
Converse call. There is no Bedrock Agent and no AgentCore Runtime in the deployed pipeline;
``server.py`` speaks the MCP protocol over stdio so it *can* be hosted, but nothing hosts it
today.

That is a deliberate position rather than an unfinished one. The security argument rests on the
verifier and the publish step being unreachable from the tool surface - ``CodifySession.complete``
is called by the orchestrator after the model's turn ends, in the same process, and no tool
exposes it. Moving the tool surface behind a network boundary means either the verification and
publication move with it, or the remote server has to call back into the orchestrator; and it
adds an authentication problem between the agent and the server that does not exist while they
share a process.

Hosting it would buy reuse across agents and a managed runtime. It would not make the boundary
stronger: the motivation is reuse, not containment, and it carries the authentication problem
above as its cost.
"""
