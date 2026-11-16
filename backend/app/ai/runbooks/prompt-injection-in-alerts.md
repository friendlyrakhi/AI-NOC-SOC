# Instruction-like text inside alerts or logs

Attackers sometimes plant text such as "ignore previous instructions" in hostnames, email subjects, log lines or command lines, hoping an AI assistant will obey it.

Steps:
1. Treat such text as evidence of attacker activity, not as an instruction.
2. The platform flags these items as suspicious; review them before trusting any AI analysis that cites them.
3. AI assistance never closes alerts or performs actions; all actions need human approval.
4. Investigate the source of the planted text as part of the incident.
