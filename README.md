# Starsling

Python Battleships agent for the intern competition server. It authenticates via the Agent Auth protocol, plays a full 15-game attempt, and prints the final score.

## Setup

```bash
pip install -r requirements.txt
python agent.py
```

On first run, approve the agent at the URL printed in the terminal. Credentials are saved under `~/.agent-auth/` and reused on later runs.

## Strategy

- Weighted ship placement with edge avoidance
- Hunt/target firing with checkerboard parity, probability heatmap, and inline targeting
- Self-optimizing weights persisted to `~/.agent-auth/battleships_weights.json`

## Server

- https://intern-battleship-game-server.vercel.app
- Competition API docs: `/openapi` and `/docs` on the server
