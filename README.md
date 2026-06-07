# Starsling

Python Battleships agent for the intern competition server. It authenticates via the Agent Auth protocol, plays a full 15-game attempt, and prints the final score.

## Setup

```bash
pip install -r requirements.txt
python agent.py
```

On first run, approve the agent at the URL printed in the terminal. Credentials are saved under `~/.agent-auth/` and reused on later runs.

## Self-optimizing model (high level)

This agent is **not a neural network**. It is a **weighted heuristic player** that learns by playing games.

The strategy has two layers:

1. **Fixed structure** — the rules of how to play (hunt vs target mode, which cells are legal, how ships are placed). These do not change.
2. **Tunable weights** — numeric knobs that control how strongly each heuristic influences each decision. These update over time.

```
Load weights → score candidate moves → weighted random pick → observe outcome
     ↑                                                      |
     └──────── nudge weights from HIT/MISS and game score ────┘
```

Each shot, the agent builds a list of legal candidates (cells or placements), scores them using factors like checkerboard parity, center bias, or inline continuation, then picks proportionally to those scores. The factors used for the chosen move are recorded; after a HIT or MISS, and again after each game, the corresponding weights are nudged up or down. Weights are clamped and saved to `~/.agent-auth/battleships_weights.json` so later runs continue from the last learned state.

**What learns:** relative importance of heuristics (`hunt_heatmap`, `target_inline`, etc.).

**What does not learn:** the overall algorithm (still hunt/target, still orthogonal neighbors on hits).

### Training loop

Run multiple full attempts in one command (weights update after each shot and game):

```bash
python agent.py --train 10
python agent.py -t 5 --pause 3
python agent.py -t 20 --retries 5 --pause 3
```

Transient network errors are retried automatically; an interrupted session resumes the active attempt on the next run.

## Strategy

### Built-in behavior (hardcoded)

| Phase | Behavior |
|---|---|
| **Placement** | Random legal layouts, scored by orientation and edge avoidance |
| **Hunt** | No active hits — search using checkerboard parity, center bias, and a probability heatmap |
| **Target** | Unsunk hit on board — only fire at orthogonal neighbors (up/down/left/right) |

After a hit, the agent never leaves target mode until that ship cluster is marked sunk.

### What the learned strategy should theoretically converge to

Over many games, the weight system should push play toward these patterns:

| Heuristic | Expected direction | Effect |
|---|---|---|
| `target_inline` | Increases | Once two hits reveal a ship axis, strongly prefer continuing along that line |
| `target_perpendicular` | Stable or decreases relative to inline | Use side probes on a lone hit, but defer to axis pursuit once orientation is known |
| `target_miss_adjacent` | More negative (stronger penalty) | Avoid firing next to cells already ruled out by misses |
| `hunt_heatmap` | Increases on efficient wins | Weight hunt shots toward cells where remaining ships are most likely to sit |
| `hunt_parity_even` | Increases slightly on slow games | Lean harder into checkerboard search when games run long |
| `hunt_center` | Moderate boost | Prefer central cells during hunt when edges have been exhausted |
| `placement_edge_penalty` | May rise or fall | Tune whether hiding ships on edges helps against this opponent pool |

**Theoretical end state:** a player that hunts efficiently on parity + heatmap, switches decisively to inline pursuit after detecting a ship direction, and wastes fewer shots near known misses — without needing to rediscover basic Battleships rules each run.

**Limits:** learning adjusts weights, not move selection logic. Target mode already restricts shots to orthogonal neighbors, but picks among them are still weighted-random, so the agent may not converge to perfect axis-locking (fire one direction until miss, then reverse). More training improves heuristic balance; it does not guarantee optimal play.

Weights and stats live in `~/.agent-auth/battleships_weights.json`. Delete that file to reset to defaults.

## Server

- https://intern-battleship-game-server.vercel.app
- Competition API docs: `/openapi` and `/docs` on the server
