#!/usr/bin/env python3
"""
Battleships agent — plays a full competition attempt against the server.

Auth: implements the Agent Auth protocol (§ device-flow connect + per-request
agent JWT) directly in Python using PyJWT + cryptography.  No dependency on the
@auth/agent-cli binary, but follows the identical wire protocol.

Strategy: weighted hunt/target firing and ship placement. Weights are persisted
and updated after each shot and game so the agent self-optimizes over time.
"""

import base64
import hashlib
import json
import math
import random
import time
import uuid
import webbrowser
from copy import deepcopy
from pathlib import Path

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

# ─── Config ───────────────────────────────────────────────────────────────────

SERVER = "https://intern-battleship-game-server.vercel.app"
COMP   = "295cccc9137b5335cc581d67d655d6fa3b41dac6610dad0e7ed201625523ad8c"
BASE   = f"{SERVER}/competitions/{COMP}"
ISSUER = f"{SERVER}/api/auth"   # Better Auth issuer (audience for host JWTs)

CAPABILITIES = [
    "getCompetitionRules",
    "createAttempt",
    "getCurrentAttempt",
    "placeShips",
    "submitShot",
    "abandonAttempt",
]

FLEET = [
    ("CARRIER",    5),
    ("BATTLESHIP", 4),
    ("CRUISER",    3),
    ("SUBMARINE",  3),
    ("DESTROYER",  2),
]

# Persisted state file (host keypair + agent keypair + agent_id)
CREDS_FILE = Path.home() / ".agent-auth" / "battleships_creds.json"
WEIGHTS_FILE = Path.home() / ".agent-auth" / "battleships_weights.json"

# Tunable strategy weights (defaults chosen from standard Battleships heuristics).
DEFAULT_WEIGHTS: dict[str, float] = {
    # Hunt: checkerboard parity + center bias + placement-probability heatmap.
    "hunt_parity_even": 1.0,
    "hunt_parity_odd": 0.2,
    "hunt_center": 0.18,
    "hunt_heatmap": 1.2,
    # Target: prefer continuing a detected ship axis over blind neighbors.
    "target_inline": 2.8,
    "target_perpendicular": 1.0,
    "target_miss_adjacent": -0.9,
    # Placement: slight edge avoidance; balanced orientation.
    "placement_horizontal": 1.0,
    "placement_vertical": 1.0,
    "placement_edge_penalty": 0.45,
    # Optimizer meta-parameters.
    "learning_rate": 0.06,
    "min_weight": 0.05,
    "max_weight": 5.0,
}

TUNABLE_KEYS = [k for k in DEFAULT_WEIGHTS if not k.startswith("learning") and k != "min_weight" and k != "max_weight"]


# ─── Crypto helpers ───────────────────────────────────────────────────────────

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _generate_keypair() -> dict:
    """Generate an Ed25519 keypair; return as {publicKey: JWK, privateKey: JWK}."""
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes  = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    x   = _b64url(pub_bytes)
    d   = _b64url(priv_bytes)
    kid = _jwk_thumbprint(x)

    return {
        "publicKey":  {"crv": "Ed25519", "x": x, "kty": "OKP", "kid": kid},
        "privateKey": {"crv": "Ed25519", "x": x, "d": d, "kty": "OKP", "kid": kid},
    }


def _jwk_thumbprint(x: str) -> str:
    """SHA-256 JWK thumbprint for an Ed25519 key (RFC 7638)."""
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x},
        separators=(",", ":"), sort_keys=True,
    )
    return _b64url(hashlib.sha256(canonical.encode()).digest())


def _load_private_key(jwk_priv: dict) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a JWK dict."""
    d_bytes = base64.urlsafe_b64decode(jwk_priv["d"] + "==")
    return Ed25519PrivateKey.from_private_bytes(d_bytes)


def _sign_host_jwt(host_kp: dict, agent_pub_jwk: dict | None = None) -> str:
    """Sign a host+jwt for the Agent Auth registration or polling."""
    kid = host_kp["publicKey"]["kid"]
    now = int(time.time()) - 30   # 30-s back-dated iat to absorb server clock skew

    claims: dict = {
        "host_public_key": host_kp["publicKey"],
        "iss": kid,
        "sub": kid,
        "aud": ISSUER,
        "iat": now,
        "exp": now + 600,          # 10-minute lifetime
        "jti": str(uuid.uuid4()),
    }
    if agent_pub_jwk is not None:
        claims["agent_public_key"] = agent_pub_jwk

    priv = _load_private_key(host_kp["privateKey"])
    return jwt.encode(
        claims, priv,
        algorithm="EdDSA",
        headers={"typ": "host+jwt", "kid": kid},
    )


def _sign_agent_jwt(agent_kp: dict, agent_id: str, caps: list[str]) -> str:
    """Mint a fresh single-use agent+jwt for API calls."""
    kid = agent_kp["publicKey"]["kid"]
    # Back-date iat by 30 s so the server (whose clock is slightly ahead) never
    # sees a token with iat in the future and rejects it.
    now = int(time.time()) - 30
    priv = _load_private_key(agent_kp["privateKey"])
    return jwt.encode(
        {
            "capabilities": caps,
            "sub": agent_id,
            "aud": ISSUER,
            "iat": now,
            "exp": now + 600,   # 10-minute window to cover the backdate
            "jti": str(uuid.uuid4()),
        },
        priv,
        algorithm="EdDSA",
        headers={"typ": "agent+jwt", "kid": kid},
    )


# ─── Agent auth (device-flow) ─────────────────────────────────────────────────

def _register_agent(host_kp: dict, agent_kp: dict) -> dict:
    """POST to the register endpoint; returns the server's registration body."""
    host_jwt = _sign_host_jwt(host_kp, agent_pub_jwk=agent_kp["publicKey"])
    resp = requests.post(
        f"{ISSUER}/agent/register",
        headers={
            "Authorization": f"Bearer {host_jwt}",
            "Content-Type":  "application/json",
        },
        json={
            "name":         "battleships-agent",
            "mode":         "delegated",
            "capabilities": CAPABILITIES,
        },
    )
    if not resp.ok:
        raise RuntimeError(f"register failed {resp.status_code}: {resp.text}")
    return resp.json()


def _poll_status(host_kp: dict, agent_id: str, interval: int = 5, expires_in: int = 300) -> dict:
    """Poll the status endpoint until the agent is active/approved."""
    deadline = time.time() + expires_in
    print(f"Polling for approval (up to {expires_in}s)...")
    while time.time() < deadline:
        time.sleep(interval)
        host_jwt = _sign_host_jwt(host_kp)
        resp = requests.get(
            f"{ISSUER}/agent/status",
            params={"agent_id": agent_id},
            headers={"Authorization": f"Bearer {host_jwt}"},
        )
        if not resp.ok:
            continue
        status = resp.json()
        s = status.get("status", "")
        print(f"  Status: {s}")
        if s in ("active", "claimed"):
            return status
        if s in ("rejected", "revoked"):
            raise RuntimeError(f"Agent was {s} during approval.")
    raise RuntimeError("Approval timed out.")


def get_or_create_agent() -> tuple[dict, dict, str]:
    """
    Return (host_keypair, agent_keypair, agent_id).
    On first run: executes the device-flow (shows the URL, polls), saves creds.
    On subsequent runs: loads creds from disk.
    """
    if CREDS_FILE.exists():
        creds = json.loads(CREDS_FILE.read_text())
        print(f"Using saved agent: {creds['agentId']}")
        return creds["hostKeypair"], creds["agentKeypair"], creds["agentId"]

    print("No saved agent. Starting device-flow registration...\n")
    host_kp  = _generate_keypair()
    agent_kp = _generate_keypair()

    reg = _register_agent(host_kp, agent_kp)
    agent_id = reg["agent_id"]

    approval = reg.get("approval", {})
    url      = approval.get("verification_uri_complete") or approval.get("verification_uri", "")
    interval = approval.get("interval", 5)
    expires  = approval.get("expires_in", 300)

    print(f"Agent ID:  {agent_id}")
    print(f"\nApprove this agent by visiting:\n  {url}\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass

    _poll_status(host_kp, agent_id, interval=interval, expires_in=expires)
    print("Agent approved!\n")

    CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    CREDS_FILE.write_text(json.dumps({
        "agentId":    agent_id,
        "hostKeypair":  host_kp,
        "agentKeypair": agent_kp,
    }, indent=2))
    print(f"Credentials saved to {CREDS_FILE}")
    return host_kp, agent_kp, agent_id


# ─── REST helpers ─────────────────────────────────────────────────────────────

def api(method: str, path: str, agent_kp: dict, agent_id: str, body=None) -> dict:
    """Authenticated request with a fresh agent JWT; returns parsed JSON."""
    token   = _sign_agent_jwt(agent_kp, agent_id, CAPABILITIES)
    url     = f"{BASE}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"

    resp = getattr(requests, method)(url, headers=headers, json=body)

    if not resp.ok:
        try:
            err = resp.json()
        except Exception:
            err = resp.text
        print(f"  HTTP {resp.status_code} {method.upper()} {path}: {err}")
        resp.raise_for_status()

    return resp.json()


# ─── Self-optimizing weights ──────────────────────────────────────────────────

class StrategyOptimizer:
    """Loads, applies, and learns tunable strategy weights across runs."""

    def __init__(self, path: Path = WEIGHTS_FILE):
        self.path = path
        self.weights = self._load()
        self.stats = self.weights.pop("_stats", {
            "games": 0,
            "wins": 0,
            "total_shots": 0,
            "total_score": 0.0,
        })
        self._last_pick: dict | None = None
        self._game_shots = 0

    def _load(self) -> dict[str, float]:
        merged = deepcopy(DEFAULT_WEIGHTS)
        if self.path.exists():
            try:
                stored = json.loads(self.path.read_text())
                for key in TUNABLE_KEYS:
                    if key in stored:
                        merged[key] = float(stored[key])
                if "_stats" in stored:
                    merged["_stats"] = stored["_stats"]
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        return merged

    def save(self) -> None:
        payload = {k: round(self.weights[k], 4) for k in TUNABLE_KEYS}
        payload["_stats"] = self.stats
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2))

    def _clamp(self, key: str, value: float) -> float:
        lo = self.weights["min_weight"]
        hi = self.weights["max_weight"]
        return max(lo, min(hi, value))

    def nudge(self, key: str, delta: float) -> None:
        if key not in TUNABLE_KEYS:
            return
        self.weights[key] = self._clamp(key, self.weights[key] + delta)

    def record_pick(self, row: int, col: int, factors: dict[str, float], mode: str) -> None:
        self._last_pick = {"row": row, "col": col, "factors": factors, "mode": mode}

    def learn_from_shot(self, outcome: str) -> None:
        lr = self.weights["learning_rate"] * 0.35
        pick = self._last_pick
        if not pick:
            return
        reward = 1.0 if outcome == "HIT" else -0.35
        for key, strength in pick["factors"].items():
            if strength == 0 or key not in TUNABLE_KEYS:
                continue
            self.nudge(key, lr * reward * strength)
        if pick["mode"] == "target" and outcome == "MISS":
            self.nudge("target_miss_adjacent", lr * 0.5)

    def begin_game(self) -> None:
        self._game_shots = 0

    def record_shot(self) -> None:
        self._game_shots += 1
        self.stats["total_shots"] = self.stats.get("total_shots", 0) + 1

    def learn_from_game(self, outcome: str, score_delta: float | int | str) -> None:
        self.stats["games"] = self.stats.get("games", 0) + 1
        try:
            score = float(score_delta)
        except (TypeError, ValueError):
            score = 0.0
        self.stats["total_score"] = self.stats.get("total_score", 0.0) + score

        won = str(outcome).upper() in ("WIN", "VICTORY", "SUNK_ALL", "COMPLETED")
        if won:
            self.stats["wins"] = self.stats.get("wins", 0) + 1

        shots = max(self._game_shots, 1)
        # Fewer shots and higher score => stronger positive reinforcement.
        efficiency = max(0.0, min(1.0, (100.0 - shots) / 80.0))
        score_norm = max(-1.0, min(1.0, score / 20.0))
        game_reward = 0.55 * efficiency + 0.45 * score_norm
        if not won:
            game_reward -= 0.25

        lr = self.weights["learning_rate"]
        pick = self._last_pick
        if pick:
            for key, strength in pick["factors"].items():
                if strength == 0 or key not in TUNABLE_KEYS:
                    continue
                self.nudge(key, lr * game_reward * strength * 0.4)

        if won and shots <= 45:
            self.nudge("hunt_heatmap", lr * 0.3)
            self.nudge("target_inline", lr * 0.2)
        elif shots >= 70:
            self.nudge("hunt_center", lr * 0.15)
            self.nudge("hunt_parity_even", lr * 0.1)

        self.save()

    def summary(self) -> str:
        games = self.stats.get("games", 0)
        wins = self.stats.get("wins", 0)
        avg_shots = self.stats.get("total_shots", 0) / max(games, 1)
        return (
            f"weights games={games} wins={wins} avg_shots={avg_shots:.1f} "
            f"heatmap={self.weights['hunt_heatmap']:.2f} "
            f"inline={self.weights['target_inline']:.2f}"
        )


def _weighted_choice(candidates: list[tuple], optimizer: StrategyOptimizer) -> tuple:
    """Pick (row, col, factors) from scored candidates."""
    if not candidates:
        raise ValueError("no candidates")
    if len(candidates) == 1:
        row, col, factors = candidates[0]
        optimizer.record_pick(
            row, col, factors,
            "target" if "target_inline" in factors or "target_perpendicular" in factors else "hunt",
        )
        return row, col, factors

    scored = [(row, col, factors, sum(factors.values())) for row, col, factors in candidates]
    max_score = max(s for *_, s in scored)
    min_score = min(s for *_, s in scored)
    weights = []
    for *_, total in scored:
        if max_score == min_score:
            weights.append(1.0)
        else:
            weights.append(max(0.01, total - min_score + 0.01))

    chosen = random.choices(scored, weights=weights, k=1)[0]
    row, col, factors, _ = chosen
    optimizer.record_pick(row, col, factors, "target" if "target_inline" in factors or "target_perpendicular" in factors else "hunt")
    return row, col, factors


def _center_bonus(row: int, col: int, rows: int, cols: int, weight: float) -> float:
    cr, cc = (rows - 1) / 2.0, (cols - 1) / 2.0
    max_dist = math.hypot(cr, cc) or 1.0
    dist = math.hypot(row - cr, col - cc)
    return weight * (1.0 - dist / max_dist)


def _shot_board(shots_data: list[dict]) -> tuple[set[tuple], set[tuple], dict[tuple, str | None], set[int]]:
    hits: dict[tuple, str | None] = {}
    misses: set[tuple] = set()
    shot_positions: set[tuple] = set()
    sunk_lengths: set[int] = set()

    for s in shots_data:
        pos = (int(s["row"]), int(s["col"]))
        shot_positions.add(pos)
        if s["outcome"] == "HIT":
            hits[pos] = s.get("sunkShipClass")
            sunk_cls = s.get("sunkShipClass")
            if sunk_cls:
                for ship_class, length in FLEET:
                    if ship_class == sunk_cls:
                        sunk_lengths.add(length)
        else:
            misses.add(pos)

    return shot_positions, misses, hits, sunk_lengths


# ─── Ship placement ───────────────────────────────────────────────────────────

def place_fleet_weighted(optimizer: StrategyOptimizer, rows: int = 10, cols: int = 10) -> list[dict]:
    """Place fleet using weighted random valid positions (fast, per-ship)."""
    w = optimizer.weights

    def edge_penalty(cells: list[tuple]) -> float:
        return sum(w["placement_edge_penalty"] for r, c in cells if r in (0, rows - 1) or c in (0, cols - 1))

    while True:
        placements: list[dict] = []
        occupied: set[tuple] = set()
        ok = True

        for ship_class, length in FLEET:
            options: list[tuple[float, dict]] = []
            for orientation in ("HORIZONTAL", "VERTICAL"):
                orient_w = w["placement_horizontal"] if orientation == "HORIZONTAL" else w["placement_vertical"]
                if orientation == "HORIZONTAL":
                    positions = ((sr, sc) for sr in range(rows) for sc in range(cols - length + 1))
                    cells_fn = lambda sr, sc, ln=length: [(sr, sc + i) for i in range(ln)]
                else:
                    positions = ((sr, sc) for sr in range(rows - length + 1) for sc in range(cols))
                    cells_fn = lambda sr, sc, ln=length: [(sr + i, sc) for i in range(ln)]

                for sr, sc in positions:
                    cells = cells_fn(sr, sc)
                    if any(c in occupied for c in cells):
                        continue
                    score = orient_w - edge_penalty(cells)
                    options.append((score, {
                        "shipClass": ship_class,
                        "orientation": orientation,
                        "startRow": sr,
                        "startCol": sc,
                    }))

            if not options:
                ok = False
                break

            weights = [max(s, 0.01) for s, _ in options]
            _, placement = random.choices(options, weights=weights, k=1)[0]
            sr, sc = placement["startRow"], placement["startCol"]
            if placement["orientation"] == "HORIZONTAL":
                occupied.update((sr, sc + i) for i in range(length))
            else:
                occupied.update((sr + i, sc) for i in range(length))
            placements.append(placement)

        if ok:
            return placements


# ─── Firing strategy ──────────────────────────────────────────────────────────

def _connected_hit_cluster(all_hits: dict, start: tuple) -> set[tuple]:
    """BFS from `start` through adjacent hit cells."""
    visited: set[tuple] = {start}
    queue = [start]
    while queue:
        r, c = queue.pop(0)
        for dr, dc in ((-1, 0), (1, 0), (0, -1), (0, 1)):
            nb = (r + dr, c + dc)
            if nb in all_hits and nb not in visited:
                visited.add(nb)
                queue.append(nb)
    return visited


def _cluster_axis(cluster: set[tuple]) -> str | None:
    if len(cluster) < 2:
        return None
    rows = {r for r, _ in cluster}
    cols = {c for _, c in cluster}
    if len(rows) == 1:
        return "HORIZONTAL"
    if len(cols) == 1:
        return "VERTICAL"
    return None


def _heatmap_with_constraints(
    rows: int,
    cols: int,
    shot_positions: set[tuple],
    hits: dict[tuple, str | None],
    sunk_lengths: set[int],
    heatmap_weight: float,
) -> dict[tuple, float]:
    remaining = [length for _, length in FLEET if length not in sunk_lengths]
    scores: dict[tuple, float] = {}

    for length in remaining:
        for orientation in ("HORIZONTAL", "VERTICAL"):
            for sr in range(rows):
                for sc in range(cols):
                    if orientation == "HORIZONTAL":
                        if sc + length > cols:
                            continue
                        cells = [(sr, sc + i) for i in range(length)]
                    else:
                        if sr + length > rows:
                            continue
                        cells = [(sr + i, sc) for i in range(length)]

                    # Placement must cover all hits in any active cluster and avoid misses.
                    valid = True
                    for pos, outcome in [(p, "MISS") for p in shot_positions if p not in hits]:
                        if pos in cells:
                            valid = False
                            break
                    if not valid:
                        continue

                    hit_count = sum(1 for c in cells if c in hits)
                    if hit_count == 0 and hits:
                        # When we have unsunk hits, prefer placements that cover them.
                        continue

                    for cell in cells:
                        if cell in shot_positions:
                            continue
                        scores[cell] = scores.get(cell, 0.0) + 1.0 + 0.5 * hit_count

    if not scores:
        return {}
    peak = max(scores.values())
    return {cell: (val / peak) * heatmap_weight for cell, val in scores.items()}


def pick_next_shot(
    shots_data: list[dict],
    optimizer: StrategyOptimizer,
    rows: int = 10,
    cols: int = 10,
) -> tuple[int, int]:
    """
    Weighted hunt/target strategy. Returns (row, col).
    """
    w = optimizer.weights
    shot_positions, misses, all_hits, sunk_lengths = _shot_board(shots_data)

    sunk_cells: set[tuple] = set()
    visited: set[tuple] = set()
    for pos in all_hits:
        if pos in visited:
            continue
        cluster = _connected_hit_cluster(all_hits, pos)
        visited.update(cluster)
        if any(all_hits[p] is not None for p in cluster):
            sunk_cells.update(cluster)

    unsunk_hits = set(all_hits) - sunk_cells
    heatmap = _heatmap_with_constraints(rows, cols, shot_positions, all_hits, sunk_lengths, w["hunt_heatmap"])

    # ── Target mode ────────────────────────────────────────────────────────
    if unsunk_hits:
        clusters: list[set[tuple]] = []
        seen: set[tuple] = set()
        for pos in unsunk_hits:
            if pos in seen:
                continue
            cluster = _connected_hit_cluster(all_hits, pos) & unsunk_hits
            seen.update(cluster)
            clusters.append(cluster)

        candidates: list[tuple] = []
        for cluster in clusters:
            axis = _cluster_axis(cluster)
            cluster_list = sorted(cluster)
            for r, c in cluster_list:
                for dr, dc in ((-1, 0), (1, 0), (0, -1), (0, 1)):
                    nb = (r + dr, c + dc)
                    nr, nc = nb
                    if not (0 <= nr < rows and 0 <= nc < cols) or nb in shot_positions:
                        continue

                    factors: dict[str, float] = {}
                    inline = False
                    if axis == "HORIZONTAL" and dr == 0:
                        inline = True
                    elif axis == "VERTICAL" and dc == 0:
                        inline = True
                    elif len(cluster) == 1:
                        inline = False

                    if inline:
                        factors["target_inline"] = w["target_inline"]
                    else:
                        factors["target_perpendicular"] = w["target_perpendicular"]

                    if any((nb[0] + dr2, nb[1] + dc2) in misses for dr2, dc2 in ((-1, 0), (1, 0), (0, -1), (0, 1))):
                        factors["target_miss_adjacent"] = w["target_miss_adjacent"]

                    if nb in heatmap:
                        factors["hunt_heatmap"] = heatmap[nb]

                    candidates.append((nr, nc, factors))

        if candidates:
            row, col, _ = _weighted_choice(candidates, optimizer)
            return row, col

    # ── Hunt mode ──────────────────────────────────────────────────────────
    candidates = []
    for r in range(rows):
        for c in range(cols):
            if (r, c) in shot_positions:
                continue
            factors: dict[str, float] = {}
            if (r + c) % 2 == 0:
                factors["hunt_parity_even"] = w["hunt_parity_even"]
            else:
                factors["hunt_parity_odd"] = w["hunt_parity_odd"]

            factors["hunt_center"] = _center_bonus(r, c, rows, cols, w["hunt_center"])

            if (r, c) in heatmap:
                factors["hunt_heatmap"] = heatmap[(r, c)]

            if any((r + dr, c + dc) in misses for dr, dc in ((-1, 0), (1, 0), (0, -1), (0, 1))):
                factors["target_miss_adjacent"] = w["target_miss_adjacent"]

            candidates.append((r, c, factors))

    row, col, _ = _weighted_choice(candidates, optimizer)
    return row, col


# ─── Game loop ────────────────────────────────────────────────────────────────

def play(agent_kp: dict, agent_id: str, optimizer: StrategyOptimizer) -> None:
    rows, cols = 10, 10

    def call(method, path, body=None):
        return api(method, path, agent_kp, agent_id, body)

    print(f"Strategy optimizer: {optimizer.summary()}")

    # Resume an in-progress attempt or start a new one
    try:
        print("Checking for an existing active attempt...")
        resp = call("get", "/attempts/current")
        print("Resumed active attempt.")
    except requests.HTTPError as exc:
        if exc.response.status_code == 404:
            print("No active attempt - starting a new one...")
            resp = call("post", "/attempts")
        else:
            raise

    while True:
        rt = resp.get("responseType")

        # ── MOVE_REQUIRED ──────────────────────────────────────────────────
        if rt == "MOVE_REQUIRED":
            state     = resp["state"]
            game_n    = state.get("gameOrdinal", "?")
            total     = state.get("totalGames", "?")
            next_move = state["nextRequiredMove"]
            opponent  = state.get("opponent", {}).get("displayName", "unknown")

            if next_move == "PLACE_SHIPS":
                print(f"\n[Game {game_n}/{total}] vs {opponent} - placing ships...")
                optimizer.begin_game()
                placements = place_fleet_weighted(optimizer, rows, cols)
                resp = call("post", "/attempts/current/placements",
                            {"placements": placements})

            elif next_move == "SUBMIT_SHOT":
                shots_so_far = state.get("yourShots", [])
                row, col     = pick_next_shot(shots_so_far, optimizer, rows, cols)
                sunk_count   = len(state.get("sunkOpponentShipClasses", []))
                print(
                    f"  [Game {game_n}/{total}] shot #{len(shots_so_far)+1:>3} "
                    f"-> ({row},{col})  [{sunk_count}/{len(FLEET)} sunk]",
                    end=" ... ", flush=True,
                )
                resp = call("post", "/attempts/current/shots", {"row": row, "col": col})
                optimizer.record_shot()

                # Print outcome from the fresh response state
                if resp.get("responseType") == "MOVE_REQUIRED":
                    fresh_shots = resp["state"].get("yourShots", [])
                    if fresh_shots:
                        last      = fresh_shots[-1]
                        outcome   = last.get("outcome", "?")
                        sunk_cls  = last.get("sunkShipClass")
                        suffix    = f" (SANK {sunk_cls})" if sunk_cls else ""
                        print(f"{outcome}{suffix}")
                        optimizer.learn_from_shot(outcome)
                    else:
                        print()

            else:
                print(f"Unknown nextRequiredMove: {next_move!r}")
                break

        # ── GAME_COMPLETED ─────────────────────────────────────────────────
        elif rt == "GAME_COMPLETED":
            result  = resp.get("result", {})
            outcome = result.get("outcome", "?")
            score   = result.get("score", "?")
            print(f"\n  Game complete - {outcome}  (score delta: {score})")
            optimizer.learn_from_game(outcome, score)
            print(f"  Updated: {optimizer.summary()}")
            next_resp = resp.get("next")
            if next_resp:
                resp = next_resp
            else:
                resp = call("get", "/attempts/current")

        # ── ATTEMPT_COMPLETED ──────────────────────────────────────────────
        elif rt == "ATTEMPT_COMPLETED":
            result      = resp.get("result", {})
            final_score = result.get("finalScore", result.get("score", "N/A"))
            optimizer.save()
            print("\n" + "=" * 50)
            print("ATTEMPT COMPLETED")
            print(f"Final Score: {final_score}")
            print(f"Optimizer: {optimizer.summary()}")
            print("=" * 50)
            return

        # ── ATTEMPT_DISQUALIFIED ───────────────────────────────────────────
        elif rt == "ATTEMPT_DISQUALIFIED":
            reason = (
                resp.get("reason")
                or resp.get("message")
                or json.dumps(resp)
            )
            print(f"\nATTEMPT DISQUALIFIED: {reason}")
            return

        else:
            print(f"Unexpected responseType: {rt!r}")
            print(json.dumps(resp, indent=2))
            break


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    host_kp, agent_kp, agent_id = get_or_create_agent()
    optimizer = StrategyOptimizer()
    print(f"\nAgent: {agent_id}\n")
    play(agent_kp, agent_id, optimizer)


if __name__ == "__main__":
    main()
