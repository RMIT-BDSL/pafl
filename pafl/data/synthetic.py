"""A small simulated water plant.

Why this exists. Three reasons, and only the first is obvious.

1. It lets the whole pipeline run before any real dataset is downloaded, so a
   smoke test needs no network and no licence.
2. Its physics are known exactly, so the invariant residuals of honest data are
   ground truth rather than an estimate. That makes it the cleanest place to
   check the day-1 kill criterion.
3. A deliberately mis-specified copy of it *is* Recipe C, the attacker who
   simulates telemetry instead of instrumenting a plant.

Topology, chosen to mirror the shape of BATADAL:

    source -> PU1 -> T1 -> PU2 -> T2 -> PU3 -> T3 -> PU4 -> demand

Column names follow the BATADAL convention so code written here transfers.
"""
from __future__ import annotations
from dataclasses import dataclass, field, replace
import numpy as np
import pandas as pd

N_TANKS = 3
N_PUMPS = 4


@dataclass(frozen=True)
class PlantParams:
    """Every physical constant in one place, so a mis-specified copy is one call."""

    area: tuple[float, ...] = (12.0, 15.0, 10.0)      # tank cross-section, m^2
    nominal_flow: tuple[float, ...] = (2.20, 2.05, 1.95, 2.00)  # m^3 per step when a pump runs
    level_lo: tuple[float, ...] = (2.0, 2.5, 1.8)     # hysteresis lower setpoint, m
    level_hi: tuple[float, ...] = (4.5, 5.0, 4.0)     # hysteresis upper setpoint, m
    level_init: tuple[float, ...] = (3.2, 3.6, 2.9)
    dt: float = 1.0                                   # one step
    sensor_noise: float = 0.004                       # std dev on level, m
    flow_noise: float = 0.020                         # std dev on flow, m^3
    flow_noise_rho: float = 0.55                      # correlation of flow noise across steps
    actuator_delay: int = 2                           # steps between command and effect
    demand_period: int = 1440                         # steps in one demand cycle
    demand_depth: float = 0.45                        # how deep the demand trough goes


def misspecified(p: PlantParams) -> PlantParams:
    """Recipe C. The parameters an attacker would guess but not measure.

    Wrong tank areas, no actuator dead time, and white flow noise instead of
    correlated noise. The output looks plausible on a plot and fails the
    invariants at once.
    """
    return replace(
        p,
        area=tuple(a * 1.35 for a in p.area),
        actuator_delay=0,
        flow_noise_rho=0.0,
    )


@dataclass
class AttackWindow:
    """One scripted attack on the simulated plant."""

    start: int
    end: int
    kind: str            # 'level_freeze' | 'level_offset' | 'pump_stuck_off' | 'flow_scale'
    target: int = 0      # tank index or pump index
    magnitude: float = 0.0


def _demand_profile(n: int, p: PlantParams, rs: np.random.Generator) -> np.ndarray:
    t = np.arange(n)
    base = 1.0 - p.demand_depth * (0.5 + 0.5 * np.cos(2 * np.pi * t / p.demand_period))
    jitter = rs.normal(0.0, 0.03, size=n)
    return np.clip(base + jitter, 0.15, 1.25)


def _ar1_noise(n: int, sigma: float, rho: float, rs: np.random.Generator) -> np.ndarray:
    """Correlated noise. Real flow meters do not produce white noise, and an
    attacker who uses white noise leaves a signature."""
    if rho <= 0:
        return rs.normal(0.0, sigma, size=n)
    out = np.empty(n)
    out[0] = rs.normal(0.0, sigma)
    s = sigma * np.sqrt(1 - rho**2)
    for i in range(1, n):
        out[i] = rho * out[i - 1] + rs.normal(0.0, s)
    return out


def simulate(
    n_steps: int = 20_000,
    params: PlantParams | None = None,
    attacks: list[AttackWindow] | None = None,
    seed: int = 0,
    site_shift: float = 0.0,
) -> pd.DataFrame:
    """Run the plant and return a dataframe of sensor and actuator channels.

    site_shift moves the setpoints and pump sizes a little. Different clients in
    the federation are different plants, not different samples from one plant,
    and that heterogeneity is the whole reason robust aggregation struggles here.
    """
    p = params or PlantParams()
    rs = np.random.default_rng(seed)
    attacks = attacks or []

    area = np.array(p.area) * (1.0 + 0.10 * site_shift)
    qnom = np.array(p.nominal_flow) * (1.0 + 0.12 * site_shift)
    lo = np.array(p.level_lo) * (1.0 + 0.06 * site_shift)
    hi = np.array(p.level_hi) * (1.0 + 0.06 * site_shift)

    level = np.array(p.level_init, dtype=float)
    cmd = np.ones(N_PUMPS, dtype=int)             # controller command
    cmd_hist: list[np.ndarray] = [cmd.copy() for _ in range(max(p.actuator_delay, 0) + 1)]

    demand = _demand_profile(n_steps, p, rs)
    fnoise = np.stack([_ar1_noise(n_steps, p.flow_noise, p.flow_noise_rho, rs) for _ in range(N_PUMPS)])

    rows = []
    for t in range(n_steps):
        # --- controller: hysteresis on the level of the tank each pump feeds ---
        for i in range(N_TANKS):
            if level[i] < lo[i]:
                cmd[i] = 1
            elif level[i] > hi[i]:
                cmd[i] = 0
        cmd[N_PUMPS - 1] = 1 if demand[t] > 0.35 else 0    # outlet pump follows demand

        cmd_hist.append(cmd.copy())
        applied = cmd_hist[-(p.actuator_delay + 1)]        # actuator dead time
        if len(cmd_hist) > 64:
            cmd_hist = cmd_hist[-64:]

        status = applied.copy()
        flow = status * qnom + status * fnoise[:, t]
        flow[N_PUMPS - 1] *= demand[t]
        flow = np.maximum(flow, 0.0)

        # --- physical process: mass balance on each tank ---
        true_level = level.copy()
        for i in range(N_TANKS):
            true_level[i] = level[i] + p.dt * (flow[i] - flow[i + 1]) / area[i]
        true_level = np.clip(true_level, 0.05, 12.0)

        # --- attacks act between the process and what the historian records ---
        obs_level = true_level.copy()
        obs_flow = flow.copy()
        obs_status = status.copy()
        flag = 0
        for a in attacks:
            if not (a.start <= t < a.end):
                continue
            flag = 1
            if a.kind == "level_freeze":
                obs_level[a.target] = level[a.target]
            elif a.kind == "level_offset":
                obs_level[a.target] = true_level[a.target] + a.magnitude
            elif a.kind == "pump_stuck_off":
                true_level = level.copy()
                for i in range(N_TANKS):
                    f = flow.copy()
                    f[a.target] = 0.0
                    true_level[i] = level[i] + p.dt * (f[i] - f[i + 1]) / area[i]
                obs_flow[a.target] = 0.0
                obs_level = np.clip(true_level, 0.05, 12.0)
            elif a.kind == "flow_scale":
                obs_flow[a.target] = flow[a.target] * a.magnitude

        level = true_level

        row = {"step": t}
        for i in range(N_TANKS):
            row[f"L_T{i+1}"] = obs_level[i] + rs.normal(0.0, p.sensor_noise)
        for i in range(N_PUMPS):
            row[f"F_PU{i+1}"] = obs_flow[i]
            row[f"S_PU{i+1}"] = int(obs_status[i])
        row["DEMAND"] = demand[t]
        row["ATT_FLAG"] = flag
        rows.append(row)

    df = pd.DataFrame(rows)
    df.attrs["plant"] = {
        "area": area.tolist(),
        "qnom": qnom.tolist(),
        "dt": p.dt,
        "n_tanks": N_TANKS,
        "n_pumps": N_PUMPS,
    }
    return df


def default_attacks(n_steps: int, seed: int = 0, n: int = 6) -> list[AttackWindow]:
    """Scatter a handful of scripted attacks through the run."""
    rs = np.random.default_rng(seed)
    kinds = ["level_freeze", "level_offset", "pump_stuck_off", "flow_scale"]
    out: list[AttackWindow] = []
    margin = int(0.12 * n_steps)
    starts = np.sort(rs.choice(np.arange(margin, n_steps - margin), size=n, replace=False))
    for i, s in enumerate(starts):
        k = kinds[i % len(kinds)]
        dur = int(rs.integers(max(30, n_steps // 200), max(60, n_steps // 60)))
        mag = {"level_offset": float(rs.uniform(0.4, 1.1)),
               "flow_scale": float(rs.uniform(0.3, 0.6))}.get(k, 0.0)
        tgt = int(rs.integers(0, N_TANKS if k.startswith("level") else N_PUMPS - 1))
        out.append(AttackWindow(int(s), int(s) + dur, k, tgt, mag))
    return out
