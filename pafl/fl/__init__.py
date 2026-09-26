"""The federated-learning layer, in the order a run uses it.

partition      split one clean record into client shards
scenario       a federation on the simulated plant (the pilot's setting)
scenario_real  a federation on SWaT, WADI or BATADAL: slices, splicing, eval sets
variants       the five federations compared: clean, honest_only, fabricated,
               projected, gated
gate           the physics check's verdict on every client's batch
train          the federated loop, the detector's training and its threshold
defences       the seven aggregation rules
models         the detectors
"""
