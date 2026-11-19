# Sentinel ablations (820 held-out incidents, trained on 866)

Each group is removed from the rule baseline and from the learned classifier (retrained without it).

| Signals | Sentinel accuracy | Macro-F1 | Compromised-HMI recall | Operator incidents called an attack | Rules accuracy |
|---|---|---|---|---|---|
| all signals | 93.9% | 0.923 | 87% | 3.4% | 92.0% |
| without human presence | 93.8% | 0.921 | 83% | 1.9% | 92.3% |
| without source identity (profile, IP vs label, hours) | 82.6% | 0.760 | 20% | 22.7% | 64.1% |
| without behaviour (push, probe, rhythm, persistence, retries, typos) | 93.4% | 0.915 | 72% | 0.0% | 87.0% |
| without twin forecasts (counterfactual, weather risk) | 88.0% | 0.860 | 86% | 0.0% | 83.5% |
| without integrity alarm numbers | 88.7% | 0.884 | 87% | 3.4% | 85.6% |
