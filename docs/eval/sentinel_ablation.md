# Sentinel ablations (558 held-out incidents, trained on 875)

Each group is removed from the rule baseline and from the learned classifier (retrained without it).

| Signals | Sentinel accuracy | Macro-F1 | Compromised-HMI recall | Operator incidents called an attack | Rules accuracy |
|---|---|---|---|---|---|
| all signals | 93.5% | 0.925 | 90% | 3.9% | 90.7% |
| without human presence | 93.0% | 0.919 | 88% | 5.5% | 91.2% |
| without source identity (profile, IP vs label, hours) | 78.7% | 0.763 | 20% | 24.2% | 62.4% |
| without behaviour (push, probe, rhythm, persistence, retries, typos) | 92.3% | 0.910 | 75% | 0.0% | 82.3% |
| without twin forecasts (counterfactual, weather risk) | 90.9% | 0.890 | 88% | 2.3% | 84.8% |
| without integrity alarm numbers | 89.8% | 0.898 | 90% | 3.9% | 86.4% |
