# SOC Network Visualization Dashboard

A production-style, client-side cybersecurity visualization dashboard with:

- SOC topology SVG canvas with zones, devices, links, and interface labels
- Attack scenario selector (9 scenarios)
- Animated packet flow simulation with mirrored IDS traffic
- Detection pipeline feed and alert feed
- Real-time metrics (flows/s, anomaly rate, confidence)
- Dark glassmorphism SOC styling

## Run

```bash
python3 -m http.server 4173
# open http://localhost:4173
```

No backend or package install required.
