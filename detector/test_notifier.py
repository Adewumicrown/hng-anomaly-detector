from notifier import Notifier
from datetime import datetime

n = Notifier()
n.start()

# Test BAN alert
n.notify("BAN", {
    "ip":        "1.2.3.4",
    "condition": "zscore=4.21 > threshold=3.0",
    "rate":      45.2,
    "baseline":  3.1,
    "stddev":    2.4,
    "duration":  "10min",
    "timestamp": datetime.utcnow().isoformat(),
})

# Test GLOBAL alert
n.notify("GLOBAL", {
    "condition": "rate=120.0 > 5x mean=18.0",
    "rate":      120.0,
    "baseline":  18.0,
    "stddev":    4.2,
    "timestamp": datetime.utcnow().isoformat(),
})

# Test UNBAN alert
n.notify("UNBAN", {
    "ip":        "1.2.3.4",
    "ban_count": 1,
    "duration":  "10min",
    "timestamp": datetime.utcnow().isoformat(),
})

import time
time.sleep(3)  # let the queue drain
print("Done.")
