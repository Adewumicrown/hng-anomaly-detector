from monitor import parse_log_line, tail_log
import threading, time

# Test 1: parse a valid line
line = '{"source_ip":"1.2.3.4","timestamp":"2026-04-27T08:00:00+00:00","method":"GET","path":"/","status":200,"response_size":1234,"request_time":0.05}'
result = parse_log_line(line)
print("Parsed entry:", result)
assert result["source_ip"] == "1.2.3.4"
assert result["status"] == 200
print("✅ parse_log_line works")

# Test 2: bad line returns None
bad = parse_log_line("not json at all")
assert bad is None
print("✅ bad line returns None")

# Test 3: tail_log against the real nginx log
print("\n[test] Tailing real log — send a curl request to see it fire:")

def on_entry(entry):
    print(f"[monitor] Got entry: {entry['source_ip']} {entry['method']} {entry['path']} {entry['status']}")

t = threading.Thread(target=tail_log, args=["/var/log/nginx/hng-access.log", on_entry], daemon=True)
t.start()

# Keep alive for 15 seconds — curl http://localhost/ in another terminal
time.sleep(15)
print("Done.")
