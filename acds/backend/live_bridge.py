import time
import requests
import json
import subprocess
import socket

API_URL = "http://localhost:8000/ingest"

def monitor_system_logs():
    print("Real-time log monitoring started (Interval: 10s)...")
    seen_events = set()
    
    while True:
        try:
            # First try Security log (Admin required)
            cmd = 'powershell -Command "Get-EventLog -LogName Security -Newest 5 -ErrorAction Stop | Select-Object Index, EventID, Source, TimeGenerated, Message | ConvertTo-Json"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode != 0:
                # Fallback to Application log (No Admin needed)
                cmd = 'powershell -Command "Get-EventLog -LogName Application -Newest 5 | Select-Object Index, EventID, Source, TimeGenerated, Message | ConvertTo-Json"'
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            output = result.stdout.strip()
            if output:
                events = json.loads(output)
                if isinstance(events, dict):
                    events = [events]
                
                payload_events = []
                for ev in events:
                    idx = ev.get('Index')
                    if idx and idx not in seen_events:
                        seen_events.add(idx)
                        
                        # Map Windows Event to ACDS format
                        event_id = ev.get('EventID', 0)
                        msg = ev.get('Message', '')
                        
                        acds_event = {
                            "raw_text": json.dumps(ev),
                            "layer": "windows_event",
                            "event_id": event_id,
                            "message": msg,
                            "source": ev.get('Source'),
                            "timestamp": ev.get('TimeGenerated'),
                            "src_ip": socket.gethostbyname(socket.gethostname()) # Current device IP
                        }
                        
                        payload_events.append(acds_event)
                
                # Prevent memory leak over days of running
                if len(seen_events) > 1000:
                    seen_events.clear()
                    
                if payload_events:
                    requests.post(API_URL, json={'events': payload_events})
                    
        except Exception as e:
            print(f"Error fetching logs: {e}")
            
        time.sleep(10)

if __name__ == "__main__":
    monitor_system_logs()
