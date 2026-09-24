import pytest
from datetime import datetime, timezone

import parser


@pytest.fixture(autouse=True)
def reset_pid_to_ip():
    """
    parser.pid_to_ip is a module-level dict used to correlate SSH connection
    lines across two log lines (see parse_ssh_line). It's global, mutable
    state - exactly the kind of thing that makes tests interfere with each
    other if one test's PID happens to collide with another's. Clearing it
    before and after every test keeps them independent.
    """
    parser.pid_to_ip.clear()
    yield
    parser.pid_to_ip.clear()


# ---------------------------------------------------------------------------
# SSH log parsing
# ---------------------------------------------------------------------------

def test_failed_login_is_parsed():
    line = "Sep 23 21:19:04 hostname sshd[33]: Failed password for testuser from 172.18.0.3 port 60338 ssh2\n"
    result = parser.parse_ssh_line(line)
    assert result["event_type"] == "ssh_failed_login"
    assert result["username"] == "testuser"
    assert result["source_ip"] == "172.18.0.3"
    assert result["source_host"] == "hostname"


def test_accepted_login_is_parsed():
    line = "Sep 23 21:20:10 hostname sshd[40]: Accepted password for testuser from 172.18.0.3 port 60400 ssh2\n"
    result = parser.parse_ssh_line(line)
    assert result["event_type"] == "ssh_accepted_login"
    assert result["username"] == "testuser"
    assert result["source_ip"] == "172.18.0.3"


def test_connection_from_line_returns_none_but_records_pid():
    line = "Sep 23 21:19:04 hostname sshd[99]: Connection from 172.18.0.5 port 51000 on 172.18.0.2 port 22\n"
    result = parser.parse_ssh_line(line)
    assert result is None
    assert parser.pid_to_ip["99"] == "172.18.0.5"


def test_recon_probe_is_correlated_with_earlier_connection_line():
    connection_line = "Sep 23 21:19:04 hostname sshd[101]: Connection from 172.18.0.9 port 51000 on 172.18.0.2 port 22\n"
    probe_line = "Sep 23 21:19:05 hostname sshd[101]: error: kex_exchange_identification: Connection closed by remote host\n"

    assert parser.parse_ssh_line(connection_line) is None
    result = parser.parse_ssh_line(probe_line)

    assert result["event_type"] == "ssh_recon_probe"
    assert result["source_ip"] == "172.18.0.9"
    # The PID entry should be consumed (popped), not left behind
    assert "101" not in parser.pid_to_ip


def test_recon_probe_with_unknown_pid_has_no_source_ip():
    # If we never saw a matching "Connection from" line for this PID (e.g. it
    # arrived before the collector started tailing), there's nothing to
    # correlate against - source_ip should be None, not raise a KeyError.
    probe_line = "Sep 23 21:19:05 hostname sshd[999]: error: kex_exchange_identification: Connection closed by remote host\n"
    result = parser.parse_ssh_line(probe_line)
    assert result["event_type"] == "ssh_recon_probe"
    assert result["source_ip"] is None


def test_unmatched_ssh_line_returns_none():
    line = "Sep 23 21:19:04 hostname sshd[33]: Server listening on 0.0.0.0 port 22.\n"
    assert parser.parse_ssh_line(line) is None


def test_syslog_timestamp_assumes_current_year_and_utc():
    dt = parser.parse_syslog_timestamp("Sep 23 21:19:04")
    assert dt.year == datetime.now().year
    assert dt.month == 9
    assert dt.day == 23
    assert dt.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# HTTP log parsing
# ---------------------------------------------------------------------------

def test_sql_injection_path_is_flagged():
    assert parser.is_suspicious_path("/index.html?id=1%27%20OR%20%271%27%3D%271") is True


def test_path_traversal_is_flagged():
    assert parser.is_suspicious_path("/../../../etc/passwd") is True


def test_double_encoded_traversal_is_still_flagged():
    # unquote() only decodes once; %252f decodes to the literal string "%2f",
    # which is why "..%2f" has to be in SUSPICIOUS_PATTERNS explicitly.
    assert parser.is_suspicious_path("/..%252f..%252fetc/passwd") is True


def test_benign_path_is_not_flagged():
    assert parser.is_suspicious_path("/index.html") is False


def test_http_line_with_suspicious_path_is_parsed():
    line = '172.18.0.4 - - [23/Sep/2026:23:03:14 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "curl/8.21.0" "-"\n'
    result = parser.parse_http_line(line)
    assert result["event_type"] == "http_suspicious_request"
    assert result["source_ip"] == "172.18.0.4"
    assert result["source_host"] == "web-target"


def test_http_line_with_benign_path_returns_none():
    line = '172.18.0.4 - - [23/Sep/2026:23:03:14 +0000] "GET /index.html HTTP/1.1" 200 896 "-" "curl/8.21.0" "-"\n'
    assert parser.parse_http_line(line) is None


def test_nginx_timestamp_keeps_its_own_offset():
    dt = parser.parse_nginx_timestamp("23/Sep/2026:23:03:14 +0000")
    assert dt.year == 2026
    assert dt.utcoffset().total_seconds() == 0


# ---------------------------------------------------------------------------
# Raw packet capture parsing
# ---------------------------------------------------------------------------

def test_syn_probe_line_is_parsed():
    line = "2026-09-24 13:53:07.793999 IP 172.18.0.4.58866 > 172.18.0.5.22: Flags [S], seq 966568056, win 64240, options [mss 1460,sackOK,TS val 1308864446 ecr 0,nop,wscale 10], length 0\n"
    result = parser.parse_synscan_line(line)
    assert result["event_type"] == "syn_probe"
    assert result["source_ip"] == "172.18.0.4"
    assert result["dest_port"] == 22


def test_tcpdump_banner_lines_are_ignored():
    assert parser.parse_synscan_line("tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\n") is None
    assert parser.parse_synscan_line("listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n") is None


def test_tcpdump_timestamp_is_utc():
    dt = parser.parse_tcpdump_timestamp("2026-09-24 13:53:07.793999")
    assert dt.tzinfo == timezone.utc
    assert dt.microsecond == 793999


# ---------------------------------------------------------------------------
# File integrity monitoring parsing
# ---------------------------------------------------------------------------

def test_fim_line_is_parsed():
    line = "2026-09-24T15:01:56Z FILE_CHANGED /root/.ssh/authorized_keys e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ae0d5151227c3bb5efb58642aed76e8f2484c861d6b49989d2a096511ec31b73\n"
    result = parser.parse_fim_line(line)
    assert result["event_type"] == "file_integrity_violation"
    assert result["file_path"] == "/root/.ssh/authorized_keys"
    assert result["source_ip"] is None


def test_fim_timestamp_is_utc():
    dt = parser.parse_fim_timestamp("2026-09-24T15:01:56Z")
    assert dt.tzinfo == timezone.utc
