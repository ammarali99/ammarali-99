@echo off
setlocal
cd /d "%~dp0"

:: --- Auto-elevate: most A1 checks and almost everything A4 does need an
:: Administrator Command Prompt. Relaunch elevated via UAC if we're not
:: already admin, instead of making you open one by hand every time.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator rights...
    powershell -Command "Start-Process '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)

:: --- Fast mode: `run_scan.bat fast` skips the slow internet-touching
:: checks (traceroute, PMTU ladder, throughput download, STUN, captive
:: portal probe, mDNS/DHCP broadcasts) for quick iterative testing.
:: Everything else still runs. Omit the arg (or pass anything else) for
:: a full scan.
set SKIP_FLAGS=
if /i "%~1"=="fast" (
    echo === Fast mode: skipping traceroute/PMTU/throughput/NAT-type/captive-portal/mDNS/DHCP-probe ===
    set SKIP_FLAGS=--no-traceroute --no-pmtu --no-throughput --no-nat-type --no-captive-portal --no-mdns --no-dhcp-probe
)

echo === Running A1 (Discovery) ===
python network_discovery_v0.15.0.py --cache %SKIP_FLAGS%
echo.

echo === Running A2 (Rule Engine) ===
python a2_rule_engine_v0.9.0.py --cache
echo.

echo === Running A4 (Diff against last scan) ===
python a4_snapshot_rollback_v0.4.0.py --diff
echo.

pause
