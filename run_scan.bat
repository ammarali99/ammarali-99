@echo off
cd /d "%~dp0"

echo === Running A1 (Discovery) ===
python network_discovery_v0.13.1.py --cache
echo.

echo === Running A2 (Rule Engine) ===
python a2_rule_engine_v0.7.2.py --cache
echo.

pause
