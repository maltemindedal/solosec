@echo off
:: This wrapper allows Windows users to just type "warden"
:: without needing to type ".ps1"
powershell -ExecutionPolicy Bypass -File "%~dp0warden.ps1" %*
