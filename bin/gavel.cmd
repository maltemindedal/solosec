@echo off
:: This wrapper allows Windows users to just type "gavel"
:: without needing to type ".ps1"
powershell -ExecutionPolicy Bypass -File "%~dp0gavel.ps1" %*
