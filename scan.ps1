echo "Starting Full Code Scanning - Cipher doing it darling"
sleep 5

echo "Starting Bandit - security test"
sleep 2
echo "----------------------------------------"
bandit -r .
echo "----------------------------------------"
sleep 5

echo "Startig Snyk - libraries vulns test"
sleep 2
echo "----------------------------------------"
snyk test --file=requirements.txt --package-manager=pip
echo "----------------------------------------"
sleep 5
echo "Done"
sleep 5

echo "Starting Gitleaks - Secret scanner for commits"
sleep 2
echo "----------------------------------------"
.\gitleaks.exe detect --source . --verbose
echo "----------------------------------------"
sleep 5
echo "Done"
sleep 5

echo "Starting Pyright - SAST "
sleep 2
echo "----------------------------------------"
pyright
echo "----------------------------------------"
sleep 5
echo "Done"
sleep 5

echo "Starting Pylint - SAST "
sleep 2
echo "----------------------------------------"
pylint app.py
echo "----------------------------------------"
sleep 5
echo "Done"
sleep 5

echo "Starting Flake8 - SAST "
sleep 2
echo "----------------------------------------"
flake8 app.py
echo "----------------------------------------"
sleep 5
echo "Done"
sleep 5