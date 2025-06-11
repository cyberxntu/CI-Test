Exiplanation For CyberX jentilmens To Undwerstand what We did :

 - Web Application:

    Made with Python and SQLite as the database.

    Contains multiple vulnerabilities intentionally, including:

        Broken Access Control (admin page accessible without checks)

        Cross-Site Scripting (XSS)

        Logic flaws

        Plaintext password storage

        Missing CSRF protection

        Weak session key (hardcoded and short)

        No input validation




2 - Scan Bash File:

A bash script that runs all security and static analysis tools with one command.

All tools are installed locally, mostly using pip or npm.




Security Tools:

    bandit: Scans Python code for common security issues.

    snyk: Scans dependencies listed in requirements.txt for known vulnerabilities.

    gitleaks: Scans the Git repository (commits and code) for secrets like API keys and passwords. It’s used via the .exe file in this case (not added to PATH).



Static Analysis Tools (SAST):

    pyright: Checks for type errors in Python code.

    pylint: Performs deep analysis of the code for errors, bad practices, and style issues.

    flake8: Checks for coding style issues based on PEP8.

This setup helps us detect weaknesses in the code and the development process. The web app was created specifically to be scanned and tested by these tools



-- When you done installing these files and tools just run ( .\scan.ps1 ) in vs code terminal
-- the requirements.txt files was generated using this command ( pip freeze > requirements.txt )
-- gitleaks.exe should be within the files to run ( I tryed adding it to env path but .. i could not so im running it directly )
-- when you finish building and testing your CI/CD pipeline we will make more stable-respectfull version of this application
-- to use "Snyk" you must first use this command (synk auth) to sign up