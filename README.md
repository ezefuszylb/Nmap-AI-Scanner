The script executes an Nmap scan with -sV --script=vuln to detect running services and vulnerabilities on a target IP. It then analyzes the results and generates a basic report. The report is further processed using LLM model llama3.2:1b to provide a basic risk assessment and remediation guidance. The results are saved into a PDF file.
This project can be modified to do the following:

-Add nMap commands to make a more complete and bigger report.

-Use another llama model.

-Modifiy the query params to ask the LLM specific questions about the vulnerabilities.
