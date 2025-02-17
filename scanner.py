import nmap
import ollama
import sys
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def run_nmap_scan(target):
    # Initialize the Nmap PortScanner
    nm = nmap.PortScanner()

    # Run the Nmap scan with vulnerability detection scripts
    print(f"Starting Nmap scan on {target}...")
    nm.scan(target, arguments=' ')

    # Check if the scan was successful
    if nm.all_hosts():
        return nm
    else:
        print("Scan failed. Please check the target and try again.")
        sys.exit(1)

def analyze_nmap_results(nm):
    vulnerabilities = []
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"\nProtocol: {proto}")

            ports = nm[host][proto].keys()
            for port in ports:
                print(f"\nPort: {port}")
                print(f"State: {nm[host][proto][port]['state']}")
                print(f"Service: {nm[host][proto][port]['name']}")
                print(f"Version: {nm[host][proto][port]['version']}")

                # Check for vulnerabilities
                if 'script' in nm[host][proto][port]:
                    for script, output in nm[host][proto][port]['script'].items():
                        if 'vuln' in script.lower():
                            vulnerability = {
                                'host': host,
                                'port': port,
                                'service': nm[host][proto][port]['name'],
                                'vulnerability': script,
                                'output': output
                            }
                            vulnerabilities.append(vulnerability)
                            print(f"Vulnerability: {script}")
                            print(f"Details: {output}")
    return vulnerabilities

def generate_report(vulnerabilities):
    report = "Vulnerability Identification:\n"
    for vuln in vulnerabilities:
        report += f"- Host: {vuln['host']}, Port: {vuln['port']}, Service: {vuln['service']}\n"
        report += f"  Vulnerability: {vuln['vulnerability']}\n"
        report += f"  Details: {vuln['output']}\n"
    return report

def analyze_with_ollama(report):
    # Prepare the prompt for Ollama
    prompt = f"""
    Analyze the following vulnerability scan report and provide a detailed analysis:
    - Identify potential vulnerabilities, such as open ports, outdated software, misconfigurations, or weak passwords.
    - Assess the risk of each vulnerability based on severity, likelihood, and exploitation ease.
    - Provide remediation guidance for each vulnerability.

    Scan Report:
    {report}
    """

    # Query Ollama for analysis
    response = ollama.generate(model='llama3.2:1b', prompt=prompt)
    return response['response']

def save_to_pdf(report, analysis, filename='vulnerability_report.pdf'):
    # Create a PDF document
    pdf = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Add the scan report to the PDF
    story.append(Paragraph("Vulnerability Scan Report", styles['Title']))
    story.append(Spacer(1, 12))
    for line in report.split('\n'):
        story.append(Paragraph(line, styles['BodyText']))
        story.append(Spacer(1, 6))

    # Add the Ollama analysis to the PDF
    story.append(Paragraph("Ollama Analysis", styles['Title']))
    story.append(Spacer(1, 12))
    for line in analysis.split('\n'):
        story.append(Paragraph(line, styles['BodyText']))
        story.append(Spacer(1, 6))

    # Build the PDF
    pdf.build(story)
    print(f"\nPDF report saved to '{filename}'.")

def main():
    target = input("Enter the IP address or domain name to scan: ")

    nm = run_nmap_scan(target)

    vulnerabilities = analyze_nmap_results(nm)

    report = generate_report(vulnerabilities)

    print("\nScan Report:")
    print(report)

    print("\nAnalyzing scan results with Ollama...")
    analysis = analyze_with_ollama(report)
    print("\nOllama Analysis:")
    print(analysis)

    save_to_pdf(report, analysis)

if __name__ == "__main__":
    main()