#!/usr/bin/env python3
"""
Description: This is the Squizee Quiz Application, a Python-based quiz game using tkinter for the GUI.
Ensure you have tkinter installed to run this application. You can install it using the command: pip install tk

Authors: Bevan Aque Paraz and ChatGPT 4.0
GitHub: https://github.com/B3van/squizee
"""

import random
import tkinter as tk
from tkinter import messagebox, simpledialog

# Question bank defined within the script
questions = [
    {
        "question": "A security analyst is reviewing alerts in the SIEM related to potential malicious network traffic coming from an employee's corporate laptop. The security analyst has determined that additional data about the executable running on the machine is necessary to continue the investigation. Which of the following logs should the analyst use as a data source?",
        "options": [
            "Application",
            "IPS/IDS",
            "Network",
            "Endpoint"
        ],
        "answer": "Endpoint"
    },
    {
        "question": "A cyber operations team informs a security analyst about a new tactic malicious actors are using to compromise networks. SIEM alerts have not yet been configured. Which of the following best describes what the security analyst should do to identify this behavior?",
        "options": [
            "Digital forensics",
            "E-discovery",
            "Incident response",
            "Threat hunting"
        ],
        "answer": "Threat hunting"
    },
    {
        "question": "A company purchased cyber insurance to address items listed on the risk register. Which of the following strategies does this represent?",
        "options": [
            "Accept",
            "Transfer",
            "Mitigate",
            "Avoid"
        ],
        "answer": "Transfer"
    },
    {
        "question": "A security administrator would like to protect data on employees' laptops. Which of the following encryption techniques should the security administrator use?",
        "options": [
            "Partition",
            "Asymmetric",
            "Full disk",
            "Database"
        ],
        "answer": "Full disk"
    },
    {
        "question": "Which of the following security control types does an acceptable use policy best represent?",
        "options": [
            "Detective",
            "Compensating",
            "Corrective",
            "Preventive"
        ],
        "answer": "Preventive"
    },
    {
        "question": "An IT manager informs the entire help desk staff that only the IT manager and the help desk lead will have access to the administrator console of the help desk software. Which of the following security techniques is the IT manager setting up?",
        "options": [
            "Hardening",
            "Employee monitoring",
            "Configuration enforcement",
            "Least privilege"
        ],
        "answer": "Least privilege"
    },
    {
        "question": "Which of the following roles, according to the shared responsibility model, is responsible for securing the company's database in an IaaS model for a cloud environment?",
        "options": [
            "Client",
            "Third-party vendor",
            "Cloud provider",
            "DBA"
        ],
        "answer": "Client"
    },
    {
        "question": "A client asked a security company to provide a document outlining the project, the cost, and the completion time frame. Which of the following documents should the company provide to the client?",
        "options": [
            "MSA",
            "SLA",
            "BPA",
            "SOW"
        ],
        "answer": "SOW"
    },
    {
        "question": "A security team is reviewing the findings in a report that was delivered after a third party performed a penetration test. One of the findings indicated that a web application form field is vulnerable to cross-site scripting. Which of the following application security techniques should the security analyst recommend the developer implement to prevent this vulnerability?",
        "options": [
            "Secure cookies",
            "Version control",
            "Input validation",
            "Code signing"
        ],
        "answer": "Input validation"
    },
    {
        "question": "Which of the following must be considered when designing a high-availability network? (Choose two).",
        "options": [
            "Ease of recovery",
            "Ability to patch",
            "Physical isolation",
            "Responsiveness",
            "Attack surface",
            "Extensible authentication"
        ],
        "answer": [
            "Ease of recovery",
            "Attack surface"
        ]
    },
    {
        "question": "A technician needs to apply a high-priority patch to a production system. Which of the following steps should be taken first?",
        "options": [
            "Air gap the system.",
            "Move the system to a different network segment.",
            "Create a change control request.",
            "Apply the patch to the system."
        ],
        "answer": "Create a change control request."
    },
    {
        "question": "Which of the following describes the reason root cause analysis should be conducted as part of incident response?",
        "options": [
            "To gather IoCs for the investigation",
            "To discover which systems have been affected",
            "To eradicate any trace of malware on the network",
            "To prevent future incidents of the same nature"
        ],
        "answer": "To prevent future incidents of the same nature"
    },
    {
        "question": "Which of the following is the most likely outcome if a large bank fails an internal PCI DSS compliance assessment?",
        "options": [
            "Fines",
            "Audit findings",
            "Sanctions",
            "Reputation damage"
        ],
        "answer": "Fines"
    },
    {
        "question": "A company is developing a business continuity strategy and needs to determine how many staff members would be required to sustain the business in the case of a disruption. Which of the following best describes this step?",
        "options": [
            "Capacity planning",
            "Redundancy",
            "Geographic dispersion",
            "Tabletop exercise"
        ],
        "answer": "Capacity planning"
    },
    {
        "question": "A company's legal department drafted sensitive documents in a SaaS application and wants to ensure the documents cannot be accessed by individuals in high-risk countries. Which of the following is the most effective way to limit this access?",
        "options": [
            "Data masking",
            "Encryption",
            "Geolocation policy",
            "Data sovereignty regulation"
        ],
        "answer": "Geolocation policy"
    },
    {
        "question": "Which of the following is a hardware-specific vulnerability?",
        "options": [
            "Firmware version",
            "Buffer overflow",
            "SQL injection",
            "Cross-site scripting"
        ],
        "answer": "Firmware version"
    },
    {
        "question": "While troubleshooting a firewall configuration, a technician determines that a 'deny any' policy should be added to the bottom of the ACL. The technician updates the policy, but the new policy causes several company servers to become unreachable. Which of the following actions would prevent this issue?",
        "options": [
            "Documenting the new policy in a change request and submitting the request to change management",
            "Testing the policy in a non-production environment before enabling the policy in the production network",
            "Disabling any intrusion prevention signatures on the 'deny any' policy prior to enabling the new policy",
            "Including an 'allow any' policy above the 'deny any' policy"
        ],
        "answer": "Testing the policy in a non-production environment before enabling the policy in the production network"
    },
    {
        "question": "An organization is building a new backup data center with cost-benefit as the primary requirement and RTO and RPO values around two days. Which of the following types of sites is the best for this scenario?",
        "options": [
            "Real-time recovery",
            "Hot",
            "Cold",
            "Warm"
        ],
        "answer": "Warm"
    },
    {
        "question": "A company requires hard drives to be securely wiped before sending decommissioned systems to recycling. Which of the following best describes this policy?",
        "options": [
            "Enumeration",
            "Sanitization",
            "Destruction",
            "Inventory"
        ],
        "answer": "Sanitization"
    },
    {
        "question": "A systems administrator works for a local hospital and needs to ensure patient data is protected and secure. Which of the following data classifications should be used to secure patient data?",
        "options": [
            "Private",
            "Critical",
            "Sensitive",
            "Public"
        ],
        "answer": "Sensitive"
    },
    {
        "question": "A U.S.-based cloud-hosting provider wants to expand its data centers to new international locations. Which of the following should the hosting provider consider first?",
        "options": [
            "Local data protection regulations",
            "Risks from hackers residing in other countries",
            "Impacts to existing contractual obligations",
            "Time zone differences in log correlation"
        ],
        "answer": "Local data protection regulations"
    },
    {
        "question": "Which of the following would be the best way to block unknown programs from executing?",
        "options": [
            "Access control list",
            "Application allow list",
            "Host-based firewall",
            "DLP solution"
        ],
        "answer": "Application allow list"
    },
    {
        "question": "A company hired a consultant to perform an offensive security assessment covering penetration testing and social engineering. Which of the following teams will conduct this assessment activity?",
        "options": [
            "White",
            "Purple",
            "Blue",
            "Red"
        ],
        "answer": "Red"
    },
    {
        "question": "A software development manager wants to ensure the authenticity of the code created by the company. Which of the following options is the most appropriate?",
        "options": [
            "Testing input validation on the user input fields",
            "Performing code signing on company-developed software",
            "Performing static code analysis on the software",
            "Ensuring secure cookies are used"
        ],
        "answer": "Performing code signing on company-developed software"
    },
    {
        "question": "Which of the following can be used to identify potential attacker activities without affecting production servers?",
        "options": [
            "Honeypot",
            "Video surveillance",
            "Zero Trust",
            "Geofencing"
        ],
        "answer": "Honeypot"
    },
    {
        "question": "During an investigation, an incident response team attempts to understand the source of an incident. Which of the following incident response activities describes this process?",
        "options": [
            "Analysis",
            "Lessons learned",
            "Detection",
            "Containment"
        ],
        "answer": "Analysis"
    },
    {
        "question": "A security practitioner completes a vulnerability assessment on a company's network and finds several vulnerabilities, which the operations team remediates. Which of the following should be done next?",
        "options": [
            "Conduct an audit.",
            "Initiate a penetration test.",
            "Rescan the network.",
            "Submit a report."
        ],
        "answer": "Rescan the network."
    },
    {
        "question": "An administrator was notified that a user logged in remotely after hours and copied large amounts of data to a personal device. Which of the following best describes the user's activity?",
        "options": [
            "Penetration testing",
            "Phishing campaign",
            "External audit",
            "Insider threat"
        ],
        "answer": "Insider threat"
    },
    {
        "question": "Which of the following allows for the attribution of messages to individuals?",
        "options": [
            "Adaptive identity",
            "Non-repudiation",
            "Authentication",
            "Access logs"
        ],
        "answer": "Non-repudiation"
    },
    {
        "question": "Which of the following is the best way to consistently determine on a daily basis whether security settings on servers have been modified?",
        "options": [
            "Automation",
            "Compliance checklist",
            "Attestation",
            "Manual audit"
        ],
        "answer": "Automation"
    },
    {
        "question": "Which of the following tools can assist with detecting an employee who has accidentally emailed a file containing a customer's PII?",
        "options": [
            "SCAP",
            "NetFlow",
            "Antivirus",
            "DLP"
        ],
        "answer": "DLP"
    },
    {
        "question": "An organization recently updated its security policy to include the following statement: Regular expressions are included in source code to remove special characters such as $, |, ;. &, `, and ? from variables set by forms in a web application. Which of the following best explains the security technique the organization adopted by making this addition to the policy?",
        "options": [
            "Identify embedded keys",
            "Code debugging",
            "Input validation",
            "Static code analysis"
        ],
        "answer": "Input validation"
    },
    {
        "question": "A security analyst and the management team are reviewing the organizational performance of a recent phishing campaign. The user click-through rate exceeded the acceptable risk threshold, and the management team wants to reduce the impact when a user clicks on a link in a phishing message. Which of the following should the analyst do?",
        "options": [
            "Place posters around the office to raise awareness of common phishing activities.",
            "Implement email security filters to prevent phishing emails from being delivered",
            "Update the EDR policies to block automatic execution of downloaded programs.",
            "Create additional training for users to recognize the signs of phishing attempts."
        ],
        "answer": "Update the EDR policies to block automatic execution of downloaded programs."
    },
    {
        "question": "Which of the following has been implemented when a host-based firewall on a legacy Linux system allows connections from only specific internal IP addresses?",
        "options": [
            "Compensating control",
            "Network segmentation",
            "Transfer of risk",
            "SNMP traps"
        ],
        "answer": "Compensating control"
    },
    {
        "question": "The management team notices that new accounts that are set up manually do not always have correct access or permissions. Which of the following automation techniques should a systems administrator use to streamline account creation?",
        "options": [
            "Guard rail script",
            "Ticketing workflow",
            "Escalation script",
            "User provisioning script"
        ],
        "answer": "User provisioning script"
    },
    {
        "question": "A company is planning to set up a SIEM system and assign an analyst to review the logs on a weekly basis. Which of the following types of controls is the company setting up?",
        "options": [
            "Corrective",
            "Preventive",
            "Detective",
            "Deterrent"
        ],
        "answer": "Detective"
    },
    {
        "question": "A systems administrator is looking for a low-cost application-hosting solution that is cloud-based. Which of the following meets these requirements?",
        "options": [
            "Serverless framework",
            "Type 1 hypervisor",
            "SD-WAN",
            "SDN"
        ],
        "answer": "Serverless framework"
    },
    {
        "question": "A security operations center determines that the malicious activity detected on a server is normal. Which of the following activities describes the act of ignoring detected activity in the future?",
        "options": [
            "Tuning",
            "Aggregating",
            "Quarantining",
            "Archiving"
        ],
        "answer": "Tuning"
    },
    {
        "question": "A security analyst reviews domain activity logs and notices the following: Which of the following is the best explanation for what the security analyst has discovered?",
        "options": [
            "The user jsmith's account has been locked out.",
            "A keylogger is installed on jsmith's workstation",
            "An attacker is attempting to brute force jsmith's account.",
            "Ransomware has been deployed in the domain."
        ],
        "answer": "An attacker is attempting to brute force jsmith's account."
    },
    {
        "question": "A company is concerned about weather events causing damage to the server room and downtime. Which of the following should the company consider?",
        "options": [
            "Clustering servers",
            "Geographic dispersion",
            "Load balancers",
            "Off-site backups"
        ],
        "answer": "Geographic dispersion"
    },
    {
        "question": "Which of the following is a primary security concern for a company setting up a BYOD program?",
        "options": [
            "End of life",
            "Buffer overflow",
            "VM escape",
            "Jailbreaking"
        ],
        "answer": "Jailbreaking"
    },
    {
        "question": "A company decided to reduce the cost of its annual cyber insurance policy by removing the coverage for ransomware attacks. Which of the following analysis elements did the company most likely use in making this decision?",
        "options": [
            "IMTTR",
            "RTO",
            "ARO",
            "MTBF"
        ],
        "answer": "ARO"
    },
    {
        "question": "Which of the following is the most likely to be included as an element of communication in a security awareness program?",
        "options": [
            "Reporting phishing attempts or other suspicious activities",
            "Detecting insider threats using anomalous behavior recognition",
            "Verifying information when modifying wire transfer data",
            "Performing social engineering as part of third-party penetration testing"
        ],
        "answer": "Reporting phishing attempts or other suspicious activities"
    },
    {
        "question": "Which of the following vulnerabilities is exploited when an attacker overwrites a register with a malicious address?",
        "options": [
            "VM escape",
            "SQL injection",
            "Buffer overflow",
            "Race condition"
        ],
        "answer": "Buffer overflow"
    },
    {
        "question": "Which of the following would be the best way to handle a critical business application that is running on a legacy server?",
        "options": [
            "Segmentation",
            "Isolation",
            "Hardening",
            "Decommissioning"
        ],
        "answer": "Segmentation"
    },
    {
        "question": "Which of the following describes the process of concealing code or text inside a graphical image?",
        "options": [
            "Symmetric encryption",
            "Hashing",
            "Data masking",
            "Steganography"
        ],
        "answer": "Steganography"
    },
    {
        "question": "After a company was compromised, customers initiated a lawsuit. The company's attorneys have requested that the security team initiate a legal hold in response to the lawsuit. Which of the following describes the action the security team will most likely be required to take?",
        "options": [
            "Retain the emails between the security team and affected customers for 30 days.",
            "Retain any communications related to the security breach until further notice.",
            "Retain any communications between security members during the breach response.",
            "Retain all emails from the company to affected customers for an indefinite period of time."
        ],
        "answer": "Retain any communications related to the security breach until further notice."
    },
    {
        "question": "A network manager wants to protect the company's VPN by implementing multifactor authentication that uses: - Something you know - Something you have - Something you are Which of the following would accomplish the manager's goal?",
        "options": [
            "Domain name, PKI, GeoIP lookup",
            "VPN IP address, company ID, facial structure",
            "Password, authentication token, thumbprint",
            "Company URL, TLS certificate, home address"
        ],
        "answer": "Password, authentication token, thumbprint"
    },
    {
        "question": "A security manager created new documentation to use in response to various types of security incidents. Which of the following is the next step the manager should take?",
        "options": [
            "Set the maximum data retention policy.",
            "Securely store the documents on an air-gapped network.",
            "Review the documents' data classification policy.",
            "Conduct a tabletop exercise with the team."
        ],
        "answer": "Conduct a tabletop exercise with the team."
    },
    {
        "question": "Users at a company are reporting they are unable to access the URL for a new retail website because it is flagged as gambling and is being blocked. Which of the following changes would allow users to access the site?",
        "options": [
            "Creating a firewall rule to allow HTTPS traffic",
            "Configuring the IPS to allow shopping",
            "Tuning the DLP rule that detects credit card data",
            "Updating the categorization in the content filter"
        ],
        "answer": "Updating the categorization in the content filter"
    },
    {
        "question": "An administrator discovers that some files on a database server were recently encrypted. The administrator sees from the security logs that the data was last accessed by a domain user. Which of the following best describes the type of attack that occurred?",
        "options": [
            "Insider threat",
            "Social engineering",
            "Watering-hole",
            "Unauthorized attacker"
        ],
        "answer": "Insider threat"
    },
    {
        "question": "Which of the following automation use cases would best enhance the security posture of an organization by rapidly updating permissions when employees leave a company?",
        "options": [
            "Provisioning resources",
            "Disabling access",
            "Reviewing change approvals",
            "Escalating permission requests"
        ],
        "answer": "Disabling access"
    },
    {
        "question": "Which of the following must be considered when designing a high-availability network? (Select two).",
        "options": [
            "Ease of recovery",
            "Ability to patch",
            "Physical isolation",
            "Responsiveness",
            "Attack surface",
            "Extensible authentication"
        ],
        "answer": [
            "Ease of recovery",
            "Attack surface"
        ]
    },
    {
        "question": "Which of the following methods to secure credit card data is best to use when a requirement is to see only the last four numbers on a credit card?",
        "options": [
            "Encryption",
            "Hashing",
            "Masking",
            "Tokenization"
        ],
        "answer": "Masking"
    },
    {
        "question": "An administrator finds that all user workstations and servers are displaying a message that is associated with files containing an extension of .ryk. Which of the following types of infections is present on the systems?",
        "options": [
            "Virus",
            "Trojan",
            "Spyware",
            "Ransomware"
        ],
        "answer": "Ransomware"
    },
    {
        "question": "A healthcare organization wants to provide a web application that allows individuals to digitally report health emergencies. Which of the following is the most important consideration during development?",
        "options": [
            "Scalability",
            "Availability",
            "Cost",
            "Ease of deployment"
        ],
        "answer": "Availability"
    },
    {
        "question": "Which of the following is the best reason to complete an audit in a banking environment?",
        "options": [
            "Regulatory requirement",
            "Organizational change",
            "Self-assessment requirement",
            "Service-level requirement"
        ],
        "answer": "Regulatory requirement"
    },
    {
        "question": "A security administrator is deploying a DLP solution to prevent the exfiltration of sensitive customer data. Which of the following should the administrator do first?",
        "options": [
            "Block access to cloud storage websites.",
            "Create a rule to block outgoing email attachments.",
            "Apply classifications to the data.",
            "Remove all user permissions from shares on the file server."
        ],
        "answer": "Apply classifications to the data."
    },
    {
        "question": "Which of the following describes a security alerting and monitoring tool that collects system, application, and network logs from multiple sources in a centralized system?",
        "options": [
            "SIEM",
            "DLP",
            "IDS",
            "SNMP"
        ],
        "answer": "SIEM"
    },
    {
        "question": "Which of the following are cases in which an engineer should recommend the decommissioning of a network device? (Select two).",
        "options": [
            "The device has been moved from a production environment to a test environment.",
            "The device is configured to use cleartext passwords.",
            "The device is moved to an isolated segment on the enterprise network.",
            "The device is moved to a different location in the enterprise.",
            "The device's encryption level cannot meet organizational standards.",
            "The device is unable to receive authorized updates."
        ],
        "answer": [
            "The device's encryption level cannot meet organizational standards.",
            "The device is unable to receive authorized updates."
        ]
    },
    {
        "question": "An administrator assists the legal and compliance team with ensuring information about customer transactions is archived for the proper time period. Which of the following data policies is the administrator carrying out?",
        "options": [
            "Compromise",
            "Retention",
            "Analysis",
            "Transfer",
            "Inventory"
        ],
        "answer": "Retention"
    },
    {
        "question": "A systems administrator is working on a solution with the following requirements: - Provide a secure zone. - Enforce a company-wide access control policy. - Reduce the scope of threats. Which of the following is the systems administrator setting up?",
        "options": [
            "Zero Trust",
            "AAA",
            "Non-repudiation",
            "CIA"
        ],
        "answer": "Zero Trust"
    },
    {
        "question": "A security administrator needs a method to secure data in an environment that includes some form of checks so that the administrator can track any changes. Which of the following should the administrator set up to achieve this goal?",
        "options": [
            "SPF",
            "GPO",
            "NAC",
            "FIM"
        ],
        "answer": "FIM"
    },
    {
        "question": "Which of the following is the phase in the incident response process when a security analyst reviews roles and responsibilities?",
        "options": [
            "Preparation",
            "Recovery",
            "Lessons learned",
            "Analysis"
        ],
        "answer": "Preparation"
    },
    {
        "question": "A company is discarding a classified storage array and hires an outside vendor to complete the disposal. Which of the following should the company request from the vendor?",
        "options": [
            "Certification",
            "Inventory list",
            "Classification",
            "Proof of ownership"
        ],
        "answer": "Certification"
    },
    {
        "question": "Which of the following would be the best ways to ensure only authorized personnel can access a secure facility? (Select two).",
        "options": [
            "Fencing",
            "Video surveillance",
            "Badge access",
            "Access control vestibule",
            "Sign-in sheet",
            "Sensor"
        ],
        "answer": [
            "Badge access",
            "Access control vestibule"
        ]
    },
    {
        "question": "A company's marketing department collects, modifies, and stores sensitive customer data. The infrastructure team is responsible for securing the data while in transit and at rest. Which of the following data roles describes the customer?",
        "options": [
            "Processor",
            "Custodian",
            "Subject",
            "Owner"
        ],
        "answer": "Subject"
    },
    {
        "question": "Malware spread across a company's network after an employee visited a compromised industry blog. Which of the following best describes this type of attack?",
        "options": [
            "Impersonation",
            "Disinformation",
            "Watering-hole",
            "Smishing"
        ],
        "answer": "Watering-hole"
    },
    {
        "question": "After a recent ransomware attack on a company's system, an administrator reviewed the log files. Which of the following control types did the administrator use?",
        "options": [
            "Compensating",
            "Detective",
            "Preventive",
            "Corrective"
        ],
        "answer": "Detective"
    },
    {
        "question": "Which of the following agreement types defines the time frame in which a vendor needs to respond?",
        "options": [
            "SOW",
            "SLA",
            "MOA",
            "MOU"
        ],
        "answer": "SLA"
    },
    {
        "question": "A Chief Information Security Officer wants to monitor the company's servers for SQLi attacks and allow for comprehensive investigations if an attack occurs. The company uses SSL decryption to allow traffic monitoring. Which of the following strategies would best accomplish this goal?",
        "options": [
            "Logging all NetFlow traffic into a SIEM",
            "Deploying network traffic sensors on the same subnet as the servers",
            "Logging endpoint and OS-specific security logs",
            "Enabling full packet capture for traffic entering and exiting the servers"
        ],
        "answer": "Enabling full packet capture for traffic entering and exiting the servers"
    },
    {
        "question": "A client demands at least 99.99% uptime from a service provider's hosted security services. Which of the following documents includes the information the service provider should return to the client?",
        "options": [
            "MOA",
            "SOW",
            "MOU",
            "SLA"
        ],
        "answer": "SLA"
    },
    {
        "question": "A company is adding a clause to its AUP that states employees are not allowed to modify the operating system on mobile devices. Which of the following vulnerabilities is the organization addressing?",
        "options": [
            "Cross-site scripting",
            "Buffer overflow",
            "Jailbreaking",
            "Side loading"
        ],
        "answer": "Jailbreaking"
    },
    {
        "question": "Which of the following practices would be best to prevent an insider from introducing malicious code into a company's development process?",
        "options": [
            "Code scanning for vulnerabilities",
            "Open-source component usage",
            "Quality assurance testing",
            "Peer review and approval"
        ],
        "answer": "Peer review and approval"
    },
    {
        "question": "A systems administrator is creating a script that would save time and prevent human error when performing account creation for a large number of end users. Which of the following would be a good use case for this task?",
        "options": [
            "Off-the-shelf software",
            "Orchestration",
            "Baseline",
            "Policy enforcement"
        ],
        "answer": "Orchestration"
    },
    {
        "question": "After an audit, an administrator discovers all users have access to confidential data on a file server. Which of the following should the administrator use to restrict access to the data quickly?",
        "options": [
            "Group Policy",
            "Content filtering",
            "Data loss prevention",
            "Access control lists"
        ],
        "answer": "Access control lists"
    },
    {
        "question": "A Chief Information Security Officer (CISO) wants to explicitly raise awareness about the increase of ransomware-as-a-service in a report to the management team. Which of the following best describes the threat actor in the CISO's report?",
        "options": [
            "Insider threat",
            "Hacktivist",
            "Nation-state",
            "Organized crime"
        ],
        "answer": "Organized crime"
    },
    {
        "question": "A small business uses kiosks on the sales floor to display product information for customers. A security team discovers the kiosks use end-of-life operating systems. Which of the following is the security team most likely to document as a security implication of the current architecture?",
        "options": [
            "Patch availability",
            "Product software compatibility",
            "Ease of recovery",
            "Cost of replacement"
        ],
        "answer": "Patch availability"
    },
    {
        "question": "A company is developing a critical system for the government and storing project information on a fileshare. Which of the following describes how this data will most likely be classified? (Select two).",
        "options": [
            "Private",
            "Confidential",
            "Public",
            "Operational",
            "Urgent",
            "Restricted"
        ],
        "answer": [
            "Confidential",
            "Restricted"
        ]
    },
    {
        "question": "A security consultant needs secure, remote access to a client environment. Which of the following should the security consultant most likely use to gain access?",
        "options": [
            "EAP",
            "DHCP",
            "IPSec",
            "NAT"
        ],
        "answer": "IPSec"
    },
    {
        "question": "Which of the following best practices gives administrators a set period to perform changes to an operational system to ensure availability and minimize business impacts?",
        "options": [
            "Impact analysis",
            "Scheduled downtime",
            "Backout plan",
            "Change management boards"
        ],
        "answer": "Scheduled downtime"
    },
    {
        "question": "Which of the following actions could a security engineer take to ensure workstations and servers are properly monitored for unauthorized changes and software?",
        "options": [
            "Configure all systems to log scheduled tasks.",
            "Collect and monitor all traffic exiting the network.",
            "Block traffic based on known malicious signatures.",
            "Install endpoint management software on all systems."
        ],
        "answer": "Install endpoint management software on all systems."
    },
    {
        "question": "After a security awareness training session, a user called the IT help desk and reported a suspicious call. The suspicious caller stated that the Chief Financial Officer wanted credit card information in order to close an invoice. Which of the following topics did the user recognize from the training?",
        "options": [
            "Insider threat",
            "Email phishing",
            "Social engineering",
            "Executive whaling"
        ],
        "answer": "Social engineering"
    },
    {
        "question": "Which of the following exercises should an organization use to improve its incident response process?",
        "options": [
            "Tabletop",
            "Replication",
            "Failover",
            "Recovery"
        ],
        "answer": "Tabletop"
    },
    {
        "question": "Which of the following is used to validate a certificate when it is presented to a user?",
        "options": [
            "OCSP",
            "CSR",
            "CA",
            "CRC"
        ],
        "answer": "OCSP"
    },
    {
        "question": "A newly identified network access vulnerability has been found in the OS of legacy IoT devices. Which of the following would best mitigate this vulnerability quickly?",
        "options": [
            "Insurance",
            "Patching",
            "Segmentation",
            "Replacement"
        ],
        "answer": "Segmentation"
    },
    {
        "question": "A bank insists all of its vendors must prevent data loss on stolen laptops. Which of the following strategies is the bank requiring?",
        "options": [
            "Encryption at rest",
            "Masking",
            "Data classification",
            "Permission restrictions"
        ],
        "answer": "Encryption at rest"
    },
    {
        "question": "Which of the following would be best suited for constantly changing environments?",
        "options": [
            "RTOS",
            "Containers",
            "Embedded systems",
            "SCADA"
        ],
        "answer": "Containers"
    },
    {
        "question": "A security analyst scans a company's public network and discovers a host is running a remote desktop that can be used to access the production network. Which of the following changes should the security analyst recommend?",
        "options": [
            "Changing the remote desktop port to a non-standard number",
            "Setting up a VPN and placing the jump server inside the firewall",
            "Using a proxy for web connections from the remote desktop server",
            "Connecting the remote server to the domain and increasing the password length"
        ],
        "answer": "Setting up a VPN and placing the jump server inside the firewall"
    },
    {
        "question": "Which of the following involves an attempt to take advantage of database misconfigurations?",
        "options": [
            "Buffer overflow",
            "SQL injection",
            "VM escape",
            "Memory injection"
        ],
        "answer": "SQL injection"
    },
    {
        "question": "An organization would like to store customer data on a separate part of the network that is not accessible to users on the main corporate network. Which of the following should the administrator use to accomplish this goal?",
        "options": [
            "Segmentation",
            "Isolation",
            "Patching",
            "Encryption"
        ],
        "answer": "Segmentation"
    },
    {
        "question": "Which of the following is used to quantitatively measure the criticality of a vulnerability?",
        "options": [
            "CVE",
            "CVSS",
            "CIA",
            "CERT"
        ],
        "answer": "CVSS"
    },
    {
        "question": "A technician is opening ports on a firewall for a new system being deployed and supported by a SaaS provider. Which of the following is a risk in the new system?",
        "options": [
            "Default credentials",
            "Non-segmented network",
            "Supply chain vendor",
            "Vulnerable software"
        ],
        "answer": "Vulnerable software"
    },
    {
        "question": "Which of the following security concepts is the best reason for permissions on a human resources fileshare to follow the principle of least privilege?",
        "options": [
            "Integrity",
            "Availability",
            "Confidentiality",
            "Non-repudiation"
        ],
        "answer": "Confidentiality"
    },
    {
        "question": "Security controls in a data center are being reviewed to ensure data is properly protected and that human life considerations are included. Which of the following best describes how the controls should be set up?",
        "options": [
            "Remote access points should fail closed.",
            "Logging controls should fail open.",
            "Safety controls should fail open.",
            "Logical security controls should fail closed."
        ],
        "answer": "Safety controls should fail open."
    },
    {
        "question": "Which of the following is the most common data loss path for an air-gapped network?",
        "options": [
            "Bastion host",
            "Unsecured Bluetooth",
            "Unpatched OS",
            "Removable devices"
        ],
        "answer": "Removable devices"
    },
    {
        "question": "An organization is struggling with scaling issues on its VPN concentrator and internet circuit due to remote work. The organization is looking for a software solution that will allow it to reduce traffic on the VPN and internet circuit, while still providing encrypted tunnel access to the data center and monitoring of remote employee internet traffic. Which of the following will help achieve these objectives?",
        "options": [
            "Deploying a SASE solution to remote employees",
            "Building a load-balanced VPN solution with redundant internet",
            "Purchasing a low-cost SD-WAN solution for VPN traffic",
            "Using a cloud provider to create additional VPN concentrators"
        ],
        "answer": "Deploying a SASE solution to remote employees"
    },
    {
        "question": "A company's end users are reporting that they are unable to reach external websites. After reviewing the performance data for the DNS severs, the analyst discovers that the CPU, disk, and memory usage are minimal, but the network interface is flooded with inbound traffic. Network logs show only a small number of DNS queries sent to this server. Which of the following best describes what the security analyst is seeing?",
        "options": [
            "Concurrent session usage",
            "Secure DNS cryptographic downgrade",
            "On-path resource consumption",
            "Reflected denial of service"
        ],
        "answer": "Reflected denial of service"
    },
    {
        "question": "A systems administrator wants to prevent users from being able to access data based on their responsibilities. The administrator also wants to apply the required access structure via a simplified format. Which of the following should the administrator apply to the site recovery resource group?",
        "options": [
            "RBAC",
            "ACL",
            "SAML",
            "GPO"
        ],
        "answer": "RBAC"
    },
    {
        "question": "One of a company's vendors sent an analyst a security bulletin that recommends a BIOS update. Which of the following vulnerability types is being addressed by the patch?",
        "options": [
            "Virtualization",
            "Firmware",
            "Application",
            "Operating system"
        ],
        "answer": "Firmware"
    },
    {
        "question": "A security analyst locates a potentially malicious video file on a server and needs to identify both the creation date and the file's creator. Which of the following actions would most likely give the security analyst the information required?",
        "options": [
            "Obtain the file's SHA-256 hash",
            "Use hexdump on the file's contents",
            "Check endpoint logs",
            "Query the file's metadata"
        ],
        "answer": "Query the file's metadata"
    },
    {
        "question": "After a recent vulnerability scan, a security engineer needs to harden the routers within the corporate network. Which of the following is the most appropriate to disable?",
        "options": [
            "Console access",
            "Routing protocols",
            "VLANs",
            "Web-based administration"
        ],
        "answer": "Web-based administration"
    },
    {
        "question": "Which of the following should a systems administrator use to ensure an easy deployment of resources within the cloud provider?",
        "options": [
            "Software as a service",
            "Infrastructure as code",
            "Internet of Things",
            "Software-defined networking"
        ],
        "answer": "Infrastructure as code"
    },
    {
        "question": "An enterprise has been experiencing attacks focused on exploiting vulnerabilities in older browser versions with well-known exploits. Which of the following security solutions should be configured to best provide the ability to monitor and block these known signature-based attacks?",
        "options": [
            "ACL",
            "DLP",
            "IDS",
            "IPS"
        ],
        "answer": "IPS"
    },
    {
        "question": "During the onboarding process, an employee needs to create a password for an intranet account. The password must include ten characters, numbers, and letters, and two special characters. Once the password is created, the company will grant the employee access to other company-owned websites based on the intranet profile. Which of the following access management concepts is the company most likely using to safeguard intranet accounts and grant access to multiple sites based on a user's intranet account? (Select two).",
        "options": [
            "Federation",
            "Identity proofing",
            "Password complexity",
            "Default password changes",
            "Password manager",
            "Open authentication"
        ],
        "answer": [
            "Federation",
            "Password complexity"
        ]
    },
    {
        "question": "A security engineer is implementing FDE for all laptops in an organization. Which of the following are the most important for the engineer to consider as part of the planning process? (Select two).",
        "options": [
            "Key escrow",
            "TPM presence",
            "Digital signatures",
            "Data tokenization",
            "Public key management",
            "Certificate authority linking"
        ],
        "answer": [
            "Key escrow",
            "TPM presence"
        ]
    },
    {
        "question": "A hacker gained access to a system via a phishing attempt that was a direct result of a user clicking a suspicious link. The link laterally deployed ransomware, which laid dormant for multiple weeks, across the network. Which of the following would have mitigated the spread?",
        "options": [
            "IPS",
            "IDS",
            "WAF",
            "UAT"
        ],
        "answer": "IPS"
    },
    {
        "question": "Which of the following threat actors is the most likely to be hired by a foreign government to attack critical systems located in other countries?",
        "options": [
            "Hacktivist",
            "Whistleblower",
            "Organized crime",
            "Unskilled attacker"
        ],
        "answer": "Organized crime"
    },
    {
        "question": "Which of the following is used to add extra complexity before using a one-way data transformation algorithm?",
        "options": [
            "Key stretching",
            "Data masking",
            "Steganography",
            "Salting"
        ],
        "answer": "Salting"
    },
    {
        "question": "An employee clicked a link in an email from a payment website that asked the employee to update contact information. The employee entered the log-in information but received a 'page not found' error message. Which of the following types of social engineering attacks occurred?",
        "options": [
            "Brand impersonation",
            "Pretexting",
            "Typosquatting",
            "Phishing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An enterprise is trying to limit outbound DNS traffic originating from its internal network. Outbound DNS requests will only be allowed from one device with the IP address 10.50.10.25. Which of the following firewall ACLs will accomplish this goal?",
        "options": [
            "Access list outbound permit 0.0.0.0 0 0.0.0.0/0 port 53",
            "Access list outbound permit 0.0.0.0/0 10.50.10.25 32 port 53",
            "Access list outbound permit 0.0.0.0 0 0.0.0.0/0 port 53",
            "Access list outbound permit 10.50.10.25 32 0.0.0.0/0 port 53"
        ],
        "answer": "Access list outbound permit 10.50.10.25 32 0.0.0.0/0 port 53"
    },
    {
        "question": "A data administrator is configuring authentication for a SaaS application and would like to reduce the number of credentials employees need to maintain. The company prefers to use domain credentials to access new SaaS applications. Which of the following methods would allow this functionality?",
        "options": [
            "SSO",
            "LEAP",
            "MFA",
            "PEAP"
        ],
        "answer": "SSO"
    },
    {
        "question": "Which of the following scenarios describes a possible business email compromise attack?",
        "options": [
            "An employee receives a gift card request in an email that has an executive's name in the display field of the email.",
            "Employees who open an email attachment receive messages demanding payment in order to access files.",
            "A service desk employee receives an email from the HR director asking for log-in credentials to a cloud administrator account.",
            "An employee receives an email with a link to a phishing site that is designed to look like the company's email portal."
        ],
        "answer": "A service desk employee receives an email from the HR director asking for log-in credentials to a cloud administrator account."
    },
    {
        "question": "A company prevented direct access from the database administrators' workstations to the network segment that contains database servers. Which of the following should a database administrator use to access the database servers?",
        "options": [
            "Jump server",
            "RADIUS",
            "HSM",
            "Load balancer"
        ],
        "answer": "Jump server"
    },
    {
        "question": "An organization's internet-facing website was compromised when an attacker exploited a buffer overflow. Which of the following should the organization deploy to best protect against similar attacks in the future?",
        "options": [
            "NGFW",
            "WAF",
            "TLS",
            "SD-WAN"
        ],
        "answer": "WAF"
    },
    {
        "question": "An administrator notices that several users are logging in from suspicious IP addresses. After speaking with the users, the administrator determines that the employees were not logging in from those IP addresses and resets the affected users' passwords. Which of the following should the administrator implement to prevent this type of attack from succeeding in the future?",
        "options": [
            "Multifactor authentication",
            "Permissions assignment",
            "Access management",
            "Password complexity"
        ],
        "answer": "Multifactor authentication"
    },
    {
        "question": "An employee receives a text message that appears to have been sent by the payroll department and is asking for credential verification. Which of the following social engineering techniques are being attempted? (Choose two.)",
        "options": [
            "Typosquatting",
            "Phishing",
            "Impersonation",
            "Vishing",
            "Smishing",
            "Misinformation"
        ],
        "answer": [
            "Impersonation",
            "Smishing"
        ]
    },
    {
        "question": "Several employees received a fraudulent text message from someone claiming to be the Chief Executive Officer (CEO). The message stated: 'I'm in an airport right now with no access to email. I need you to buy gift cards for employee recognition awards. Please send the gift cards to following email address.' Which of the following are the best responses to this situation? (Choose two).",
        "options": [
            "Cancel current employee recognition gift cards.",
            "Add a smishing exercise to the annual company training.",
            "Issue a general email warning to the company.",
            "Have the CEO change phone numbers.",
            "Conduct a forensic investigation on the CEO's phone.",
            "Implement mobile device management."
        ],
        "answer": [
            "Add a smishing exercise to the annual company training.",
            "Issue a general email warning to the company."
        ]
    },
    {
        "question": "An organization wants a third-party vendor to do a penetration test that targets a specific device. The organization has provided basic information about the device. Which of the following best describes this kind of penetration test?",
        "options": [
            "Partially known environment",
            "Unknown environment",
            "Integrated",
            "Known environment"
        ],
        "answer": "Partially known environment"
    },
    {
        "question": "An attacker posing as the Chief Executive Officer calls an employee and instructs the employee to buy gift cards. Which of the following techniques is the attacker using?",
        "options": [
            "Smishing",
            "Disinformation",
            "Impersonating",
            "Whaling"
        ],
        "answer": "Whaling"
    },
    {
        "question": "An analyst is evaluating the implementation of Zero Trust principles within the data plane. Which of the following would be most relevant for the analyst to evaluate?",
        "options": [
            "Secured zones",
            "Subject role",
            "Adaptive identity",
            "Threat scope reduction"
        ],
        "answer": "Subject role"
    },
    {
        "question": "An organization is leveraging a VPN between its headquarters and a branch location. Which of the following is the VPN protecting?",
        "options": [
            "Data in use",
            "Data in transit",
            "Geographic restrictions",
            "Data sovereignty"
        ],
        "answer": "Data in transit"
    },
    {
        "question": "The marketing department set up its own project management software without telling the appropriate departments. Which of the following describes this scenario?",
        "options": [
            "Shadow IT",
            "Insider threat",
            "Data exfiltration",
            "Service disruption"
        ],
        "answer": "Shadow IT"
    },
    {
        "question": "A company wants to verify that the software the company is deploying came from the vendor the company purchased the software from. Which of the following is the best way for the company to confirm this information?",
        "options": [
            "Validate the code signature",
            "Execute the code in a sandbox",
            "Search the executable for ASCII strings",
            "Generate a hash of the files"
        ],
        "answer": "Validate the code signature"
    },
    {
        "question": "After a security incident, a systems administrator asks the company to buy a NAC platform. Which of the following attack surfaces is the systems administrator trying to protect?",
        "options": [
            "Bluetooth",
            "Wired",
            "NFC",
            "SCADA"
        ],
        "answer": "Wired"
    },
    {
        "question": "Which of the following factors are the most important to address when formulating a training curriculum plan for a security awareness program? (Select two).",
        "options": [
            "Channels by which the organization communicates with customers",
            "The reporting mechanisms for ethics violations",
            "Threat vectors based on the industry in which the organization operates",
            "Secure software development training for all personnel",
            "Cadence and duration of training events",
            "Retraining requirements for individuals who fail phishing simulations"
        ],
        "answer": [
            "Threat vectors based on the industry in which the organization operates",
            "Cadence and duration of training events"
        ]
    },
    {
        "question": "An organization disabled unneeded services and placed a firewall in front of a business-critical legacy system. Which of the following best describes the actions taken by the organization?",
        "options": [
            "Exception",
            "Segmentation",
            "Risk transfer",
            "Compensating controls"
        ],
        "answer": "Compensating controls"
    },
    {
        "question": "A company is required to use certified hardware when building networks. Which of the following best addresses the risks associated with procuring counterfeit hardware?",
        "options": [
            "A thorough analysis of the supply chain",
            "A legally enforceable corporate acquisition policy",
            "A right to audit clause in vendor contracts and SOWs",
            "An in-depth penetration test of all suppliers and vendors"
        ],
        "answer": "A thorough analysis of the supply chain"
    },
    {
        "question": "Which of the following provides the details about the terms of a test with a third-party penetration tester?",
        "options": [
            "Rules of engagement",
            "Supply chain analysis",
            "Right to audit clause",
            "Due diligence"
        ],
        "answer": "Rules of engagement"
    },
    {
        "question": "A penetration tester begins an engagement by performing port and service scans against the client environment according to the rules of engagement. Which of the following reconnaissance types is the tester performing?",
        "options": [
            "Active",
            "Passive",
            "Defensive",
            "Offensive"
        ],
        "answer": "Active"
    },
    {
        "question": "Which of the following is required for an organization to properly manage its restore process in the event of system failure?",
        "options": [
            "IRP",
            "DRP",
            "RPO",
            "SDLC"
        ],
        "answer": "DRP"
    },
    {
        "question": "Which of the following vulnerabilities is associated with installing software outside of a manufacturer's approved software repository?",
        "options": [
            "Jailbreaking",
            "Memory injection",
            "Resource reuse",
            "Side loading"
        ],
        "answer": "Side loading"
    },
    {
        "question": "A security analyst is reviewing the following logs: Which of the following attacks is most likely occurring?",
        "options": [
            "Password spraying",
            "Account forgery",
            "Pass-the-hash",
            "Brute-force"
        ],
        "answer": "Password spraying"
    },
    {
        "question": "A systems administrator receives the following alert from a file integrity monitoring tool: The hash of the cmd.exe file has changed. The systems administrator checks the OS logs and notices that no patches were applied in the last two months. Which of the following most likely occurred?",
        "options": [
            "The end user changed the file permissions",
            "A cryptographic collision was detected",
            "A snapshot of the file system was taken",
            "A rootkit was deployed"
        ],
        "answer": "A rootkit was deployed"
    },
    {
        "question": "An engineer needs to find a solution that creates an added layer of security by preventing unauthorized access to internal company resources. Which of the following would be the best solution?",
        "options": [
            "RDP server",
            "Jump server",
            "Proxy server",
            "Hypervisor"
        ],
        "answer": "Jump server"
    },
    {
        "question": "A company's web filter is configured to scan the URL for strings and deny access when matches are found. Which of the following search strings should an analyst employ to prohibit access to non-encrypted websites?",
        "options": [
            "encryption=off",
            "http://",
            "www.*.com",
            ":443"
        ],
        "answer": "http://"
    },
    {
        "question": "During a security incident, the security operations team identified sustained network traffic from a malicious IP address: 10.1.4.9. A security analyst is creating an inbound firewall rule to block the IP address from accessing the organization's network. Which of the following fulfills this request?",
        "options": [
            "access-list inbound deny ip source 0.0.0.0/0 destination 10.1.4.9/32",
            "access-list inbound deny ip source 10.1.4.9/32 destination 0.0.0.0/0",
            "access-list inbound permit ip source 10.1.4.9/32 destination 0.0.0.0/0",
            "access-list inbound permit ip source 0.0.0.0/0 destination 10.1.4.9/32"
        ],
        "answer": "access-list inbound deny ip source 10.1.4.9/32 destination 0.0.0.0/0"
    },
    {
        "question": "A company needs to provide administrative access to internal resources while minimizing the traffic allowed through the security boundary. Which of the following methods is most secure?",
        "options": [
            "Implementing a bastion host",
            "Deploying a perimeter network",
            "Installing a WAF",
            "Utilizing single sign-on"
        ],
        "answer": "Implementing a bastion host"
    },
    {
        "question": "Which of the following is the most likely to be used to document risks, responsible parties, and thresholds?",
        "options": [
            "Risk tolerance",
            "Risk transfer",
            "Risk register",
            "Risk analysis"
        ],
        "answer": "Risk register"
    },
    {
        "question": "Which of the following should a security administrator adhere to when setting up a new set of firewall rules?",
        "options": [
            "Disaster recovery plan",
            "Incident response procedure",
            "Business continuity plan",
            "Change management procedure"
        ],
        "answer": "Change management procedure"
    },
    {
        "question": "A company is expanding its threat surface program and allowing individuals to security test the company's internet-facing application. The company will compensate researchers based on the vulnerabilities discovered. Which of the following best describes the program the company is setting up?",
        "options": [
            "Open-source intelligence",
            "Bug bounty",
            "Red team",
            "Penetration testing"
        ],
        "answer": "Bug bounty"
    },
    {
        "question": "Which of the following threat actors is the most likely to use large financial resources to attack critical systems located in other countries?",
        "options": [
            "Insider",
            "Unskilled attacker",
            "Nation-state",
            "Hacktivist"
        ],
        "answer": "Nation-state"
    },
    {
        "question": "Which of the following enables the use of an input field to run commands that can view or manipulate data?",
        "options": [
            "Cross-site scripting",
            "Side loading",
            "Buffer overflow",
            "SQL injection"
        ],
        "answer": "SQL injection"
    },
    {
        "question": "Employees in the research and development business unit receive extensive training to ensure they understand how to best protect company data. Which of the following is the type of data these employees are most likely to use in day-to-day work activities?",
        "options": [
            "Encrypted",
            "Intellectual property",
            "Critical",
            "Data in transit"
        ],
        "answer": "Intellectual property"
    },
    {
        "question": "A company has begun labeling all laptops with asset inventory stickers and associating them with employee IDs. Which of the following security benefits do these actions provide? (Choose two.)",
        "options": [
            "If a security incident occurs on the device, the correct employee can be notified.",
            "The security team will be able to send user awareness training to the appropriate device.",
            "Users can be mapped to their devices when configuring software MFA tokens.",
            "User-based firewall policies can be correctly targeted to the appropriate laptops.",
            "When conducting penetration testing, the security team will be able to target the desired laptops.",
            "Company data can be accounted for when the employee leaves the organization."
        ],
        "answer": [
            "If a security incident occurs on the device, the correct employee can be notified.",
            "Company data can be accounted for when the employee leaves the organization."
        ]
    },
    {
        "question": "A technician wants to improve the situational and environmental awareness of existing users as they transition from remote to in-office work. Which of the following is the best option?",
        "options": [
            "Send out periodic security reminders",
            "Update the content of new hire documentation",
            "Modify the content of recurring training",
            "Implement a phishing campaign"
        ],
        "answer": "Modify the content of recurring training"
    },
    {
        "question": "A newly appointed board member with cybersecurity knowledge wants the board of directors to receive a quarterly report detailing the number of incidents that impacted the organization. The systems administrator is creating a way to present the data to the board of directors. Which of the following should the systems administrator use?",
        "options": [
            "Packet captures",
            "Vulnerability scans",
            "Metadata",
            "Dashboard"
        ],
        "answer": "Dashboard"
    },
    {
        "question": "Which of the following are the most likely vectors for the unauthorized or unintentional inclusion of vulnerable code in a software company's final software releases? (Choose two).",
        "options": [
            "Certificate mismatch",
            "Use of penetration-testing utilities",
            "Weak passwords",
            "Included third-party libraries",
            "Vendors/supply chain",
            "Outdated anti-malware software"
        ],
        "answer": [
            "Included third-party libraries",
            "Vendors/supply chain"
        ]
    },
    {
        "question": "Which of the following are common VoIP-associated vulnerabilities? (Choose two).",
        "options": [
            "SPIM",
            "Vishing",
            "VLAN hopping",
            "Phishing",
            "DHCP snooping",
            "Tailgating"
        ],
        "answer": [
            "SPIM",
            "Vishing"
        ]
    },
    {
        "question": "Which of the following best describes the 'A' in CIA?",
        "options": [
            "Data is protected from unauthorized changes.",
            "Information can be accessed by the right people.",
            "Information is always accurate and truthful.",
            "The organization's systems are up and operational."
        ],
        "answer": "The organization's systems are up and operational."
    },
    {
        "question": "Which of the following technical controls should be implemented to safeguard data in cloud-based services while the data is in transit and at rest?",
        "options": [
            "Data masking",
            "Geolocation",
            "Encryption",
            "Snapshots"
        ],
        "answer": "Encryption"
    },
    {
        "question": "Which of the following is the primary objective of a post-incident review in incident response?",
        "options": [
            "Eliminating the attacker",
            "Improving processes",
            "Documenting evidence",
            "Remediating controls"
        ],
        "answer": "Improving processes"
    },
    {
        "question": "Which of the following is the most likely result of a change control process that is managed improperly?",
        "options": [
            "Patch management is ineffective.",
            "Regulatory standards are followed.",
            "Stakeholders are updated regularly.",
            "Security updates are applied in a timely manner."
        ],
        "answer": "Patch management is ineffective."
    },
    {
        "question": "Which of the following settings must be configured on endpoints to prevent unknown applications from executing on systems?",
        "options": [
            "Registry key",
            "Cryptographic library",
            "Application allow list",
            "Host firewall"
        ],
        "answer": "Application allow list"
    },
    {
        "question": "A company's Chief Executive Officer is concerned that the systems are susceptible to social engineering. Which of the following would best address this concern?",
        "options": [
            "Encryption",
            "DNSSEC",
            "Training",
            "Firewall"
        ],
        "answer": "Training"
    },
    {
        "question": "A Chief Executive Officer hires an outside consultant to perform a penetration test of the network and the company's web applications. Which of the following will the consultant perform if the consultant uses a black-box testing methodology?",
        "options": [
            "All the company's physical security controls will be tested.",
            "Only the company’s web applications will be tested.",
            "The consultant will test all the company’s applications.",
            "The consultant will not have access to any company resources."
        ],
        "answer": "The consultant will not have access to any company resources."
    },
    {
        "question": "An organization is responding to an internal incident caused by an employee connecting to a file server over FTP. Which of the following is the most likely cause of the incident?",
        "options": [
            "Insider threat",
            "Cleartext credentials",
            "Rogue access point",
            "Weak encryption"
        ],
        "answer": "Cleartext credentials"
    },
    {
        "question": "A Chief Executive Officer requests that a new security solution be implemented to reduce the risk of unauthorized access to the internal network due to lost, stolen, or unapproved devices. Which of the following should be implemented?",
        "options": [
            "VPN concentrator",
            "NAC",
            "Proxies",
            "Content filter"
        ],
        "answer": "NAC"
    },
    {
        "question": "A Chief Executive Officer's daughter just lost her mobile phone. She uses the phone to communicate with her parent and play games. The Chief Executive Officer is concerned that their sensitive company emails could be intercepted. Which of the following would be the best method to protect the data in the future?",
        "options": [
            "Enable full device encryption",
            "Install mobile antivirus software",
            "Lock the device with a pattern lock",
            "Implement mobile remote wipe"
        ],
        "answer": "Implement mobile remote wipe"
    },
    {
        "question": "An attacker captures the encrypted communication between two parties and then uses cryptanalysis to try to decipher the key. Which of the following attacks is occurring?",
        "options": [
            "Side-channel",
            "Known plain text",
            "Man-in-the-middle",
            "Ciphertext only"
        ],
        "answer": "Ciphertext only"
    },
    {
        "question": "Which of the following will provide in-transit confidentiality protections for emails sent between the management team?",
        "options": [
            "Digital signatures",
            "IMAP",
            "SMTP",
            "Encryption"
        ],
        "answer": "Encryption"
    },
    {
        "question": "A company needs to increase the security posture of its environment by implementing a solution that will perform the following tasks: - Identify malicious software that could affect employee workstations - Prevent websites from capturing information about visited sites - Reduce the likelihood of successful malware installation - Block access to command-and-control servers Which of the following will best meet these requirements?",
        "options": [
            "Antivirus",
            "VPN",
            "Host-based firewall",
            "Web content filter"
        ],
        "answer": "Web content filter"
    },
    {
        "question": "A company is implementing a new data management system that will hold all company data and provide access to employees based on their role within the company. The goal of the implementation is to ensure employees only have access to data that is necessary for their role and nothing more. Which of the following will ensure this goal is met?",
        "options": [
            "SAML",
            "ACL",
            "DLP",
            "RBAC"
        ],
        "answer": "RBAC"
    },
    {
        "question": "An external attacker was able to gain access to a company by compromising an employee's home computer. Which of the following describes this type of attack?",
        "options": [
            "Physical access",
            "On-path",
            "Watering-hole",
            "Supply chain"
        ],
        "answer": "Watering-hole"
    },
    {
        "question": "An organization is planning to roll out a new antivirus solution. Which of the following should the organization consider first?",
        "options": [
            "Network performance",
            "Impact to the users",
            "Datacenter architecture",
            "Expected false-positive rate"
        ],
        "answer": "Impact to the users"
    },
    {
        "question": "A security engineer is conducting log analysis and identifies a malware outbreak caused by a user downloading an email attachment. The user downloaded the attachment, opened it, and unknowingly executed the malware. The engineer reviews the following log entries: Which of the following is the most likely method used to execute the payload?",
        "options": [
            "Remote script execution",
            "Command-line interface",
            "Unauthorized web shell",
            "SQL injection"
        ],
        "answer": "Command-line interface"
    },
    {
        "question": "A technician receives a call from a company's Chief Executive Officer regarding a suspicious email that was received. The email contains a PDF invoice that the Chief Executive Officer does not recognize. Which of the following should the technician do to determine if the file is safe?",
        "options": [
            "Check the email's DKIM.",
            "Download the file and open it on an isolated virtual machine.",
            "Analyze the file in a sandbox.",
            "Perform signature-based detection using antivirus software."
        ],
        "answer": "Analyze the file in a sandbox."
    },
    {
        "question": "A security administrator is implementing encryption on all laptops in a company. Which of the following should the administrator implement to allow for the quick restoration of data if a laptop is lost or stolen?",
        "options": [
            "TPM",
            "Key escrow",
            "Salting",
            "Hashing"
        ],
        "answer": "Key escrow"
    },
    {
        "question": "A security analyst reviews logs from a NAS appliance and notes the following: The administrator then reviews the following configuration settings: Which of the following should the administrator do to address the vulnerability?",
        "options": [
            "Disallow anonymous access.",
            "Create a new share for public access.",
            "Enable stronger encryption algorithms.",
            "Update the SMB to the latest version."
        ],
        "answer": "Disallow anonymous access."
    },
    {
        "question": "A network security team is investigating an alert within the SIEM for traffic to a known malicious IP address. The source of the traffic is coming from an employee's workstation. The team verifies that no other machines on the network are receiving or sending traffic to this IP address. Which of the following types of malware is the most likely cause of this traffic?",
        "options": [
            "RAT",
            "Worm",
            "Fileless virus",
            "Logic bomb"
        ],
        "answer": "RAT"
    },
    {
        "question": "An administrator needs to check a network segment for vulnerabilities. The administrator creates several different pieces of equipment, such as wireless access points, laptops, and desktops, with known vulnerabilities. The administrator then scans the network for all devices and notes the vulnerability matches. Which of the following techniques is the administrator using?",
        "options": [
            "Baselining",
            "Fingerprinting",
            "Differential analysis",
            "Operational context"
        ],
        "answer": "Fingerprinting"
    },
    {
        "question": "A security administrator is configuring a new firewall for a network and wants to prevent users from accessing unauthorized websites. Which of the following should the administrator configure?",
        "options": [
            "Web content filter",
            "Application control",
            "Antivirus",
            "DNS sinkhole"
        ],
        "answer": "Web content filter"
    },
    {
        "question": "A company hired a third party to conduct a security assessment on the corporate network. The third party performed a penetration test and found some critical vulnerabilities that could have been used to steal company information. The third party proposed some technical solutions to fix the vulnerabilities. Which of the following risk management strategies did the company adopt?",
        "options": [
            "Mitigation",
            "Avoidance",
            "Acceptance",
            "Transference"
        ],
        "answer": "Mitigation"
    },
    {
        "question": "Which of the following is the most likely objective of a nation-state utilizing a zero-day vulnerability to attack a software company?",
        "options": [
            "Financial gain",
            "Competitive advantage",
            "Critical infrastructure",
            "Intellectual property"
        ],
        "answer": "Intellectual property"
    },
    {
        "question": "A company recently performed a security audit and discovered that several of its switches had not been patched and were vulnerable to CVE-2018-5711. Which of the following types of vulnerabilities were discovered?",
        "options": [
            "Privilege escalation",
            "Software misconfiguration",
            "Zero day",
            "Unsecure protocols"
        ],
        "answer": "Software misconfiguration"
    },
    {
        "question": "Which of the following components is used to attach public keys to previously agreed-upon shared secrets?",
        "options": [
            "MD5",
            "RSA",
            "PEM",
            "HMAC"
        ],
        "answer": "HMAC"
    },
    {
        "question": "Which of the following should an administrator configure on endpoints to prevent host enumeration by a network scanner?",
        "options": [
            "DLP",
            "EPP",
            "VPN",
            "HIPS"
        ],
        "answer": "HIPS"
    },
    {
        "question": "A systems administrator is configuring a NAS solution for a company. All the data on the NAS must be available in the event of a disaster. The solution must also minimize the recovery time if data on the NAS becomes corrupted. Which of the following configuration settings would best meet these requirements?",
        "options": [
            "Journaling",
            "WORM",
            "Snapshot",
            "Deduplication"
        ],
        "answer": "Snapshot"
    },
    {
        "question": "A company wants to implement a new secure backup solution for the following: - Workstations, servers, and network devices are the targets of the backup. - Confidentiality must be assured. - Data must be encrypted. Which of the following should be implemented? (Select two).",
        "options": [
            "Hardware encryption",
            "Software encryption",
            "Performance baseline",
            "Network baseline",
            "Load balancers",
            "Test restorations"
        ],
        "answer": [
            "Hardware encryption",
            "Software encryption"
        ]
    },
    {
        "question": "Which of the following is a technical control?",
        "options": [
            "Firewall rules",
            "Locking hardware",
            "Retraining employees",
            "Monitoring agent"
        ],
        "answer": "Firewall rules"
    },
    {
        "question": "A company wants to implement a certificate management policy that will integrate with the Active Directory infrastructure. Which of the following should the company implement?",
        "options": [
            "Wildcard certificate",
            "Self-signed certificate",
            "Extended validation certificate",
            "Private CA"
        ],
        "answer": "Private CA"
    },
    {
        "question": "Which of the following vulnerability types would allow an attacker to inject malicious code into a system's memory?",
        "options": [
            "Buffer overflow",
            "Privilege escalation",
            "Resource exhaustion",
            "Memory leak"
        ],
        "answer": "Buffer overflow"
    },
    {
        "question": "A security administrator receives reports of slow connections on a company system. The administrator reviews network utilization and discovers that traffic is at 500 Mbps and should be only 200 Mbps. This is an example of which of the following attacks?",
        "options": [
            "Jamming",
            "Man-in-the-middle",
            "On-path",
            "Distributed denial of service"
        ],
        "answer": "Distributed denial of service"
    },
    {
        "question": "Which of the following documents provides the reason for an information security change?",
        "options": [
            "MOA",
            "BIA",
            "BPA",
            "RFQ"
        ],
        "answer": "BIA"
    },
    {
        "question": "A server needs to be able to verify data sent to it and ensure data integrity. Which of the following encryption algorithms should the server use?",
        "options": [
            "Diffie-Hellman",
            "RSA",
            "SHA",
            "DES"
        ],
        "answer": "SHA"
    },
    {
        "question": "A technician is investigating an issue with a wireless access point in a common area. All SSIDs are working except the guest SSID. Which of the following is most likely the problem?",
        "options": [
            "SSIDs on other bands are working.",
            "Other SSIDs do not have the same password.",
            "The guest SSID uses WPA.",
            "The guest SSID uses 5GHz."
        ],
        "answer": "The guest SSID uses 5GHz."
    },
    {
        "question": "An analyst is reviewing a SIEM incident report. The report indicates several computers on the production network that are not protected by antivirus software have been infected with a zero-day virus. The computers are not patched properly. Which of the following would be the best mitigation strategy for preventing future infections?",
        "options": [
            "Installing a proxy server",
            "Segmenting the network",
            "Updating the software firewall",
            "Utilizing email filtering"
        ],
        "answer": "Segmenting the network"
    },
    {
        "question": "An administrator needs to set up network segmentation in a SCADA system to best protect it from attackers. Which of the following should the administrator implement?",
        "options": [
            "A jump box",
            "A proxy server",
            "A firewall",
            "An air gap"
        ],
        "answer": "An air gap"
    },
    {
        "question": "A security operations center analyst received a call from a business unit stating that an employee was possibly involved in the exfiltration of proprietary data to a competitor. Which of the following should be the next step?",
        "options": [
            "Perform a vulnerability scan.",
            "Review logs and services.",
            "Contact the forensic investigator.",
            "Verify that chain of custody is followed."
        ],
        "answer": "Contact the forensic investigator."
    },
    {
        "question": "A server that was used to host a database will be repurposed to host a new application. The administrator needs to securely remove the confidential customer data from the system to ensure that it cannot be recovered. Which of the following would be the best method for the administrator to use?",
        "options": [
            "Degaussing",
            "Wiping",
            "Overwriting",
            "Repartitioning"
        ],
        "answer": "Wiping"
    },
    {
        "question": "A security administrator discovered several unauthorized devices on the network and wants to proactively stop this from happening again. Which of the following should the administrator implement?",
        "options": [
            "Change management",
            "User training",
            "NAC",
            "Incident response"
        ],
        "answer": "NAC"
    },
    {
        "question": "A network engineer is designing a secure tunneled VPN. The network engineer has implemented IPSec and needs to ensure that the ESP protocol will work correctly within the VPN tunnel. Which of the following ports must be allowed?",
        "options": [
            "22",
            "50",
            "51",
            "1701"
        ],
        "answer": "50"
    },
    {
        "question": "Which of the following encryption algorithms would be the most efficient for a low-power mobile device?",
        "options": [
            "DES",
            "AES",
            "ECC",
            "SHA-1"
        ],
        "answer": "ECC"
    },
    {
        "question": "Which of the following policies establishes the requirements for user access to the network?",
        "options": [
            "Social media",
            "Acceptable use",
            "Account management",
            "Code of conduct"
        ],
        "answer": "Acceptable use"
    },
    {
        "question": "A company was recently compromised by a known threat actor. The company wants to exchange threat information with trusted partners to enable better detection and response to potential threats. Which of the following would be the best way to accomplish this?",
        "options": [
            "CA",
            "PKI",
            "IaaS",
            "STIX"
        ],
        "answer": "STIX"
    },
    {
        "question": "An organization is concerned with data loss on a file server due to ransomware. The systems administrator is configuring the file server to maintain snapshots. Which of the following should the systems administrator use to increase the likelihood of a successful file recovery?",
        "options": [
            "SaaS",
            "PaaS",
            "IaaS",
            "DaaS"
        ],
        "answer": "SaaS"
    },
    {
        "question": "Which of the following cloud security solutions would be best suited for detecting a cryptocurrency mining application?",
        "options": [
            "EPP",
            "CASB",
            "SWG",
            "FWaaS"
        ],
        "answer": "CASB"
    },
    {
        "question": "An organization has decided to migrate a portion of its mission-critical applications to the cloud to increase availability. As part of the migration, the organization will change its current infrastructure and threat detection mechanisms. The organization's security administrator must ensure the new cloud infrastructure meets its security requirements. Which of the following should the security administrator do first?",
        "options": [
            "Integrate the new applications into the SIEM.",
            "Review the security requirements in the SLAs.",
            "Remove the organization's current threat detection mechanisms.",
            "Configure the new infrastructure to use the organization's existing threat detection policies."
        ],
        "answer": "Review the security requirements in the SLAs."
    },
    {
        "question": "Which of the following protocols would be the most appropriate for securely logging into a remote server?",
        "options": [
            "SSL",
            "SSH",
            "HTTP",
            "FTP"
        ],
        "answer": "SSH"
    },
    {
        "question": "A security administrator has been asked to implement a solution that allows the company to respond to new threats in a timely manner. Which of the following should the security administrator implement?",
        "options": [
            "Automated patch management",
            "Continuous monitoring",
            "Manual incident response",
            "Scheduled penetration testing"
        ],
        "answer": "Continuous monitoring"
    },
    {
        "question": "Which of the following best describes the process of overwriting data to destroy original information on storage media so that it is no longer readable?",
        "options": [
            "Data masking",
            "Degaussing",
            "Zeroizing",
            "Scrubbing"
        ],
        "answer": "Scrubbing"
    },
    {
        "question": "Which of the following is the best way to ensure that a company's employees are adhering to a company's security policies?",
        "options": [
            "Conducting security awareness training",
            "Performing a qualitative risk assessment",
            "Implementing an internal auditing process",
            "Disabling generic accounts"
        ],
        "answer": "Implementing an internal auditing process"
    },
    {
        "question": "A company had a compromise that involved a malicious insider exfiltrating data to a competitor. Which of the following solutions would help mitigate this threat in the future?",
        "options": [
            "An IPS",
            "A proxy",
            "UAM",
            "NIDS"
        ],
        "answer": "UAM"
    },
    {
        "question": "A company's sales department is concerned about the availability of the business system during its busy season. Which of the following would be the best way for the security team to address the department's concern?",
        "options": [
            "Performing a business impact analysis",
            "Completing a quantitative risk analysis",
            "Conducting a table top exercise",
            "Updating the disaster recovery plan"
        ],
        "answer": "Performing a business impact analysis"
    },
    {
        "question": "A security analyst is configuring a site-to-site VPN connection. The analyst needs to ensure the entire data flow between both sites is encrypted and authenticated. Which of the following should the analyst implement?",
        "options": [
            "TLS",
            "Transport mode",
            "ESP",
            "SFTP"
        ],
        "answer": "ESP"
    },
    {
        "question": "Which of the following would be the best control to prevent shadow IT?",
        "options": [
            "Establish a cloud approval process.",
            "Configure an IPS.",
            "Update the AUP.",
            "Complete annual security training."
        ],
        "answer": "Establish a cloud approval process."
    },
    {
        "question": "Which of the following would most likely be reviewed during a qualitative risk analysis?",
        "options": [
            "ALE",
            "ARO",
            "Exposure factor",
            "KRI"
        ],
        "answer": "KRI"
    },
    {
        "question": "A company that uses a cloud infrastructure has hired an outside firm to evaluate the company's data security. The firm has been instructed to interact only with the network layer and the security team. Which of the following types of testing will be performed?",
        "options": [
            "Gray box",
            "Black box",
            "White box",
            "Blue team"
        ],
        "answer": "Gray box"
    },
    {
        "question": "Which of the following activities must be included when developing a disaster recovery plan?",
        "options": [
            "Implementing a spam filter",
            "Updating the site map",
            "Creating a data retention policy",
            "Completing a business impact analysis"
        ],
        "answer": "Completing a business impact analysis"
    },
    {
        "question": "A company recently implemented a new email filtering system. The email filtering system blocks emails with the following conditions: - The email has a malformed URL - The email is missing the reply-to field - The email has a subject with multiple exclamation marks Which of the following types of attacks is the email filter trying to block?",
        "options": [
            "Whaling",
            "Impersonation",
            "Phishing",
            "On-path"
        ],
        "answer": "Phishing"
    },
    {
        "question": "Which of the following incident response steps comes before recovery?",
        "options": [
            "Detection",
            "Eradication",
            "Containment",
            "Lessons learned"
        ],
        "answer": "Eradication"
    },
    {
        "question": "A company has requested that its users be given access to the corporate directory and email services. The company also wants to restrict access to sensitive systems based on user roles. Which of the following will provide the best solution?",
        "options": [
            "Multi-factor authentication",
            "SSO",
            "OTP",
            "Biometrics"
        ],
        "answer": "SSO"
    },
    {
        "question": "Which of the following should a security analyst use to ensure the integrity of an operating system?",
        "options": [
            "FDE",
            "CASB",
            "SCAP",
            "SAST"
        ],
        "answer": "SCAP"
    },
    {
        "question": "Which of the following allows for data-at-rest encryption for cloud storage?",
        "options": [
            "AES",
            "DES",
            "SSL",
            "TLS"
        ],
        "answer": "AES"
    },
    {
        "question": "A company's enterprise security gateway uses TLS inspection. Which of the following will most likely be a consideration when implementing this configuration?",
        "options": [
            "The encryption key size",
            "The supported ciphers",
            "The certificate chain",
            "The traffic analysis"
        ],
        "answer": "The certificate chain"
    },
    {
        "question": "A company is implementing a new wireless infrastructure for their remote offices and wants to use strong encryption with minimal overhead on their older devices. Which of the following should they use?",
        "options": [
            "WPA2",
            "WPA",
            "WEP",
            "AES"
        ],
        "answer": "WPA2"
    },
    {
        "question": "Which of the following should a security administrator consider when deploying a SIEM system with the goal of effective reporting on critical security incidents?",
        "options": [
            "Log collection points",
            "Log forwarding frequency",
            "Log correlation",
            "Log encryption"
        ],
        "answer": "Log correlation"
    },
    {
        "question": "A company recently started using a cloud-based storage service, but employees are able to access the service only while on the internal network. Which of the following would best allow the employees to access the storage service when working from home?",
        "options": [
            "Site-to-site VPN",
            "SSL inspection",
            "Split-tunnel VPN",
            "Reverse proxy"
        ],
        "answer": "Split-tunnel VPN"
    },
    {
        "question": "A company is moving into a new building with a data center and wants to implement a new physical security plan. Which of the following should the company consider? (Choose two.)",
        "options": [
            "Identity proofing",
            "Lock types",
            "Background checks",
            "EAP-TLS",
            "Biometrics",
            "Video surveillance"
        ],
        "answer": [
            "Lock types",
            "Video surveillance"
        ]
    },
    {
        "question": "Which of the following types of controls should be put in place to detect and prevent illicit activity and meet regulatory compliance requirements for an organization?",
        "options": [
            "Administrative",
            "Technical",
            "Physical",
            "Logical"
        ],
        "answer": "Administrative"
    },
    {
        "question": "An analyst is reviewing multiple SIEM reports that show the corporation is experiencing increased DNS traffic to and from several IP addresses. Which of the following will the analyst most likely report during the upcoming briefing?",
        "options": [
            "Zero-day attack",
            "Domain hijacking",
            "Unauthorized resource usage",
            "Malicious traffic"
        ],
        "answer": "Malicious traffic"
    },
    {
        "question": "A company recently experienced an attack where an external host was able to connect to the RDP port of a server. Which of the following would best prevent this from happening again?",
        "options": [
            "IDS",
            "MAC filtering",
            "Firewall rule",
            "Proxy server"
        ],
        "answer": "Firewall rule"
    },
    {
        "question": "A company's audit department has requested a list of cloud solutions that adhere to the company's security policies and industry best practices. Which of the following should the company implement?",
        "options": [
            "IaaS",
            "DLP",
            "CASB",
            "SDN"
        ],
        "answer": "CASB"
    },
    {
        "question": "A company's Chief Information Officer is concerned about the number of items running on its production systems. The Chief Information Officer wants to install only the minimum number of items required for each role. Which of the following is the solution the Chief Information Officer wants to implement?",
        "options": [
            "Least functionality",
            "Application allow list",
            "Least privilege",
            "Network segmentation"
        ],
        "answer": "Least functionality"
    },
    {
        "question": "An attacker is trying to exfiltrate large amounts of data from the network and is running into issues. The attacker tries to bypass the network-based DLP solution by sending zipped files. Which of the following is the DLP most likely configured to analyze?",
        "options": [
            "Compression ratio",
            "File name",
            "File hashing",
            "Content matching"
        ],
        "answer": "Compression ratio"
    },
    {
        "question": "An analyst is reviewing logs and notices an IP address on the network is connected to a high number of out-of-state IP addresses. Which of the following best describes the type of malware the analyst has discovered?",
        "options": [
            "Botnet",
            "RAT",
            "Keylogger",
            "Adware"
        ],
        "answer": "Botnet"
    },
    {
        "question": "A company allows employees to use a personal social media account from company-provided laptops. The company is concerned that employees are posting information about the company, its customers, and partners. Which of the following would be best to help mitigate this issue?",
        "options": [
            "Web content filter",
            "MOU",
            "NDA",
            "AUP"
        ],
        "answer": "AUP"
    },
    {
        "question": "A company provides mobile devices to employees but has experienced several incidents of the devices being stolen. Which of the following controls would best help mitigate the impact of the theft?",
        "options": [
            "Data loss prevention",
            "Screen locks",
            "Mobile antivirus",
            "Full-device encryption"
        ],
        "answer": "Full-device encryption"
    },
    {
        "question": "Which of the following should be an important consideration when developing a vulnerability scan schedule for an environment?",
        "options": [
            "Asset inventory",
            "Change management",
            "Log aggregation",
            "System logs"
        ],
        "answer": "Change management"
    },
    {
        "question": "A security analyst needs to share intelligence information about a company's identified threat with the other organizations in the same industry. Which of the following will the security analyst most likely use?",
        "options": [
            "ISAC",
            "STIX",
            "TTP",
            "TLP"
        ],
        "answer": "ISAC"
    },
    {
        "question": "A company needs to achieve confidentiality for its business data, and the Chief Executive Officer does not want to spend a significant amount of money on the implementation. Which of the following would be the best solution for the Chief Executive Officer to use?",
        "options": [
            "Obfuscation",
            "Hashing",
            "Encryption",
            "Digital signature"
        ],
        "answer": "Encryption"
    },
    {
        "question": "A company hires a third party to perform a security assessment of its systems. The third party first learns about the network infrastructure and checks public sources for vulnerability information. Which of the following assessment techniques is the third party performing?",
        "options": [
            "A red-team exercise",
            "Passive footprinting",
            "A design review",
            "Internal penetration testing"
        ],
        "answer": "Passive footprinting"
    },
    {
        "question": "Which of the following assessment types would be the best for an auditor to perform when identifying how well the risk management process has been applied?",
        "options": [
            "Quantitative",
            "Qualitative",
            "Key risk indicators",
            "Key performance indicators"
        ],
        "answer": "Qualitative"
    },
    {
        "question": "A company recently implemented a DLP solution to prevent the exfiltration of sensitive data. Which of the following incidents would be addressed by the DLP solution? (Choose two.)",
        "options": [
            "An employee remotely accessing the corporate ERP system",
            "An unauthorized user accessing confidential data in a public cloud",
            "A user transferring files to a USB device",
            "A user copying files from one server to another",
            "An unapproved email being sent with sensitive information"
        ],
        "answer": [
            "A user transferring files to a USB device",
            "An unapproved email being sent with sensitive information"
        ]
    },
    {
        "question": "A server was compromised recently, and the company determined that the attacker gained access using an on-path attack. Which of the following components must be examined in the investigation? (Choose two.)",
        "options": [
            "Switches",
            "Cable locks",
            "Patch panels",
            "Honeypots",
            "DNS logs",
            "Certificate chain"
        ],
        "answer": [
            "DNS logs",
            "Certificate chain"
        ]
    },
    {
        "question": "A company has implemented a solution for managing its user's workstations. This solution helps protect company data by monitoring and enforcing a set of security policies. Which of the following solutions did the company most likely implement?",
        "options": [
            "Mobile device management",
            "Identity provider",
            "Remote attestation",
            "Endpoint detection and response"
        ],
        "answer": "Mobile device management"
    },
    {
        "question": "Which of the following vulnerability types is most likely to cause an application to crash or execute terminal commands?",
        "options": [
            "Buffer overflow",
            "Resource exhaustion",
            "Privilege escalation",
            "Unsecure root accounts"
        ],
        "answer": "Buffer overflow"
    },
    {
        "question": "A company is considering using a cloud security solution to protect the integrity of the data that is processed and stored in the cloud. The security solution must be able to provide information about unauthorized attempts to access the data. Which of the following cloud security solutions would best meet the company's requirements?",
        "options": [
            "EPP",
            "FWaaS",
            "SWG",
            "CASB"
        ],
        "answer": "CASB"
    },
    {
        "question": "A security administrator implements access control to limit database administrators' access to specific IP addresses. Which of the following control types is the administrator implementing?",
        "options": [
            "Detective",
            "Administrative",
            "Corrective",
            "Preventive"
        ],
        "answer": "Preventive"
    },
    {
        "question": "An organization wants to ensure sensitive data stored on a mobile device remains secure even if the device is lost or stolen. Which of the following would best meet this requirement?",
        "options": [
            "FDE",
            "MFA",
            "MDM",
            "TPM"
        ],
        "answer": "FDE"
    },
    {
        "question": "Which of the following provides a framework for effective incident management to minimize the impact of a security incident?",
        "options": [
            "Risk assessment",
            "Penetration testing",
            "Incident response plan",
            "Security control"
        ],
        "answer": "Incident response plan"
    },
    {
        "question": "A company is deploying a wireless network to its new office building. The security administrator has implemented WPA3 for secure communications and would like to implement a solution to allow only authorized devices to connect to the wireless network. Which of the following would best meet this requirement?",
        "options": [
            "NAC",
            "DNSSEC",
            "LDAP",
            "PKI"
        ],
        "answer": "NAC"
    },
    {
        "question": "A network administrator must improve the overall security posture of the internal environment. Which of the following would best protect the network against internal attacks?",
        "options": [
            "Network segmentation",
            "Network address translation",
            "Server hardening",
            "Secure shell"
        ],
        "answer": "Network segmentation"
    },
    {
        "question": "Which of the following is the best reason for an organization to monitor the network?",
        "options": [
            "To detect insider threats",
            "To enforce security policies",
            "To detect rogue devices",
            "To ensure availability"
        ],
        "answer": "To ensure availability"
    },
    {
        "question": "A security administrator is configuring a VPN concentrator for a new remote site. The security policy requires that the VPN traffic between the two sites be encrypted. Which of the following should the security administrator implement?",
        "options": [
            "IPSec",
            "RDP",
            "SSH",
            "TLS"
        ],
        "answer": "IPSec"
    },
    {
        "question": "A company wants to create a secure tunnel between two of its locations to transfer sensitive data. Which of the following would best meet this requirement?",
        "options": [
            "DNSSEC",
            "TLS",
            "IPSec",
            "S/MIME"
        ],
        "answer": "IPSec"
    },
    {
        "question": "An organization recently discovered unauthorized devices on the network. The security administrator needs to implement a solution to prevent unauthorized devices from connecting to the network in the future. Which of the following would be the best solution to implement?",
        "options": [
            "NAC",
            "WPA2",
            "MDM",
            "VPN"
        ],
        "answer": "NAC"
    },
    {
        "question": "A security administrator is implementing an encryption solution for the company's email server. The solution must ensure that the email messages are encrypted during transmission. Which of the following would best meet this requirement?",
        "options": [
            "SSL",
            "TLS",
            "IPSec",
            "SSH"
        ],
        "answer": "TLS"
    },
    {
        "question": "An organization recently conducted a business impact analysis and identified that a particular server is critical to the company's operations. Which of the following should the organization implement to ensure the server is always available?",
        "options": [
            "Redundancy",
            "DLP",
            "VPN",
            "SIEM"
        ],
        "answer": "Redundancy"
    },
    {
        "question": "A security administrator is implementing a solution to ensure that users can securely access company resources from remote locations. Which of the following would best meet this requirement?",
        "options": [
            "VPN",
            "IPS",
            "SIEM",
            "DLP"
        ],
        "answer": "VPN"
    },
    {
        "question": "A company wants to ensure that only authorized devices can connect to its wireless network. Which of the following would best meet this requirement?",
        "options": [
            "WPA2",
            "NAC",
            "VPN",
            "MDM"
        ],
        "answer": "NAC"
    },
    {
        "question": "A security administrator is implementing a solution to prevent unauthorized access to the company's network. Which of the following would best meet this requirement?",
        "options": [
            "NAC",
            "WPA2",
            "VPN",
            "MDM"
        ],
        "answer": "NAC"
    },
    {
        "question": "An organization wants to ensure that only authorized devices can access its network. Which of the following would best meet this requirement?",
        "options": [
            "NAC",
            "WPA2",
            "VPN",
            "MDM"
        ],
        "answer": "NAC"
    }
]

class SquizeeApp:
    def __init__(self, root, questions):
        self.root = root
        self.original_questions = questions
        self.questions = questions[:]
        self.answered_questions = []
        self.missed_questions = []
        self.current_question = None
        self.score = 0

        self.root.title("Squizee Quiz by BEVAN")

        self.description_label = tk.Label(root, text="Welcome to Squizee Quiz! Answer the questions and test your knowledge.", wraplength=400, justify="left")
        self.description_label.pack(pady=10)

        self.question_label = tk.Label(root, text="", wraplength=400, justify="left")
        self.question_label.pack(pady=20)
        self.question_label.pack_forget()  # Hide initially

        self.options_vars = []
        self.option_checkboxes = []

        self.next_button = tk.Button(root, text="Next", command=self.next_question)
        self.next_button.pack(pady=20)
        self.next_button.pack_forget()  # Hide initially

        self.start_button = tk.Button(root, text="Start Quiz", command=self.start_quiz)
        self.start_button.pack(pady=10)

        self.result_label = tk.Label(root, text="", wraplength=400, justify="left")
        self.result_label.pack(pady=20)

    def start_quiz(self):
        self.questions = self.original_questions[:]
        self.answered_questions = []
        self.missed_questions = []
        self.current_question = None
        self.score = 0
        self.result_label.config(text="")
        self.next_button.config(state=tk.NORMAL)
        self.next_button.pack(pady=20)  # Show the next button
        self.start_button.pack_forget()  # Hide the start button
        self.question_label.pack(pady=20)  # Show the question label
        self.ask_num_questions()

    def ask_num_questions(self):
        num_questions = simpledialog.askinteger("Number of Questions", "How many questions would you like in the quiz? (Max 100):", minvalue=1, maxvalue=100)
        if num_questions:
            self.num_questions = min(num_questions, len(self.questions))
            self.available_questions = random.sample(self.questions, self.num_questions)
            self.next_question()

    def next_question(self):
        if self.current_question:
            selected_options = [i for i, var in enumerate(self.options_vars) if var.get() == 1]
            if not selected_options:
                messagebox.showwarning("Warning", "Please select at least one option.")
                return
            correct_answers = self.current_question['answer'] if isinstance(self.current_question['answer'], list) else [self.current_question['answer']]
            user_answers = [self.current_question['options'][i] for i in selected_options]
            if all(ans in correct_answers for ans in user_answers) and len(user_answers) == len(correct_answers):
                self.score += 1
                self.result_label.config(text="Correct!")
            else:
                self.missed_questions.append(self.current_question)
                self.result_label.config(text=f"Wrong! The correct answer is: {', '.join(correct_answers)}")

        if not self.available_questions:
            self.end_quiz()
            return

        self.current_question = self.available_questions.pop()
        self.display_question(self.current_question)

    def display_question(self, question):
        self.question_label.config(text=question['question'])
        for chk in self.option_checkboxes:
            chk.pack_forget()
        self.options_vars = []
        self.option_checkboxes = []
        for i, option in enumerate(question['options']):
            var = tk.IntVar()
            chk = tk.Checkbutton(self.root, text=option, variable=var, anchor="w", justify="left")
            chk.pack(fill="x", padx=20, pady=5)
            self.options_vars.append(var)
            self.option_checkboxes.append(chk)

    def end_quiz(self):
        self.result_label.config(text=f"Your final score is {self.score} out of {self.num_questions}")
        self.next_button.config(state=tk.DISABLED)

        choice = simpledialog.askinteger("Quiz Complete", "Select an option:\n1. Answer more questions.\n2. Retry the questions you missed.\n3. Exit.", minvalue=1, maxvalue=3)
        if choice == 1:
            self.start_quiz()
        elif choice == 2:
            if self.missed_questions:
                self.retry_missed_questions()
            else:
                messagebox.showinfo("No Missed Questions", "No missed questions to retry.")
                self.reset_quiz()
        elif choice == 3:
            self.root.destroy()  # Close the Tkinter window

    def retry_missed_questions(self):
        self.questions = self.missed_questions[:]
        self.num_questions = len(self.questions)  # Update the number of questions to the number of missed questions
        self.answered_questions = []
        self.missed_questions = []
        self.current_question = None
        self.score = 0
        self.result_label.config(text="")
        self.next_button.config(state=tk.NORMAL)
        self.next_button.pack(pady=20)  # Show the next button
        self.start_button.pack_forget()  # Hide the start button
        self.question_label.pack(pady=20)  # Show the question label
        self.available_questions = random.sample(self.questions, len(self.questions))
        self.next_question()

    def reset_quiz(self):
        self.next_button.pack_forget()  # Hide the next button
        self.question_label.pack_forget()  # Hide the question label
        for chk in self.option_checkboxes:
            chk.pack_forget()  # Hide the option checkboxes
        self.start_button.pack(pady=10)  # Show the start button

# Main function
def main():
    # Create the main application window
    root = tk.Tk()
    app = SquizeeApp(root, questions)
    root.mainloop()

# Entry point of the script
if __name__ == "__main__":
    try:
        import tkinter
    except ImportError:
        print("tkinter is not installed. Please install tkinter to run this application.")
        print("Use the command: pip install tk")
    else:
        main()
