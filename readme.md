1. Prerequisites & Environment Setup

    Disable Windows Execution Aliases: Ensure Windows isn't redirecting Python commands to Microsoft Store stubs by going to Settings > Apps > Advanced app settings > App execution aliases (or running ms-settings:apps-executionaliases in PowerShell) and toggling off all Python / App Installer switches.

    Install Python & Dependencies: Ensure Python is installed (with python.exe added to PATH) and install the required Akamai authentication library:
    PowerShell

    pip install akamai-edgegrid requests

    Configure Credentials (.edgerc): Ensure an .edgerc file exists in the user home directory (~/.edgerc) containing the API client credentials. For Akamai users the target Akamai account section (e.g., [akamaio], [akamaib]).

2. Running the Script

Delete Existing State Files:

Remove-Item .\tracked_enrollments.json, .\ignored_enrollments.json -ErrorAction SilentlyContinue

Execute the script from a PowerShell terminal, passing the credential section, account switch key (for Akamai users), and debugging flag:
PowerShell

.\track_ov_ev_auto.ps1 -ConfigSection "akamaio" -AccountSwitchKey "XXXX" -ContractId "ctr_XXXX" -DebugLog

    -ConfigSection: Specifies which section in ~/.edgerc to use for authentication.

    -AccountSwitchKey: Required for multi-account management to scope queries to the target account.(Akamai user only)

    -ContractId: Enrollment queries to a specific contract.

3. How the Script Operates (Automated Workflow)

    Auto-Discovery: On the initial run, the script scans Akamai CPS, automatically identifies all OV/EV certificate enrollments (filtering out Let's Encrypt / DV certificates), and saves them locally to tracked_enrollments.json.

    Automated Batch Monitoring: In an infinite loop, it iterates through all discovered certificates every 60 seconds to pull real-time State, Status, CA Order Information, and Network Deployment states (Staging vs. Production).

    Built-in Self-Healing: Includes built-in API throttling delays (1.5s per enrollment) and 429 backoff handlers to prevent rate limiting and ensure stable execution without manual file cleanup.