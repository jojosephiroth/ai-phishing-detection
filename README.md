# AI-Assisted Phishing Detection Workflow  
  
This project is a defensive security automation tool that analyzes suspicious `.eml`  
files using a hybrid workflow:  
  
1. Email parsing  
2. Header and link extraction  
3. Rule-based phishing checks  
4. AI-assisted classification  
5. Structured JSON output  
6. Markdown analyst report generation  
  
## Why This Project Exists  
  
Security teams often receive suspicious emails that require quick triage.  
This workflow shows how AI can assist analysts by summarizing evidence,  
classifying risk, and recommending next steps while preserving human review.  
  
## Detection Categories  
  
- benign  
- spam  
- credential phishing  
- business email compromise  
- malware delivery  
- financial fraud  
- suspicious_needs_review  
  
## Example Defensive Actions  
  
- Quarantine message  
- Block sender/domain  
- Reset credentials if clicked  
- Review sign-in logs  
- Submit URLs/attachments to sandbox  
- Notify affected users
