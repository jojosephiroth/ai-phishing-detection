"""  
AI-Assisted Phishing Detection Workflow  
  
Defensive use case:  
- Analyze suspicious emails  
- Extract indicators  
- Classify phishing risk  
- Generate analyst-friendly JSON and Markdown reports  
  
Install:  
    pip install openai beautifulsoup4 tldextract python-dotenv  
  
Environment:  
    export OPENAI_API_KEY="your_api_key_here"  
  
Usage:  
    python phishing_ai_triage.py suspicious_email.eml  
"""  
  
import os  
import re  
import json  
import sys  
import hashlib  
import email  
import tldextract  
from email import policy  
from email.parser import BytesParser  
from bs4 import BeautifulSoup  
from openai import OpenAI  
  
  
MODEL = "gpt-4.1-mini"  
  
  
SUSPICIOUS_KEYWORDS = [  
    "urgent",  
    "verify",  
    "password",  
    "invoice",  
    "payment",  
    "wire transfer",  
    "gift card",  
    "account suspended",  
    "login",  
    "reset",  
    "security alert",  
    "confirm your identity",  
]  
  
  
URL_REGEX = re.compile(r"https?://[^\s>'\")]+", re.IGNORECASE)  
  
  
def sha256_text(value: str) -> str:  
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()  
  
  
def parse_email(file_path: str) -> dict:  
    """Parse .eml file and extract headers, body, links, and attachments."""  
    with open(file_path, "rb") as f:  
        msg = BytesParser(policy=policy.default).parse(f)  
  
    headers = {  
        "from": msg.get("From", ""),  
        "to": msg.get("To", ""),  
        "reply_to": msg.get("Reply-To", ""),  
        "return_path": msg.get("Return-Path", ""),  
        "subject": msg.get("Subject", ""),  
        "date": msg.get("Date", ""),  
        "message_id": msg.get("Message-ID", ""),  
        "authentication_results": msg.get("Authentication-Results", ""),  
        "received_spf": msg.get("Received-SPF", ""),  
    }  
  
    plain_text_parts = []  
    html_parts = []  
    attachments = []  
  
    for part in msg.walk():  
        content_disposition = part.get_content_disposition()  
        content_type = part.get_content_type()  
  
        if content_disposition == "attachment":  
            filename = part.get_filename() or "unknown_attachment"  
            payload = part.get_payload(decode=True) or b""  
            attachments.append({  
                "filename": filename,  
                "content_type": content_type,  
                "size_bytes": len(payload),  
                "sha256": hashlib.sha256(payload).hexdigest(),  
            })  
  
        elif content_type == "text/plain":  
            try:  
                plain_text_parts.append(part.get_content())  
            except Exception:  
                pass  
  
        elif content_type == "text/html":  
            try:  
                html_parts.append(part.get_content())  
            except Exception:  
                pass  
  
    html_text = "\n".join(html_parts)  
    soup = BeautifulSoup(html_text, "html.parser") if html_text else None  
  
    visible_html_text = soup.get_text(" ", strip=True) if soup else ""  
    full_body = "\n".join(plain_text_parts) or visible_html_text  
  
    links = extract_links(full_body, html_text)  
  
    return {  
        "headers": headers,  
        "body": full_body[:8000],  
        "body_sha256": sha256_text(full_body),  
        "links": links,  
        "attachments": attachments,  
    }  
  
  
def extract_links(text_body: str, html_body: str) -> list:  
    """Extract URLs from plain text and HTML href attributes."""  
    urls = set(URL_REGEX.findall(text_body or ""))  
  
    if html_body:  
        soup = BeautifulSoup(html_body, "html.parser")  
        for tag in soup.find_all("a", href=True):  
            urls.add(tag["href"])  
  
    parsed = []  
    for url in sorted(urls):  
        ext = tldextract.extract(url)  
        registered_domain = ".".join(part for part in [ext.domain, ext.suffix] if part)  
        parsed.append({  
            "url": url,  
            "registered_domain": registered_domain,  
            "subdomain": ext.subdomain,  
        })  
  
    return parsed  
  
  
def rule_based_checks(email_data: dict) -> dict:  
    """Run simple deterministic phishing checks before AI analysis."""  
    headers = email_data["headers"]  
    body = email_data["body"].lower()  
    subject = headers.get("subject", "").lower()  
  
    from_address = headers.get("from", "")  
    reply_to = headers.get("reply_to", "")  
    return_path = headers.get("return_path", "")  
  
    keyword_hits = [  
        word for word in SUSPICIOUS_KEYWORDS  
        if word in body or word in subject  
    ]  
  
    link_domains = {link["registered_domain"] for link in email_data["links"]}  
    has_attachments = len(email_data["attachments"]) > 0  
  
    sender_mismatch = False  
    if reply_to and from_address:  
        sender_mismatch = normalize_domain(reply_to) != normalize_domain(from_address)  
  
    return_path_mismatch = False  
    if return_path and from_address:  
        return_path_mismatch = normalize_domain(return_path) != normalize_domain(from_address)  
  
    auth_text = (  
        headers.get("authentication_results", "") + " " +  
        headers.get("received_spf", "")  
    ).lower()  
  
    auth_failures = {  
        "spf_fail": "spf=fail" in auth_text or "fail" in headers.get("received_spf", "").lower(),  
        "dkim_fail": "dkim=fail" in auth_text,  
        "dmarc_fail": "dmarc=fail" in auth_text,  
    }  
  
    score = 0  
    score += 15 if keyword_hits else 0  
    score += 20 if sender_mismatch else 0  
    score += 15 if return_path_mismatch else 0  
    score += 15 if has_attachments else 0  
    score += 10 if len(link_domains) >= 2 else 0  
    score += 20 if any(auth_failures.values()) else 0  
  
    return {  
        "rule_score": min(score, 100),  
        "keyword_hits": keyword_hits,  
        "sender_mismatch": sender_mismatch,  
        "return_path_mismatch": return_path_mismatch,  
        "auth_failures": auth_failures,  
        "unique_link_domains": sorted(link_domains),  
        "attachment_count": len(email_data["attachments"]),  
    }  
  
  
def normalize_domain(value: str) -> str:  
    """Extract registered domain from an email-ish string."""  
    match = re.search(r"@([A-Za-z0-9.-]+)", value)  
    domain = match.group(1) if match else value  
    ext = tldextract.extract(domain)  
    return ".".join(part for part in [ext.domain, ext.suffix] if part)  
  
  
def ai_phishing_analysis(email_data: dict, rule_results: dict) -> dict:  
    """Send sanitized email data to OpenAI for structured phishing triage."""  
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))  
  
    prompt_payload = {  
        "headers": email_data["headers"],  
        "body_excerpt": email_data["body"][:4000],  
        "links": email_data["links"],  
        "attachments": email_data["attachments"],  
        "rule_based_results": rule_results,  
    }  
  
    system_prompt = """  
You are a defensive security analyst performing phishing triage.  
Analyze only the provided email evidence.  
Do not invent facts.  
Return a JSON object matching the requested schema.  
Focus on user safety, detection reasoning, and recommended defensive action.  
"""  
  
    schema = {  
        "name": "phishing_triage_result",  
        "schema": {  
            "type": "object",  
            "properties": {  
                "risk_level": {  
                    "type": "string",  
                    "enum": ["low", "medium", "high", "critical"]  
                },  
                "confidence": {  
                    "type": "integer",  
                    "minimum": 0,  
                    "maximum": 100  
                },  
                "classification": {  
                    "type": "string",  
                    "enum": [  
                        "benign",  
                        "spam",  
                        "credential_phishing",  
                        "business_email_compromise",  
                        "malware_delivery",  
                        "financial_fraud",  
                        "suspicious_needs_review"  
                    ]  
                },  
                "summary": {"type": "string"},  
                "evidence": {  
                    "type": "array",  
                    "items": {"type": "string"}  
                },  
                "recommended_actions": {  
                    "type": "array",  
                    "items": {"type": "string"}  
                },  
                "indicators": {  
                    "type": "object",  
                    "properties": {  
                        "suspicious_domains": {  
                            "type": "array",  
                            "items": {"type": "string"}  
                        },  
                        "suspicious_sender_features": {  
                            "type": "array",  
                            "items": {"type": "string"}  
                        },  
                        "suspicious_attachment_names": {  
                            "type": "array",  
                            "items": {"type": "string"}  
                        }  
                    },  
                    "required": [  
                        "suspicious_domains",  
                        "suspicious_sender_features",  
                        "suspicious_attachment_names"  
                    ],  
                    "additionalProperties": False  
                }  
            },  
            "required": [  
                "risk_level",  
                "confidence",  
                "classification",  
                "summary",  
                "evidence",  
                "recommended_actions",  
                "indicators"  
            ],  
            "additionalProperties": False  
        }  
    }  
  
    response = client.responses.create(  
        model=MODEL,  
        input=[  
            {"role": "system", "content": system_prompt},  
            {  
                "role": "user",  
                "content": (  
                    "Analyze this suspicious email for phishing risk. "  
                    "Return only structured JSON.\n\n"  
                    + json.dumps(prompt_payload, indent=2)  
                )  
            }  
        ],  
        response_format={  
            "type": "json_schema",  
            "json_schema": schema  
        }  
    )  
  
    return json.loads(response.output_text)  
  
  
def write_markdown_report(email_data: dict, rule_results: dict, ai_results: dict, output_path: str):  
    """Write analyst-friendly Markdown report."""  
    headers = email_data["headers"]  
  
    lines = [  
        "# AI-Assisted Phishing Triage Report",  
        "",  
        "## Email Metadata",  
        f"- **From:** {headers.get('from', '')}",  
        f"- **To:** {headers.get('to', '')}",  
        f"- **Reply-To:** {headers.get('reply_to', '')}",  
        f"- **Subject:** {headers.get('subject', '')}",  
        f"- **Date:** {headers.get('date', '')}",  
        f"- **Body SHA256:** `{email_data.get('body_sha256')}`",  
        "",  
        "## AI Risk Assessment",  
        f"- **Risk Level:** {ai_results['risk_level']}",  
        f"- **Confidence:** {ai_results['confidence']}%",  
        f"- **Classification:** {ai_results['classification']}",  
        "",  
        "## Summary",  
        ai_results["summary"],  
        "",  
        "## Evidence",  
    ]  
  
    for item in ai_results["evidence"]:  
        lines.append(f"- {item}")  
  
    lines.extend([  
        "",  
        "## Rule-Based Findings",  
        f"- **Rule Score:** {rule_results['rule_score']}/100",  
        f"- **Keyword Hits:** {', '.join(rule_results['keyword_hits']) or 'None'}",  
        f"- **Sender Mismatch:** {rule_results['sender_mismatch']}",  
        f"- **Return-Path Mismatch:** {rule_results['return_path_mismatch']}",  
        f"- **Auth Failures:** {rule_results['auth_failures']}",  
        f"- **Unique Link Domains:** {', '.join(rule_results['unique_link_domains']) or 'None'}",  
        f"- **Attachment Count:** {rule_results['attachment_count']}",  
        "",  
        "## Recommended Actions",  
    ])  
  
    for action in ai_results["recommended_actions"]:  
        lines.append(f"- {action}")  
  
    lines.extend([  
        "",  
        "## Extracted Links",  
    ])  
  
    for link in email_data["links"]:  
        lines.append(f"- `{link['url']}`")  
  
    lines.extend([  
        "",  
        "## Attachments",  
    ])  
  
    for attachment in email_data["attachments"]:  
        lines.append(  
            f"- `{attachment['filename']}` "  
            f"({attachment['content_type']}, {attachment['size_bytes']} bytes, "  
            f"sha256: `{attachment['sha256']}`)"  
        )  
  
    with open(output_path, "w", encoding="utf-8") as f:  
        f.write("\n".join(lines))  
  
  
def main():  
    if len(sys.argv) != 2:  
        print("Usage: python phishing_ai_triage.py suspicious_email.eml")  
        sys.exit(1)  
  
    eml_path = sys.argv[1]  
  
    print("[*] Parsing email...")  
    email_data = parse_email(eml_path)  
  
    print("[*] Running rule-based checks...")  
    rule_results = rule_based_checks(email_data)  
  
    print("[*] Running AI phishing triage...")  
    ai_results = ai_phishing_analysis(email_data, rule_results)  
  
    base_name = os.path.splitext(os.path.basename(eml_path))[0]  
    json_output = f"{base_name}_phishing_triage.json"  
    md_output = f"{base_name}_phishing_report.md"  
  
    with open(json_output, "w", encoding="utf-8") as f:  
        json.dump({  
            "email": email_data,  
            "rule_based_results": rule_results,  
            "ai_results": ai_results  
        }, f, indent=2)  
  
    write_markdown_report(email_data, rule_results, ai_results, md_output)  
  
    print("[+] Done.")  
    print(f"[+] JSON output: {json_output}")  
    print(f"[+] Markdown report: {md_output}")  
    print(f"[+] Risk: {ai_results['risk_level']} / {ai_results['classification']}")  
  
  
if __name__ == "__main__":  
    main()
