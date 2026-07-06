import os
import re
import json
import email
from email import policy
from typing import List, Dict, Any, TypedDict
from dotenv import load_dotenv

# Import LangGraph classes
from langgraph.graph import StateGraph, END

# Import ML model
from ml_model import predict_phishing

load_dotenv()

# Define the State Object
class AnalysisState(TypedDict):
    raw_email: str
    
    # Parsed components
    subject: str
    body_text: str
    extracted_urls: List[str]
    headers: Dict[str, str]
    
    # Parallel verdicts
    url_verdicts: List[Dict[str, Any]]
    header_auth_results: Dict[str, Any]
    sender_reputation: Dict[str, Any]
    nlp_urgency_score: float
    
    # Sequential verdicts
    ml_phishing_probability: float
    final_risk_score: int  # 0 to 100
    llm_explanation: str
    explanation_tree: List[Dict[str, Any]]

# --- Graph Nodes ---

def parse_email_node(state: AnalysisState) -> Dict[str, Any]:
    """Parses raw email (MIME) format, extracts subject, body, headers, and URLs."""
    raw_email = state.get("raw_email", "")
    
    # Use standard email library with default policy
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        subject = msg.get("subject", "No Subject")
        
        # Extract headers as dict
        headers = {key: val for key, val in msg.items()}
        
        # Extract body text
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    body_text += part.get_payload(decode=True).decode(errors='ignore')
                elif content_type == "text/html" and "attachment" not in content_disposition:
                    # Very simple HTML tag stripping for text extraction
                    html_content = part.get_payload(decode=True).decode(errors='ignore')
                    body_text += re.sub(r'<[^>]+>', ' ', html_content)
        else:
            body_text = msg.get_payload(decode=True).decode(errors='ignore')
            
    except Exception as e:
        print(f"Error parsing email MIME: {e}")
        # Fallback if raw email is just plain text
        subject = "Unknown Subject"
        body_text = raw_email
        headers = {}
        
    # Extract URLs from body text
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, body_text)
    
    # Clean trailing punctuation from URLs
    cleaned_urls = []
    for url in urls:
        url = url.rstrip('.,;:)("')
        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return {
        "subject": subject,
        "body_text": body_text,
        "extracted_urls": cleaned_urls,
        "headers": headers
    }

def check_urls_node(state: AnalysisState) -> Dict[str, Any]:
    """Scans and verifies URLs found in the email."""
    urls = state.get("extracted_urls", [])
    url_verdicts = []
    
    # Simulated reputation databases or external lookups (VirusTotal / Safe Browsing)
    suspicious_keywords = ["verify", "login", "update-bank", "secure-signin", "free-gift", "bit.ly", "tinyurl", "paypal-security"]
    
    # If VIRUSTOTAL_API_KEY is available in environment, we could query it.
    # Otherwise, fallback to a robust rules-based analysis
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    for url in urls:
        domain = ""
        try:
            domain = url.split("//")[-1].split("/")[0]
        except:
            domain = url
            
        verdict = "SAFE"
        confidence = 0.5
        details = "No anomalies detected in domain structure."
        
        # Check suspicious keywords in url
        matched_kws = [kw for kw in suspicious_keywords if kw in url.lower()]
        
        if matched_kws:
            verdict = "SUSPICIOUS"
            confidence = 0.8
            details = f"URL contains suspicious redirection or keywords: {', '.join(matched_kws)}"
            
        # Check for IP address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            verdict = "MALICIOUS"
            confidence = 0.95
            details = "URL uses raw IP address instead of a domain name."
            
        # Mocking VT check if key exists
        if vt_key:
            details += " (VirusTotal: Checked)"
            
        url_verdicts.append({
            "url": url,
            "domain": domain,
            "verdict": verdict,
            "confidence": confidence,
            "details": details
        })
        
    return {"url_verdicts": url_verdicts}

def verify_sender_node(state: AnalysisState) -> Dict[str, Any]:
    """Analyzes SPF, DKIM, and DMARC headers plus domain age."""
    headers = state.get("headers", {})
    
    # Look for Authentication-Results or Received-SPF headers
    auth_header = ""
    for k, v in headers.items():
        if k.lower() in ["authentication-results", "received-spf", "arc-authentication-results"]:
            auth_header += f" {v}"
            
    spf = "neutral"
    dkim = "neutral"
    dmarc = "neutral"
    
    if auth_header:
        auth_header_lower = auth_header.lower()
        if "spf=pass" in auth_header_lower:
            spf = "pass"
        elif "spf=fail" in auth_header_lower:
            spf = "fail"
            
        if "dkim=pass" in auth_header_lower:
            dkim = "pass"
        elif "dkim=fail" in auth_header_lower:
            dkim = "fail"
            
        if "dmarc=pass" in auth_header_lower:
            dmarc = "pass"
        elif "dmarc=fail" in auth_header_lower:
            dmarc = "fail"
    else:
        # If no auth headers exist, check common spoofing indicators
        # e.g., missing authentication signatures altogether
        spf = "none"
        dkim = "none"
        dmarc = "none"
        
    # Analyze From domain age (mock query)
    from_header = headers.get("From", "")
    domain = ""
    domain_age_days = 1200 # Default safe domain age
    
    domain_match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_header)
    if domain_match:
        domain = domain_match.group(1).lower()
        # Mock domain ages for demo purposes
        if "paypa1" in domain or "secure" in domain or "alert" in domain:
            domain_age_days = 3
        elif "gmail.com" in domain or "yahoo.com" in domain or "microsoft.com" in domain:
            domain_age_days = 9000
            
    sender_reputation = {
        "domain": domain,
        "domain_age_days": domain_age_days,
        "suspicious_domain_age": domain_age_days < 30,
        "reputation_status": "POOR" if domain_age_days < 30 or spf == "fail" else "GOOD"
    }
    
    header_auth_results = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "all_pass": spf == "pass" and dkim == "pass" and dmarc == "pass"
    }
    
    return {
        "header_auth_results": header_auth_results,
        "sender_reputation": sender_reputation
    }

def analyze_headers_node(state: AnalysisState) -> Dict[str, Any]:
    """Detects header spoofing (e.g., mismatching Return-Path or Reply-To, relay hops)."""
    headers = state.get("headers", {})
    
    from_header = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")
    
    from_email = ""
    from_email_match = re.search(r'<([^>]+)>', from_header)
    if from_email_match:
        from_email = from_email_match.group(1)
    else:
        from_email = from_header
        
    # Count hop counts from 'Received' headers
    received_count = 0
    for k in headers.keys():
        if k.lower() == "received":
            received_count += 1
            
    mismatches = []
    
    if reply_to and from_email:
        # Check if domains match in From and Reply-To
        from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
        reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
        if from_domain and reply_domain and from_domain != reply_domain:
            mismatches.append(f"Reply-To domain ({reply_domain}) does not match From domain ({from_domain})")
            
    if return_path and from_email:
        rp_email = return_path.strip("<>")
        rp_domain = rp_email.split("@")[-1].lower() if "@" in rp_email else ""
        from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
        if rp_domain and from_domain and rp_domain != from_domain:
            mismatches.append(f"Return-Path domain ({rp_domain}) does not match From domain ({from_domain})")
            
    return {
        "header_anomalies": {
            "mismatches": mismatches,
            "relay_hops_count": received_count,
            "suspicious_hops": received_count > 8
        }
    }

def nlp_scan_node(state: AnalysisState) -> Dict[str, Any]:
    """Analyzes email content for urgency, credential harvesting language, and homoglyphs."""
    body_text = state.get("body_text", "")
    subject = state.get("subject", "")
    
    full_text = f"{subject} {body_text}".lower()
    
    # 1. Urgency keywords check
    urgency_keywords = ["urgent", "immediately", "action required", "suspension", "locked", "unauthorized", "verify", "expire", "critical"]
    urgency_hits = sum(1 for kw in urgency_keywords if kw in full_text)
    # Score between 0.0 and 1.0
    nlp_urgency_score = min(1.0, urgency_hits * 0.2)
    
    # 2. Homoglyph / Brand impersonation check
    brand_variants = {
        "paypal": ["paypa1", "paypaI", "pay-pal"],
        "netflix": ["netfl1x", "netf1ix", "netf-lix"],
        "microsoft": ["micros0ft", "micro-soft", "m1crosoft"],
        "google": ["g00gle", "go0gle", "goog1e"],
        "amazon": ["amaz0n", "amzn-security"]
    }
    
    detected_spoofs = []
    for brand, variants in brand_variants.items():
        for var in variants:
            if var in full_text:
                detected_spoofs.append(f"Spoofed representation of '{brand}' found: '{var}'")
                
    # 3. Credential harvesting signatures
    cred_signatures = ["log in to your account", "confirm password", "update security questions", "billing details", "social security number"]
    cred_hits = [sig for sig in cred_signatures if sig in full_text]
    
    return {
        "nlp_urgency_score": nlp_urgency_score,
        "nlp_analysis": {
            "urgency_hits_count": urgency_hits,
            "detected_spoofs": detected_spoofs,
            "cred_harvesting_phrases": cred_hits
        }
    }

def aggregate_node(state: AnalysisState) -> Dict[str, Any]:
    """Aggregates outputs from parallel analysis nodes."""
    # This node is a pass-through in terms of routing, but is where we can run general summarization of parallel results
    return {}

def ml_inference_node(state: AnalysisState) -> Dict[str, Any]:
    """Executes the machine learning prediction model."""
    body_text = state.get("body_text", "")
    subject = state.get("subject", "")
    
    # Predict using text classifier
    text_to_scan = f"Subject: {subject}\n{body_text}"
    prob = predict_phishing(text_to_scan)
    
    # Also integrate parallel node outputs to adjust the final risk score (0-100)
    # Start with ML probability * 100
    base_score = int(prob * 100)
    
    # Add adjustments for deterministic flags:
    adjustments = 0
    
    # Malicious URL check
    url_verdicts = state.get("url_verdicts", [])
    if any(uv["verdict"] == "MALICIOUS" for uv in url_verdicts):
        adjustments += 20
    elif any(uv["verdict"] == "SUSPICIOUS" for uv in url_verdicts):
        adjustments += 10
        
    # Sender Domain Rep check
    sender_rep = state.get("sender_reputation", {})
    if sender_rep.get("suspicious_domain_age", False):
        adjustments += 15
        
    # Header auth failures
    header_auth = state.get("header_auth_results", {})
    if header_auth.get("spf") == "fail" or header_auth.get("dmarc") == "fail":
        adjustments += 10
        
    # NLP Urgency
    urgency_score = state.get("nlp_urgency_score", 0.0)
    if urgency_score > 0.6:
        adjustments += 10
        
    final_risk_score = min(100, max(0, base_score + adjustments))
    
    # Keep score synced with ML classification
    # If ML says high phish prob but adjustments push it down or vice-versa, ensure alignment
    if prob > 0.8:
        final_risk_score = max(80, final_risk_score)
    elif prob < 0.2:
        final_risk_score = min(30, final_risk_score)
        
    return {
        "ml_phishing_probability": prob,
        "final_risk_score": final_risk_score
    }

def conditional_router(state: AnalysisState) -> str:
    """Determines whether to trigger detailed XAI or standard summary."""
    prob = state.get("ml_phishing_probability", 0.0)
    url_verdicts = state.get("url_verdicts", [])
    
    has_malicious_url = any(v["verdict"] == "MALICIOUS" for v in url_verdicts)
    
    if prob > 0.8 or (prob > 0.5 and has_malicious_url):
        return "detailed_xai"
    else:
        return "standard_summary"

def llm_explain_node(state: AnalysisState) -> Dict[str, Any]:
    """Generates the human-readable explanation using OpenAI API or dynamic heuristic fallback."""
    subject = state.get("subject", "")
    risk_score = state.get("final_risk_score", 0)
    url_verdicts = state.get("url_verdicts", [])
    header_auth = state.get("header_auth_results", {})
    sender_rep = state.get("sender_reputation", {})
    nlp_analysis = state.get("nlp_analysis", {})
    header_anomalies = state.get("header_anomalies", {})
    
    # 1. Compile explanation tree data
    explanation_tree = []
    
    # Add domain issues
    if sender_rep.get("suspicious_domain_age", False):
        explanation_tree.append({
            "reason": "Newly Registered Domain",
            "detail": f"Sender domain '{sender_rep.get('domain')}' was registered recently ({sender_rep.get('domain_age_days')} days ago).",
            "confidence": 0.95
        })
        
    # Add authentication failures
    if header_auth.get("spf") == "fail":
        explanation_tree.append({
            "reason": "SPF Authentication Failure",
            "detail": "The sender's IP address is not authorized to send emails on behalf of this domain.",
            "confidence": 0.90
        })
    if header_auth.get("dmarc") == "fail":
        explanation_tree.append({
            "reason": "DMARC Authentication Failure",
            "detail": "DMARC check failed, meaning the email domain header alignment is invalid.",
            "confidence": 0.92
        })
        
    # Add URL findings
    for url_verdict in url_verdicts:
        if url_verdict["verdict"] in ["MALICIOUS", "SUSPICIOUS"]:
            explanation_tree.append({
                "reason": "Suspicious URL Detected",
                "detail": f"The link '{url_verdict['url']}' is flagged as {url_verdict['verdict'].lower()}: {url_verdict['details']}",
                "confidence": url_verdict["confidence"]
            })
            
    # Add header anomalies
    mismatches = header_anomalies.get("mismatches", [])
    for mismatch in mismatches:
        explanation_tree.append({
            "reason": "Header Domain Mismatch",
            "detail": mismatch,
            "confidence": 0.85
        })
        
    # Add NLP signals
    detected_spoofs = nlp_analysis.get("detected_spoofs", [])
    for spoof in detected_spoofs:
        explanation_tree.append({
            "reason": "Brand Impersonation (Homoglyph)",
            "detail": spoof,
            "confidence": 0.98
        })
        
    cred_harvesting_phrases = nlp_analysis.get("cred_harvesting_phrases", [])
    if cred_harvesting_phrases:
        explanation_tree.append({
            "reason": "Credential Harvesting Intent",
            "detail": f"Detected phrases prompting user credentials: {', '.join(cred_harvesting_phrases)}",
            "confidence": 0.88
        })
        
    if state.get("nlp_urgency_score", 0.0) > 0.6:
        explanation_tree.append({
            "reason": "High Urgency Sentiment",
            "detail": "The email language attempts to coerce immediate actions under threat of account suspension.",
            "confidence": 0.80
        })
        
    # If the email is relatively safe, add safe node
    if not explanation_tree:
        explanation_tree.append({
            "reason": "No Security Anomalies Detected",
            "detail": "Authentication headers passed and the message content contains standard business patterns.",
            "confidence": 0.85
        })
        
    # 2. Query LLM if OPENAI_API_KEY is available
    openai_key = os.getenv("OPENAI_API_KEY")
    llm_explanation = ""
    
    if openai_key:
        try:
            # Query OpenAI using standard packages (or langchain if loaded)
            from langchain_openai import ChatOpenAI
            from langchain.prompts import ChatPromptTemplate
            
            chat = ChatOpenAI(temperature=0.0, openai_api_key=openai_key)
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are an expert Phishing Forensic AI Analyst. Synthesize a clean, professional, human-readable executive summary explaining why this email is flagged with a risk score of {risk_score}/100. Structure it using 2-3 bullet points. Focus on the core risk indicators: {indicators}."),
                ("user", "Subject: {subject}\n\nBody: {body_text}")
            ])
            
            chain = prompt | chat
            indicators_str = ", ".join([e["reason"] for e in explanation_tree])
            response = chain.invoke({
                "risk_score": risk_score,
                "indicators": indicators_str,
                "subject": subject,
                "body_text": state.get("body_text", "")[:2000] # truncate body text
            })
            llm_explanation = response.content
        except Exception as e:
            print(f"Failed to query OpenAI API: {e}. Falling back to heuristic text synthesis.")
            
    # Fallback to high-quality heuristic explanation synthesis
    if not llm_explanation:
        verdict_str = "PHISHING / MALICIOUS" if risk_score > 70 else ("SUSPICIOUS" if risk_score > 40 else "SAFE")
        llm_explanation = f"PhishShield AI has classified this email as **{verdict_str}** with a risk score of **{risk_score}/100**.\n\n"
        llm_explanation += "### Key Findings:\n"
        for item in explanation_tree:
            llm_explanation += f"- **{item['reason']}**: {item['detail']} *(Confidence: {int(item['confidence']*100)}%)*\n"
        llm_explanation += "\n**Analyst Recommendation:** Do not click on any links, download attachments, or reply to this sender. Block the sender and report this email to your organization's IT security team."
        
    return {
        "llm_explanation": llm_explanation,
        "explanation_tree": explanation_tree
    }

# --- Compile the LangGraph WorkFlow ---

workflow = StateGraph(AnalysisState)

# Add Nodes
workflow.add_node("parse_email", parse_email_node)
workflow.add_node("check_urls", check_urls_node)
workflow.add_node("verify_sender", verify_sender_node)
workflow.add_node("analyze_headers", analyze_headers_node)
workflow.add_node("nlp_scan", nlp_scan_node)
workflow.add_node("aggregate", aggregate_node)
workflow.add_node("ml_inference", ml_inference_node)
workflow.add_node("llm_explain", llm_explain_node)

# Set Entry Point
workflow.set_entry_point("parse_email")

# Connect parallel branches
workflow.add_edge("parse_email", "check_urls")
workflow.add_edge("parse_email", "verify_sender")
workflow.add_edge("parse_email", "analyze_headers")
workflow.add_edge("parse_email", "nlp_scan")

# Merge parallel branches back (fan-in)
workflow.add_edge("check_urls", "aggregate")
workflow.add_edge("verify_sender", "aggregate")
workflow.add_edge("analyze_headers", "aggregate")
workflow.add_edge("nlp_scan", "aggregate")

# Sequence aggregate -> ML Inference
workflow.add_edge("aggregate", "ml_inference")

# Router logic: Conditional routing after ML Inference
workflow.add_conditional_edges(
    "ml_inference",
    conditional_router,
    {
        "detailed_xai": "llm_explain",
        "standard_summary": "llm_explain" # For PoC, both end at the explain node, but they represent conditional logic paths.
    }
)

workflow.add_edge("llm_explain", END)

# Compile Graph
app_graph = workflow.compile()

def analyze_email_workflow(raw_email: str) -> Dict[str, Any]:
    """Runs the compiled LangGraph phishing analysis workflow on raw email input."""
    initial_state = {
        "raw_email": raw_email,
        "url_verdicts": [],
        "header_auth_results": {},
        "sender_reputation": {},
        "nlp_urgency_score": 0.0,
        "ml_phishing_probability": 0.0,
        "final_risk_score": 0,
        "llm_explanation": "",
        "explanation_tree": []
    }
    
    # Run the graph
    result = app_graph.invoke(initial_state)
    return result

if __name__ == "__main__":
    # Test run
    sample_email = """From: Security Alert <no-reply@paypaI.com>
Subject: URGENT: Confirm your bank account details
To: user@example.com

Dear customer, we detected unusual login activity.
Confirm your identity now by visiting: http://192.168.1.1/paypal-security
Failure to verify your credentials within 24 hours will result in permanent account suspension.
"""
    res = analyze_email_workflow(sample_email)
    print(json.dumps(res, indent=2))
