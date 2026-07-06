import os
import json
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Import workflow and inference tools
from graph import analyze_email_workflow
from ml_model import predict_phishing

load_dotenv()

app = FastAPI(
    title="PhishShield AI - Sidecar Service",
    description="Python AI sidecar running LangGraph workflow & Scikit-learn predictions.",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    raw_email: str

class PredictRequest(BaseModel):
    text: str

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "phishshield-ai-sidecar"}

@app.post("/api/v1/analyze")
def analyze_email(payload: AnalyzeRequest):
    if not payload.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email content cannot be empty")
    try:
        results = analyze_email_workflow(payload.raw_email)
        # Filter keys to output clean JSON
        serializable_keys = [
            "subject", "body_text", "extracted_urls", "url_verdicts",
            "header_auth_results", "sender_reputation", "nlp_urgency_score",
            "ml_phishing_probability", "final_risk_score", "llm_explanation",
            "explanation_tree"
        ]
        response = {k: results.get(k) for k in serializable_keys}
        return response
    except Exception as e:
        print(f"Exception during analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/predict")
def predict_text(payload: PredictRequest):
    if not payload.text.strip():
        raise HTTPException(status_code=400, detail="text content cannot be empty")
    try:
        prob = predict_phishing(payload.text)
        return {"probability": prob}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ChatRequest(BaseModel):
    analysis_context: dict
    query: str

@app.post("/api/v1/chat")
def chat_with_analyst(payload: ChatRequest):
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        try:
            from langchain_openai import ChatOpenAI
            from langchain.prompts import ChatPromptTemplate
            chat = ChatOpenAI(temperature=0.2, openai_api_key=openai_key)
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are PhishShield AI Analyst, a helpful forensic security expert. Answer the user's question regarding a scanned email based on the following context. Be concise and precise. Context:\n{context}"),
                ("user", "{query}")
            ])
            chain = prompt | chat
            res = chain.invoke({
                "context": json.dumps(payload.analysis_context),
                "query": payload.query
            })
            return {"reply": res.content}
        except Exception as e:
            print(f"Error querying OpenAI for chat: {e}")
            
    # Heuristic response fallback
    q = payload.query.lower()
    record = payload.analysis_context
    score = record.get("risk_score", 0)
    tree = record.get("explanation_tree", [])
    subject = record.get("email_subject", "scanned email")
    
    if "why" in q or "reason" in q or "suspicious" in q:
        triggers = ", ".join([t.get("reason", "") for t in tree])
        reply = f"The email '{subject}' is flagged with a risk score of {score}/100. The key security triggers identified are: {triggers}."
        if score > 70:
            reply += " This represents a critical phishing threat, likely mimicking a popular financial or cloud brand to harvest credentials."
        return {"reply": reply}
        
    triggers_str = ", ".join([t.get("reason", "") for t in tree])
    return {"reply": f"As your PhishShield security analyst, I've reviewed the scan details for '{subject}' (Risk Score: {score}/100). It triggered flags for: {triggers_str}. Let me know if you want to inspect specific elements like SPF headers or links."}

if __name__ == "__main__":
    port = int(os.getenv("AI_SERVICE_PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
