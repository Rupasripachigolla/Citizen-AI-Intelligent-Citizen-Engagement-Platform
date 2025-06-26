# app.py - Main FastAPI Application
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import sqlite3
import hashlib
import secrets
import datetime
import json
from typing import Optional, Dict
import os
from pathlib import Path
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.llms.base import LLM
from typing import Any, List
from langchain_ibm import WatsonxLLM

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Install it with: pip install python-dotenv")
    print("Make sure to set environment variables manually.")

# Create directories if they don't exist
Path("templates").mkdir(exist_ok=True)
Path("static").mkdir(exist_ok=True)

app = FastAPI(title="Citizen AI", description="AI-powered citizen services platform")

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Fallback responses when AI is not available
FALLBACK_RESPONSES = [
    "I understand your query about Indian government services. For the most accurate and up-to-date information, I recommend visiting the official government portal at india.gov.in or contacting your nearest government office.",
    "Thank you for your question about citizen services. For specific legal or procedural guidance, please visit the official government website or contact your local government office for assistance.",
    "I appreciate your inquiry about Indian government services. For detailed information and official procedures, please refer to the relevant government department's official website or visit your nearest government office.",
    "Your question about government services is important. For official guidance and procedures, I recommend checking the official government portal or contacting the appropriate government department directly.",
    "Thank you for reaching out about government services. For the most current and accurate information, please visit the official government website or contact your local government office."
]

class CitizenAIDatabase:
    def __init__(self, db_path="citizen_ai.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize all required tables"""
        conn = sqlite3.connect(self.db_path)
        
        # Users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Sessions table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Chat history table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_message TEXT NOT NULL,
                ai_response TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Sentiment analysis table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sentiment_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                feedback_text TEXT NOT NULL,
                sentiment TEXT NOT NULL,
                confidence REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt.encode('utf-8'), 
            100000
        )
        return password_hash.hex(), salt
    
    def register_user(self, username: str, email: str, password: str, full_name: str) -> Dict:
        """Register a new user"""
        if len(password) < 8:
            return {"success": False, "message": "Password must be at least 8 characters"}
        
        password_hash, salt = self._hash_password(password)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, full_name)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, password_hash, salt, full_name))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            return {"success": True, "message": "Registration successful", "user_id": user_id}
        
        except sqlite3.IntegrityError as e:
            if "username" in str(e):
                return {"success": False, "message": "Username already exists"}
            elif "email" in str(e):
                return {"success": False, "message": "Email already exists"}
            else:
                return {"success": False, "message": "Registration failed"}
    
    def login_user(self, username: str, password: str) -> Dict:
        """Authenticate user and create session"""
        conn = sqlite3.connect(self.db_path)
        
        user_data = conn.execute('''
            SELECT id, username, password_hash, salt, is_active, full_name 
            FROM users WHERE username = ? OR email = ?
        ''', (username, username)).fetchone()
        
        if not user_data or not user_data[4]:
            conn.close()
            return {"success": False, "message": "Invalid credentials"}
        
        user_id, db_username, stored_hash, salt, is_active, full_name = user_data
        
        input_hash, _ = self._hash_password(password, salt)
        
        if input_hash == stored_hash:
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.datetime.now() + datetime.timedelta(days=7)
            
            conn.execute('''
                INSERT INTO sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, session_token, expires_at))
            
            conn.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "session_token": session_token,
                "user_id": user_id,
                "username": db_username,
                "full_name": full_name
            }
        else:
            conn.close()
            return {"success": False, "message": "Invalid credentials"}
    
    def verify_session(self, session_token: str) -> Optional[Dict]:
        """Verify session token"""
        if not session_token:
            return None
            
        conn = sqlite3.connect(self.db_path)
        
        result = conn.execute('''
            SELECT s.user_id, u.username, s.expires_at, u.is_active, u.full_name
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND s.is_active = 1
        ''', (session_token,)).fetchone()
        
        conn.close()
        
        if not result:
            return None
        
        user_id, username, expires_at, is_active, full_name = result
        expires_at = datetime.datetime.fromisoformat(expires_at)
        
        if expires_at < datetime.datetime.now() or not is_active:
            return None
        
        return {"user_id": user_id, "username": username, "full_name": full_name}
    
    def save_chat(self, user_id: int, user_message: str, ai_response: str):
        """Save chat interaction"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            INSERT INTO chat_history (user_id, user_message, ai_response)
            VALUES (?, ?, ?)
        ''', (user_id, user_message, ai_response))
        conn.commit()
        conn.close()
    
    def save_sentiment(self, user_id: int, feedback_text: str, sentiment: str, confidence: float = 0.0):
        """Save sentiment analysis result"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            INSERT INTO sentiment_analysis (user_id, feedback_text, sentiment, confidence)
            VALUES (?, ?, ?, ?)
        ''', (user_id, feedback_text, sentiment, confidence))
        conn.commit()
        conn.close()
    
    def get_chat_history(self, user_id: int, limit: int = 10):
        """Get user's chat history"""
        conn = sqlite3.connect(self.db_path)
        results = conn.execute('''
            SELECT user_message, ai_response, timestamp
            FROM chat_history
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (user_id, limit)).fetchall()
        conn.close()
        return results
    
    def get_sentiment_stats(self):
        """Get sentiment analysis statistics"""
        conn = sqlite3.connect(self.db_path)
        results = conn.execute('''
            SELECT sentiment, COUNT(*) as count
            FROM sentiment_analysis
            GROUP BY sentiment
        ''', ).fetchall()
        conn.close()
        return dict(results)

# Initialize database
db = CitizenAIDatabase()

# IBM Watsonx configuration - Replace with your actual credentials or use environment variables
WATSONX_URL = os.getenv("WATSONX_URL")
WATSONX_APIKEY = os.getenv("WATSONX_APIKEY")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID")

class SimpleCitizenAI:
    def __init__(self):
        self.prompt_template = self.create_prompt_template()
        # Initialize IBM WatsonxLLM
        self.llm = WatsonxLLM(
            model_id=os.getenv("WATSONX_MODEL_ID"),
            url=WATSONX_URL,
            apikey=WATSONX_APIKEY,
            project_id=WATSONX_PROJECT_ID,
            params={
                "decoding_method": "greedy",
                "max_new_tokens": 500,
                "temperature": 0.7
            }
        )

    def create_prompt_template(self):
        return PromptTemplate(
            input_variables=["user_question"],
            template="""You are Citizen AI, a smart assistant for Indian citizens. You help with questions about:
- Indian government services and schemes
- Sustainable city planning following Indian regulations
- Energy efficiency and renewable energy in Indian context
- Water management following Indian policies
- Waste management as per Indian guidelines
- Air quality and pollution control (Indian standards)
- Smart transportation systems in India
- Green building practices (Indian Green Building Council standards)
- Environmental monitoring per Indian regulations

IMPORTANT GUIDELINES:
- All responses must comply with Indian laws and the Indian Constitution
- For sensitive legal, financial, or personal matters, advise: "Please contact your nearest government office or authorized service center for detailed assistance"
- Provide practical solutions relevant to Indian cities and regulations
- Reference Indian government schemes and initiatives when applicable

User Question: {user_question}

Provide a helpful, actionable response focused on Indian context and regulations:"""
        )

    def generate_response(self, user_message: str) -> str:
        """Generate AI response using IBM Watsonx LLM"""
        try:
            prompt = self.prompt_template.format(user_question=user_message)
            response = self.llm(prompt)
            return response.strip()
        except Exception as e:
            return f"Sorry, there was an error connecting to the AI service: {str(e)}"

# Initialize AI
ai = SimpleCitizenAI()

def get_current_user(session_token: Optional[str] = Cookie(None)):
    """Get current user from session"""
    if not session_token:
        return None
    return db.verify_session(session_token)

def analyse_sentiment(text: str):
    """Simple sentiment analysis using keywords"""
    positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 
                      'satisfied', 'happy', 'pleased', 'impressed', 'helpful', 'efficient']
    negative_words = ['bad', 'terrible', 'awful', 'horrible', 'disappointed', 'frustrated',
                      'angry', 'unsatisfied', 'poor', 'waste', 'useless', 'slow']
    text_lower = text.lower()
    positive_count = sum(1 for word in positive_words if word in text_lower)
    negative_count = sum(1 for word in negative_words if word in text_lower)
    if positive_count > negative_count:
        sentiment = "Positive"
        confidence = min(0.6 + (positive_count - negative_count) * 0.1, 1.0)
    elif negative_count > positive_count:
        sentiment = "Negative"
        confidence = min(0.6 + (negative_count - positive_count) * 0.1, 1.0)
    else:
        sentiment = "Neutral"
        confidence = 0.5
    return sentiment, confidence

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request, session_token: Optional[str] = Cookie(None)):
    user = get_current_user(session_token)
    if user:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...)
):
    result = db.register_user(username, email, password, full_name)
    
    if result["success"]:
        return RedirectResponse(url="/login?message=Registration successful", status_code=302)
    else:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": result["message"]
        })

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, message: Optional[str] = None):
    return templates.TemplateResponse("login.html", {"request": request, "message": message})

@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    result = db.login_user(username, password)
    
    if result["success"]:
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie(key="session_token", value=result["session_token"], httponly=True)
        return response
    else:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": result["message"]
        })

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, session_token: Optional[str] = Cookie(None)):
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login")
    
    # Get recent chat history
    chat_history = db.get_chat_history(user["user_id"], 5)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "chat_history": chat_history
    })

@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request, session_token: Optional[str] = Cookie(None)):
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse("chat.html", {"request": request, "user": user})

@app.post("/chat")
async def chat(
    request: Request,
    message: str = Form(...),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login")
    
    # Generate AI response
    ai_response = ai.generate_response(message)
    
    # Save chat to database
    db.save_chat(user["user_id"], message, ai_response)
    
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "user": user,
        "user_message": message,
        "ai_response": ai_response
    })

@app.get("/feedback", response_class=HTMLResponse)
async def feedback_page(request: Request, session_token: Optional[str] = Cookie(None)):
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse("feedback.html", {"request": request, "user": user})

@app.post("/feedback")
async def submit_feedback(
    request: Request,
    feedback: str = Form(...),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login")
    
    # Analyze sentiment
    sentiment, confidence = analyse_sentiment(feedback)
    
    # Save to database
    db.save_sentiment(user["user_id"], feedback, sentiment, confidence)
    
    return templates.TemplateResponse("feedback.html", {
        "request": request,
        "user": user,
        "success": "Thank you for your feedback! Your sentiment has been analyzed and recorded.",
        "sentiment": sentiment
    })

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, session_token: Optional[str] = Cookie(None)):
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login")
    
    # Get sentiment statistics
    sentiment_stats = db.get_sentiment_stats()
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "sentiment_stats": sentiment_stats
    })

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(key="session_token")
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)