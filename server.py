from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import re
import httpx
import asyncio
from passlib.context import CryptContext
from jose import JWTError, jwt
from email_validator import validate_email, EmailNotValidError
import stripe
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Authentication configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# Stripe configuration
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# SendGrid configuration
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "support@genuineaf.ai")
FROM_NAME = os.getenv("FROM_NAME", "AI Writing Detector")
sendgrid_client = SendGridAPIClient(api_key=SENDGRID_API_KEY) if SENDGRID_API_KEY else None

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Writing Detector API", version="1.0.0")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class UserSignup(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    name: str = Field(..., min_length=1, max_length=100)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class GoogleDocRequest(BaseModel):
    doc_url: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=6)

class FamilyMemberRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    name: str = Field(..., min_length=1, max_length=100)

class User(BaseModel):
    id: str
    email: str
    name: str
    subscription_status: str
    trial_expires: Optional[datetime] = None
    stripe_customer_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class StripeCheckoutRequest(BaseModel):
    price_id: str
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_first_name(full_name: str) -> str:
    """More robust first name extraction"""
    if not full_name or not full_name.strip():
        return "there"  # Fallback greeting
    parts = full_name.strip().split()
    return parts[0] if parts else full_name.strip()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"id": user_id})
    if user is None:
        raise credentials_exception
    
    return user

async def send_email(to_email: str, subject: str, html_content: str):
    """Send email using SendGrid"""
    if not sendgrid_client:
        logger.warning("SendGrid not configured, skipping email send")
        return
    
    try:
        message = Mail(
            from_email=(FROM_EMAIL, FROM_NAME),
            to_emails=to_email,
            subject=subject,
            html_content=html_content
        )
        response = sendgrid_client.send(message)
        logger.info(f"Email sent successfully to {to_email}")
        return response
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        return None

async def send_template_email(to_email: str, template_id: str, dynamic_data: dict = None):
    """Send email using SendGrid template"""
    if not sendgrid_client:
        logger.warning("SendGrid not configured, skipping template email send")
        return
    
    try:
        message = Mail(
            from_email=(FROM_EMAIL, FROM_NAME),
            to_emails=to_email
        )
        message.template_id = template_id
        
        if dynamic_data:
            message.dynamic_template_data = dynamic_data
            
        response = sendgrid_client.send(message)
        logger.info(f"Template email sent successfully to {to_email} using template {template_id}")
        return response
    except Exception as e:
        logger.error(f"Failed to send template email to {to_email}: {str(e)}")
        return None

async def add_contact_to_sendgrid_list(email: str, name: str = "", list_id: str = "5f1fce5f-ca63-4cc9-9ada-552d02cc662d", additional_data: dict = None):
    """Add contact to SendGrid marketing list"""
    if not sendgrid_client:
        logger.warning("SendGrid not configured, skipping contact addition")
        return None
    
    try:
        # Prepare contact data
        contact_data = {
            "email": email
        }
        
        # Add name if provided
        if name:
            contact_data["first_name"] = get_first_name(name)
            contact_data["last_name"] = name.split()[-1] if len(name.split()) > 1 else ""
        
        # Add any additional custom field data
        if additional_data:
            contact_data.update(additional_data)
        
        # Prepare the request payload
        data = {
            "list_ids": [list_id],
            "contacts": [contact_data]
        }
        
        # Make the API request to add contact
        response = sendgrid_client.client.marketing.contacts.put(request_body=data)
        
        if response.status_code in [200, 202]:
            logger.info(f"Contact {email} added to SendGrid list {list_id} successfully")
            return response
        else:
            logger.error(f"Failed to add contact {email} to SendGrid list. Status: {response.status_code}, Body: {response.body}")
            return None
            
    except Exception as e:
        logger.error(f"Failed to add contact {email} to SendGrid list: {str(e)}")
        return None

async def send_template_email_safe(to_email: str, template_id: str, name: str = "", dynamic_data: dict = None):
    """
    Send template email with safe fallbacks for name personalization
    This ensures emails are sent even if name is missing
    """
    if not sendgrid_client:
        logger.warning("SendGrid not configured, skipping template email send")
        return None
    
    # Prepare template data with safe fallbacks
    template_data = dynamic_data.copy() if dynamic_data else {}
    
    # Always ensure name and first_name are available for templates
    if name:
        template_data["name"] = name
        template_data["first_name"] = get_first_name(name)
    else:
        template_data["name"] = "there"  # Fallback greeting
        template_data["first_name"] = "there"  # Fallback greeting
    
    return await send_template_email(to_email, template_id, template_data)

def extract_google_doc_id(url: str) -> Optional[str]:
    """Extract document ID from Google Docs URL"""
    patterns = [
        r'/document/d/([a-zA-Z0-9-_]+)',
        r'id=([a-zA-Z0-9-_]+)',
        r'^([a-zA-Z0-9-_]+)$'  # Just the ID itself
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    return None

def extract_published_doc_content(html_content: str) -> Optional[str]:
    """Extract text content from published Google Docs HTML"""
    try:
        # Look for content in published Google Docs structure
        import re
        from html import unescape
        
        # Remove script and style elements
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        
        # Look for main content patterns in published docs
        content_patterns = [
            r'<div[^>]*class="[^"]*doc-content[^"]*"[^>]*>(.*?)</div>',
            r'<div[^>]*id="contents"[^>]*>(.*?)</div>',
            r'<div[^>]*class="[^"]*document[^"]*"[^>]*>(.*?)</div>',
            r'<body[^>]*>(.*?)</body>'
        ]
        
        extracted_content = ""
        for pattern in content_patterns:
            matches = re.findall(pattern, html_content, re.DOTALL | re.IGNORECASE)
            if matches:
                extracted_content = matches[0]
                break
        
        if extracted_content:
            # Extract text from HTML tags
            text_content = re.sub(r'<[^>]+>', ' ', extracted_content)
            # Clean up whitespace and decode HTML entities
            text_content = unescape(text_content)
            text_content = re.sub(r'\s+', ' ', text_content).strip()
            
            # Filter out very short content or navigation elements
            if len(text_content) > 100:
                return text_content
        
        return None
    except Exception as e:
        logger.warning(f"Error extracting published doc content: {str(e)}")
        return None

def extract_document_content_from_html(html_content: str) -> Optional[str]:
    """Enhanced HTML parsing for Google Docs content with better content detection"""
    try:
        import re
        from html import unescape
        
        # Remove script, style, and other non-content elements
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<noscript[^>]*>.*?</noscript>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        
        # Enhanced patterns for Google Docs content extraction
        content_patterns = [
            # Google Docs specific content containers
            r'<div[^>]*class="[^"]*kix-[^"]*"[^>]*>(.*?)</div>',
            r'<span[^>]*class="[^"]*kix-[^"]*"[^>]*>([^<]+)</span>',
            # General content patterns
            r'<p[^>]*>([^<]+)</p>',
            r'<div[^>]*>([^<]{20,})</div>',  # Divs with substantial text
            r'<span[^>]*>([^<]{15,})</span>',  # Spans with meaningful content
            # Fallback patterns
            r'>([^<]{25,})<',  # Any substantial text between tags
        ]
        
        extracted_texts = []
        seen_texts = set()
        
        for pattern in content_patterns:
            matches = re.findall(pattern, html_content, re.DOTALL)
            for match in matches:
                # Clean the text
                if isinstance(match, tuple):
                    text = match[0] if match else ""
                else:
                    text = match
                
                # Decode HTML entities and clean whitespace
                clean_text = unescape(text)
                clean_text = re.sub(r'\s+', ' ', clean_text).strip()
                
                # Filter criteria
                if (len(clean_text) > 15 and 
                    clean_text not in seen_texts and
                    not re.match(r'^[\s\W]*$', clean_text) and  # Not just whitespace/punctuation
                    'google' not in clean_text.lower()[:50] and  # Skip Google branding
                    'docs' not in clean_text.lower()[:50]):
                    
                    extracted_texts.append(clean_text)
                    seen_texts.add(clean_text)
                    
                    # Limit extraction to prevent overwhelming content
                    if len(extracted_texts) >= 100:
                        break
        
        if extracted_texts:
            # Join the extracted texts and limit total length
            full_content = ' '.join(extracted_texts)
            # Limit to reasonable size (about 10,000 characters)
            if len(full_content) > 10000:
                full_content = full_content[:10000] + "..."
            
            return full_content if len(full_content) > 50 else None
        
        return None
        
    except Exception as e:
        logger.warning(f"Error in enhanced HTML content extraction: {str(e)}")
        return None

async def fetch_google_doc_content(doc_id: str) -> dict:
    """Fetch content from a public Google Doc with improved extraction methods"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Method 1: Try the plain text export URL (most reliable for public docs)
            export_url = f"https://docs.google.com/document/d/{doc_id}/export?format=txt"
            
            try:
                response = await client.get(export_url, follow_redirects=True)
                if response.status_code == 200:
                    content = response.text.strip()
                    # Check if content is actual text (not HTML redirect page)
                    if content and len(content) >= 5 and not content.startswith('<HTML>'):
                        logger.info(f"Successfully extracted {len(content)} characters using export method")
                        return {"success": True, "content": content, "method": "export"}
                    elif content.startswith('<HTML>'):
                        logger.warning(f"Export returned HTML redirect page instead of text content")
                elif response.status_code == 403:
                    logger.warning(f"Document {doc_id} is not publicly accessible for export")
                else:
                    logger.warning(f"Export failed with status {response.status_code}")
            except Exception as e:
                logger.warning(f"Export method failed: {str(e)}")
            
            # Method 2: Try alternative export URLs
            alt_export_urls = [
                f"https://docs.google.com/document/d/{doc_id}/export?format=pdf",  # PDF fallback
                f"https://docs.google.com/document/d/{doc_id}/pub"  # Published version
            ]
            
            for alt_url in alt_export_urls:
                try:
                    response = await client.get(alt_url)
                    if response.status_code == 200 and len(response.text) > 100:
                        # For published docs, extract text content
                        if "/pub" in alt_url:
                            html_content = response.text
                            # Look for actual document content in published version
                            content = extract_published_doc_content(html_content)
                            if content and len(content) > 50:
                                logger.info(f"Successfully extracted {len(content)} characters from published version")
                                return {"success": True, "content": content, "method": "published"}
                except Exception:
                    continue
            
            # Method 3: Enhanced HTML parsing with better content detection
            doc_url = f"https://docs.google.com/document/d/{doc_id}/edit"
            try:
                response = await client.get(doc_url)
                if response.status_code == 200:
                    html_content = response.text
                    content = extract_document_content_from_html(html_content)
                    
                    if content and len(content) > 50:
                        logger.info(f"Successfully extracted {len(content)} characters using enhanced HTML parsing")
                        return {"success": True, "content": content, "method": "enhanced_html_parse"}
                    else:
                        logger.warning(f"HTML parsing extracted insufficient content: {len(content) if content else 0} characters")
            except Exception as e:
                logger.warning(f"HTML parsing failed: {str(e)}")
            
            return {
                "success": False, 
                "error": "Document is not publicly accessible, doesn't exist, or content extraction failed",
                "details": "Tried export, published, and HTML parsing methods"
            }
            
    except httpx.TimeoutException:
        return {"success": False, "error": "Request timed out - document may be too large or server is slow"}
    except httpx.HTTPError as e:
        return {"success": False, "error": f"Network error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error in Google Docs extraction: {str(e)}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}

def check_user_access(user: dict) -> bool:
    """Check if user has access based on subscription status"""
    # Family members get unlimited access
    family_members = [
        "drkilstein@gmail.com",
        "shmuelkilstein@gmail.com", 
        "joeysosin@gmail.com",
        "jacobsosin@gmail.com"
    ]
    
    if user["email"] in family_members:
        return True
    
    if user["subscription_status"] in ["pro", "business", "active"]:
        return True
    
    if user["subscription_status"] == "trial":
        trial_expires = user.get("trial_expires")
        if trial_expires and isinstance(trial_expires, datetime):
            return datetime.utcnow() < trial_expires
        return False
    
    return False

# Routes
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.post("/api/auth/signup", response_model=Token)
async def signup(user_data: UserSignup):
    try:
        # Validate email
        validated_email = validate_email(user_data.email)
        email = validated_email.email
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Invalid email address")
    
    # Check if user already exists
    existing_user = await db.users.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    hashed_password = get_password_hash(user_data.password)
    
    # Create user
    user_id = str(uuid.uuid4())
    trial_expires = datetime.utcnow() + timedelta(days=3)
    
    user_doc = {
        "id": user_id,
        "email": email,
        "name": user_data.name,
        "password_hash": hashed_password,
        "subscription_status": "trial",
        "trial_expires": trial_expires,
        "stripe_customer_id": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    await db.users.insert_one(user_doc)
    
    # Send welcome email using SendGrid template
    await send_template_email_safe(
        email, 
        "d-1070bc39b3e741748d103ae177d8537a",  # GenuineAF Day 1 Welcome template
        user_data.name,
        {
            "trial_expires": trial_expires.strftime('%B %d, %Y at %I:%M %p UTC')
        }
    )
    
    # Add user to SendGrid trial list
    await add_contact_to_sendgrid_list(
        email=email,
        name=user_data.name,
        additional_data={
            "signup_date": datetime.utcnow().strftime('%Y-%m-%d'),
            "subscription_status": "trial",
            "trial_expires": trial_expires.strftime('%Y-%m-%d')
        }
    )
    
    # Create access token
    access_token = create_access_token(data={"user_id": user_id})
    
    # Return user data
    user_response = User(
        id=user_id,
        email=email,
        name=user_data.name,
        subscription_status="trial",
        trial_expires=trial_expires,
        created_at=user_doc["created_at"],
        updated_at=user_doc["updated_at"]
    )
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@app.post("/api/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    try:
        validated_email = validate_email(user_data.email)
        email = validated_email.email
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Invalid email address")
    
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # Create access token
    access_token = create_access_token(data={"user_id": user["id"]})
    
    # Return user data
    user_response = User(
        id=user["id"],
        email=user["email"],
        name=user.get("name", ""),  # Handle existing users without names
        subscription_status=user["subscription_status"],
        trial_expires=user.get("trial_expires"),
        stripe_customer_id=user.get("stripe_customer_id"),
        created_at=user["created_at"],
        updated_at=user["updated_at"]
    )
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@app.post("/api/auth/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    try:
        # Validate email
        validated_email = validate_email(request.email)
        email = validated_email.email
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Invalid email address")
    
    # Check if user exists
    user = await db.users.find_one({"email": email})
    if not user:
        # Don't reveal if user exists or not for security
        return {"message": "If an account with this email exists, a password reset link has been sent."}
    
    # Generate password reset token (valid for 1 hour)
    reset_token = str(uuid.uuid4())
    reset_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Store reset token in database
    await db.users.update_one(
        {"email": email},
        {"$set": {
            "reset_token": reset_token,
            "reset_expires": reset_expires,
            "updated_at": datetime.utcnow()
        }}
    )
    
    # Send password reset email
    if sendgrid_client:
        try:
            reset_link = f"https://ai-writing-detector.onrender.com/reset-password?token={reset_token}"
            
            message = Mail(
                from_email=FROM_EMAIL,
                to_emails=email,
                subject="Reset Your Password - AI Writing Detector",
                html_content=f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Reset Your Password</h2>
                    <p>Hello,</p>
                    <p>You requested a password reset for your AI Writing Detector account. Click the link below to reset your password:</p>
                    <p style="margin: 30px 0;">
                        <a href="{reset_link}" 
                           style="background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
                            Reset Password
                        </a>
                    </p>
                    <p>This link will expire in 1 hour for security reasons.</p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                    <p>Best regards,<br>The AI Writing Detector Team</p>
                </div>
                """
            )
            
            sendgrid_client.send(message)
        except Exception as e:
            logging.error(f"Failed to send password reset email: {e}")
    
    return {"message": "If an account with this email exists, a password reset link has been sent."}

@app.post("/api/auth/reset-password")
async def reset_password(request: ResetPasswordRequest):
    # Find user by reset token
    user = await db.users.find_one({
        "reset_token": request.token,
        "reset_expires": {"$gt": datetime.utcnow()}
    })
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    # Hash new password
    hashed_password = get_password_hash(request.new_password)
    
    # Update user password and clear reset token
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password_hash": hashed_password,
            "updated_at": datetime.utcnow()
        },
        "$unset": {
            "reset_token": "",
            "reset_expires": ""
        }}
    )
    
    return {"message": "Password has been reset successfully. You can now log in with your new password."}

@app.get("/api/auth/me", response_model=User)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return User(
        id=current_user["id"],
        email=current_user["email"],
        name=current_user.get("name", ""),  # Handle existing users without names
        subscription_status=current_user["subscription_status"],
        trial_expires=current_user.get("trial_expires"),
        stripe_customer_id=current_user.get("stripe_customer_id"),
        created_at=current_user["created_at"],
        updated_at=current_user["updated_at"]
    )

@app.post("/api/analyze-google-doc")
async def analyze_google_doc(request: GoogleDocRequest, current_user: dict = Depends(get_current_user)):
    # Check user access
    if not check_user_access(current_user):
        if current_user["subscription_status"] == "trial":
            raise HTTPException(
                status_code=402, 
                detail="Your free trial has expired. Please upgrade to continue using the service."
            )
        else:
            raise HTTPException(
                status_code=402,
                detail="Please upgrade your subscription to access this feature."
            )
    
    # Extract document ID from URL
    doc_id = extract_google_doc_id(request.doc_url)
    if not doc_id:
        raise HTTPException(
            status_code=400, 
            detail="Invalid Google Docs URL. Please provide a valid Google Docs link."
        )
    
    # Fetch document content
    result = await fetch_google_doc_content(doc_id)
    
    if not result["success"]:
        if "not publicly accessible" in result.get("error", ""):
            raise HTTPException(
                status_code=400,
                detail="This Google Doc is not publicly accessible. Please make sure the document is shared with 'Anyone with the link can view' permissions."
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to fetch Google Doc: {result.get('error', 'Unknown error')}"
            )
    
    return result

# Stripe Routes
@app.get("/api/stripe/config")
async def get_stripe_config():
    return {"publishable_key": STRIPE_PUBLISHABLE_KEY}

@app.post("/api/stripe/create-checkout-session")
async def create_checkout_session(
    request: StripeCheckoutRequest, 
    current_user: dict = Depends(get_current_user)
):
    try:
        # Get or create Stripe customer
        stripe_customer_id = current_user.get("stripe_customer_id")
        
        if not stripe_customer_id:
            # Create new Stripe customer
            customer = stripe.Customer.create(
                email=current_user["email"],
                metadata={"user_id": current_user["id"]}
            )
            stripe_customer_id = customer.id
            
            # Update user with Stripe customer ID
            await db.users.update_one(
                {"id": current_user["id"]},
                {"$set": {"stripe_customer_id": stripe_customer_id, "updated_at": datetime.utcnow()}}
            )
        
        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': request.price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=request.success_url or 'https://genuineaf.ai/success',
            cancel_url=request.cancel_url or 'https://genuineaf.ai/cancel',
            metadata={
                'user_id': current_user["id"],
                'price_id': request.price_id
            }
        )
        
        return {"checkout_url": checkout_session.url}
        
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        logger.error(f"Checkout session creation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create checkout session")

@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        logger.error(f"Invalid payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid signature: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        
        if user_id:
            # Update user subscription status
            subscription_status = "pro"  # Default to pro
            
            # Determine subscription type based on price_id or subscription details
            if session.get('subscription'):
                subscription = stripe.Subscription.retrieve(session['subscription'])
                price_id = subscription['items']['data'][0]['price']['id']
                
                # Map price IDs to subscription types
                if price_id == "price_1Rta8FGxbXNfm3xsX4SgFsYJ":  # Business plan
                    subscription_status = "business"
                elif price_id == "price_1Rta7fGxbXNfm3xszfM9Xanr":  # Pro plan
                    subscription_status = "pro"
            
            await db.users.update_one(
                {"id": user_id},
                {
                    "$set": {
                        "subscription_status": subscription_status,
                        "updated_at": datetime.utcnow()
                    },
                    "$unset": {"trial_expires": ""}
                }
            )
            
            # Get user for email
            user = await db.users.find_one({"id": user_id})
            if user:
                # Send confirmation email
                plan_name = "Business Plan" if subscription_status == "business" else "Pro Plan"
                confirmation_html = f"""
                <h2>Payment Successful - Welcome to {plan_name}!</h2>
                <p>Hi {user['email']},</p>
                <p>Thank you for upgrading to the <strong>{plan_name}</strong>!</p>
                <p>Your subscription is now active and you have unlimited access to all features:</p>
                <ul>
                    <li>Unlimited document analysis</li>
                    <li>Google Docs integration</li>
                    <li>Advanced AI pattern detection</li>
                    <li>Priority support</li>
                    {f'<li>Team collaboration features</li><li>API access</li>' if subscription_status == 'business' else ''}
                </ul>
                <p><a href="https://genuineaf.ai">Start analyzing your documents</a></p>
                <p>Best regards,<br>The AI Writing Detector Team</p>
                """
                
                await send_email(
                    user['email'], 
                    f"Welcome to {plan_name} - Payment Confirmed!", 
                    confirmation_html
                )
            
            logger.info(f"User {user_id} upgraded to {subscription_status}")
    
    elif event['type'] == 'customer.subscription.deleted':
        # Handle subscription cancellation
        subscription = event['data']['object']
        customer_id = subscription['customer']
        
        # Find user by Stripe customer ID
        user = await db.users.find_one({"stripe_customer_id": customer_id})
        if user:
            await db.users.update_one(
                {"id": user["id"]},
                {
                    "$set": {
                        "subscription_status": "cancelled",
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            logger.info(f"User {user['id']} subscription cancelled")
    
    return {"status": "success"}

@app.post("/api/sendgrid/webhook")
async def sendgrid_webhook(request: Request):
    """Handle SendGrid webhook events"""
    try:
        payload = await request.body()
        
        # Parse the webhook payload
        try:
            events = await request.json()
        except Exception as e:
            logger.error(f"Failed to parse SendGrid webhook payload: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Handle multiple events (SendGrid can send multiple events in one request)
        if not isinstance(events, list):
            events = [events]
        
        processed_events = []
        
        for event in events:
            event_type = event.get('event')
            email = event.get('email')
            timestamp = event.get('timestamp')
            sg_event_id = event.get('sg_event_id')
            sg_message_id = event.get('sg_message_id')
            
            logger.info(f"SendGrid webhook event: {event_type} for {email} at {timestamp}")
            
            # Process different event types
            if event_type == 'delivered':
                logger.info(f"Email delivered successfully to {email}")
            elif event_type == 'bounce':
                logger.warning(f"Email bounced for {email}: {event.get('reason', 'Unknown reason')}")
            elif event_type == 'dropped':
                logger.warning(f"Email dropped for {email}: {event.get('reason', 'Unknown reason')}")
            elif event_type == 'spam_report':
                logger.warning(f"Spam report for {email}")
            elif event_type == 'unsubscribe':
                logger.info(f"Unsubscribe request from {email}")
            elif event_type == 'group_unsubscribe':
                logger.info(f"Group unsubscribe request from {email}")
            elif event_type == 'open':
                logger.info(f"Email opened by {email}")
            elif event_type == 'click':
                logger.info(f"Email link clicked by {email}")
            
            processed_events.append({
                "event": event_type,
                "email": email,
                "processed": True,
                "timestamp": timestamp
            })
        
        return {
            "status": "success",
            "processed_events": len(processed_events),
            "events": processed_events
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SendGrid webhook processing error: {str(e)}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

@app.post("/api/admin/create-family-member", response_model=Token)
async def create_family_member(request: FamilyMemberRequest, current_user: dict = Depends(get_current_user)):
    # Only allow drkilstein@gmail.com to create family members
    if current_user["email"] != "drkilstein@gmail.com":
        raise HTTPException(status_code=403, detail="Only family admin can create family members")
    
    try:
        # Validate email
        validated_email = validate_email(request.email)
        email = validated_email.email
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Invalid email address")
    
    # Check if user already exists
    existing_user = await db.users.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    hashed_password = get_password_hash(request.password)
    
    # Create family member with pro status (unlimited access)
    user_id = str(uuid.uuid4())
    
    user_doc = {
        "id": user_id,
        "email": email,
        "name": request.name,
        "password_hash": hashed_password,
        "subscription_status": "family_member",  # Special status for family
        "stripe_customer_id": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    await db.users.insert_one(user_doc)
    
    # Create access token
    access_token = create_access_token(data={"user_id": user_id})
    
    # Return user data
    user_response = User(
        id=user_id,
        email=email,
        name=request.name,
        subscription_status="family_member",
        created_at=user_doc["created_at"],
        updated_at=user_doc["updated_at"]
    )
    
    logger.info(f"Family member account created: {email}")
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@app.get("/api/admin/family-members")
async def list_family_members(current_user: dict = Depends(get_current_user)):
    # Only allow drkilstein@gmail.com to view family members
    if current_user["email"] != "drkilstein@gmail.com":
        raise HTTPException(status_code=403, detail="Only family admin can view family members")
    
    family_members = [
        "drkilstein@gmail.com",
        "shmuelkilstein@gmail.com", 
        "joeysosin@gmail.com",
        "jacobsosin@gmail.com"
    ]
    
    # Get all family member accounts
    cursor = db.users.find({"email": {"$in": family_members}})
    members = []
    async for user in cursor:
        members.append({
            "email": user["email"],
            "subscription_status": user["subscription_status"],
            "created_at": user["created_at"]
        })
    
    return {"family_members": members}

@app.get("/api/stripe/subscription")
async def get_subscription_info(current_user: dict = Depends(get_current_user)):
    if current_user.get("stripe_customer_id"):
        try:
            # Get customer's subscriptions from Stripe
            subscriptions = stripe.Subscription.list(
                customer=current_user["stripe_customer_id"],
                status="active"
            )
            
            has_active = len(subscriptions.data) > 0
            return {"has_active_subscription": has_active}
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error retrieving subscription: {e}")
            return {"has_active_subscription": False}
    
    return {"has_active_subscription": False}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8001, reload=True)
