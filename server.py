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
FROM_EMAIL = os.getenv("FROM_EMAIL", "otcpublishing@gmail.com")
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

class User(BaseModel):
    id: str
    email: str
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

async def fetch_google_doc_content(doc_id: str) -> dict:
    """Fetch content from a public Google Doc"""
    try:
        # Try the plain text export URL
        export_url = f"https://docs.google.com/document/d/{doc_id}/export?format=txt"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(export_url)
            
            if response.status_code == 200:
                content = response.text.strip()
                if content and len(content) > 10:
                    return {"success": True, "content": content, "method": "export"}
            
            # Fallback: Try accessing the document directly 
            doc_url = f"https://docs.google.com/document/d/{doc_id}/edit"
            response = await client.get(doc_url)
            
            if response.status_code == 200:
                html_content = response.text
                
                # Try to extract text content from HTML
                # This is a basic extraction - in production you might want more sophisticated parsing
                import re
                
                # Look for text content in common Google Docs patterns
                text_patterns = [
                    r'<span[^>]*>([^<]+)</span>',
                    r'>([^<]{10,})<',  # Any text content longer than 10 characters
                ]
                
                extracted_text = []
                for pattern in text_patterns:
                    matches = re.findall(pattern, html_content)
                    for match in matches:
                        clean_text = re.sub(r'\s+', ' ', match).strip()
                        if len(clean_text) > 10 and clean_text not in extracted_text:
                            extracted_text.append(clean_text)
                
                if extracted_text:
                    content = ' '.join(extracted_text[:50])  # Limit to first 50 segments
                    return {"success": True, "content": content, "method": "html_parse"}
            
            return {
                "success": False, 
                "error": "Document is not publicly accessible or doesn't exist",
                "status_code": response.status_code
            }
            
    except httpx.TimeoutException:
        return {"success": False, "error": "Request timed out - document may be too large or server is slow"}
    except httpx.HTTPError as e:
        return {"success": False, "error": f"Network error: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {str(e)}"}

def check_user_access(user: dict) -> bool:
    """Check if user has access based on subscription status"""
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
        "password_hash": hashed_password,
        "subscription_status": "trial",
        "trial_expires": trial_expires,
        "stripe_customer_id": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    await db.users.insert_one(user_doc)
    
    # Send welcome email
    welcome_html = f"""
    <h2>Welcome to AI Writing Pattern Detector!</h2>
    <p>Hi there,</p>
    <p>Thanks for signing up! Your 3-day free trial is now active.</p>
    <p>During your trial, you have unlimited access to:</p>
    <ul>
        <li>Document analysis (TXT, DOC, DOCX, RTF)</li>
        <li>Google Docs integration</li>
        <li>Advanced AI pattern detection</li>
        <li>Detailed analysis reports</li>
    </ul>
    <p>Your trial expires on <strong>{trial_expires.strftime('%B %d, %Y at %I:%M %p UTC')}</strong>.</p>
    <p>Ready to get started? <a href="https://genuineaf.ai">Analyze your first document</a></p>
    <p>Best regards,<br>The AI Writing Detector Team</p>
    """
    
    await send_email(email, "Welcome to AI Writing Detector - Free Trial Started!", welcome_html)
    
    # Create access token
    access_token = create_access_token(data={"user_id": user_id})
    
    # Return user data
    user_response = User(
        id=user_id,
        email=email,
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
# Add this at the very end of the file
app = app  # This ensures the app variable is available for Vercel
