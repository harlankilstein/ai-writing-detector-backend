Perfect! Let's deploy your backend to Render.

## **🎯 STEP 1: GET YOUR BACKEND CODE**

I'll give you the 3 files you need. **Copy each one exactly:**

### **File 1: `server.py`**
Action: file_editor view /app/backend/server.py
Observation: /app/backend/server.py:
1|from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Request
2|from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
3|from dotenv import load_dotenv
4|from starlette.middleware.cors import CORSMiddleware
5|from motor.motor_asyncio import AsyncIOMotorClient
6|import os
7|import logging
8|from pathlib import Path
9|from pydantic import BaseModel, Field, EmailStr
10|from typing import List, Optional
11|import uuid
12|from datetime import datetime, timedelta
13|import re
14|import httpx
15|import asyncio
16|from passlib.context import CryptContext
17|from jose import JWTError, jwt
18|from email_validator import validate_email, EmailNotValidError
19|import stripe
20|from sendgrid import SendGridAPIClient
21|from sendgrid.helpers.mail import Mail
22|
23|
24|ROOT_DIR = Path(__file__).parent
25|load_dotenv(ROOT_DIR / '.env')
26|
27|# Authentication configuration
28|SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
29|ALGORITHM = "HS256"
30|ACCESS_TOKEN_EXPIRE_DAYS = 30
31|
32|# Stripe configuration
33|stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
34|STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
35|STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
36|
37|# SendGrid configuration
38|SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
39|FROM_EMAIL = os.getenv("FROM_EMAIL", "otcpublishing@gmail.com")
40|FROM_NAME = os.getenv("FROM_NAME", "AI Writing Detector")
41|sendgrid_client = SendGridAPIClient(api_key=SENDGRID_API_KEY) if SENDGRID_API_KEY else None
42|
43|# Password hashing
44|pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
45|security = HTTPBearer()
46|
47|# MongoDB connection
48|mongo_url = os.environ['MONGO_URL']
49|client = AsyncIOMotorClient(mongo_url)
50|db = client[os.environ['DB_NAME']]
51|
52|# Setup logging
53|logging.basicConfig(level=logging.INFO)
54|logger = logging.getLogger(__name__)
55|
56|app = FastAPI(title="AI Writing Detector API", version="1.0.0")
57|
58|# CORS Configuration
59|app.add_middleware(
60|    CORSMiddleware,
61|    allow_origins=["*"],
62|    allow_credentials=True,
63|    allow_methods=["*"],
64|    allow_headers=["*"],
65|)
66|
67|# Pydantic models
68|class UserSignup(BaseModel):
69|    email: EmailStr
70|    password: str = Field(..., min_length=6)
71|
72|class UserLogin(BaseModel):
73|    email: EmailStr
74|    password: str
75|
76|class GoogleDocRequest(BaseModel):
77|    doc_url: str
78|
79|class User(BaseModel):
80|    id: str
81|    email: str
82|    subscription_status: str
83|    trial_expires: Optional[datetime] = None
84|    stripe_customer_id: Optional[str] = None
85|    created_at: datetime
86|    updated_at: datetime
87|
88|class Token(BaseModel):
89|    access_token: str
90|    token_type: str
91|    user: User
92|
93|class StripeCheckoutRequest(BaseModel):
94|    price_id: str
95|    success_url: Optional[str] = None
96|    cancel_url: Optional[str] = None
97|
98|# Helper functions
99|def verify_password(plain_password, hashed_password):
100|    return pwd_context.verify(plain_password, hashed_password)
101|
102|def get_password_hash(password):
103|    return pwd_context.hash(password)
104|
105|def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
106|    to_encode = data.copy()
107|    if expires_delta:
108|        expire = datetime.utcnow() + expires_delta
109|    else:
110|        expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
111|    to_encode.update({"exp": expire})
112|    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
113|    return encoded_jwt
114|
115|async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
116|    credentials_exception = HTTPException(
117|        status_code=status.HTTP_401_UNAUTHORIZED,
118|        detail="Could not validate credentials",
119|        headers={"WWW-Authenticate": "Bearer"},
120|    )
121|    
122|    try:
123|        token = credentials.credentials
124|        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
125|        user_id: str = payload.get("user_id")
126|        if user_id is None:
127|            raise credentials_exception
128|    except JWTError:
129|        raise credentials_exception
130|    
131|    user = await db.users.find_one({"id": user_id})
132|    if user is None:
133|        raise credentials_exception
134|    
135|    return user
136|
137|async def send_email(to_email: str, subject: str, html_content: str):
138|    """Send email using SendGrid"""
139|    if not sendgrid_client:
140|        logger.warning("SendGrid not configured, skipping email send")
141|        return
142|    
143|    try:
144|        message = Mail(
145|            from_email=(FROM_EMAIL, FROM_NAME),
146|            to_emails=to_email,
147|            subject=subject,
148|            html_content=html_content
149|        )
150|        response = sendgrid_client.send(message)
151|        logger.info(f"Email sent successfully to {to_email}")
152|        return response
153|    except Exception as e:
154|        logger.error(f"Failed to send email to {to_email}: {str(e)}")
155|        return None
156|
157|def extract_google_doc_id(url: str) -> Optional[str]:
158|    """Extract document ID from Google Docs URL"""
159|    patterns = [
160|        r'/document/d/([a-zA-Z0-9-_]+)',
161|        r'id=([a-zA-Z0-9-_]+)',
162|        r'^([a-zA-Z0-9-_]+)$'  # Just the ID itself
163|    ]
164|    
165|    for pattern in patterns:
166|        match = re.search(pattern, url)
167|        if match:
168|            return match.group(1)
169|    
170|    return None
171|
172|async def fetch_google_doc_content(doc_id: str) -> dict:
173|    """Fetch content from a public Google Doc"""
174|    try:
175|        # Try the plain text export URL
176|        export_url = f"https://docs.google.com/document/d/{doc_id}/export?format=txt"
177|        
178|        async with httpx.AsyncClient(timeout=30.0) as client:
179|            response = await client.get(export_url)
180|            
181|            if response.status_code == 200:
182|                content = response.text.strip()
183|                if content and len(content) > 10:
184|                    return {"success": True, "content": content, "method": "export"}
185|            
186|            # Fallback: Try accessing the document directly 
187|            doc_url = f"https://docs.google.com/document/d/{doc_id}/edit"
188|            response = await client.get(doc_url)
189|            
190|            if response.status_code == 200:
191|                html_content = response.text
192|                
193|                # Try to extract text content from HTML
194|                # This is a basic extraction - in production you might want more sophisticated parsing
195|                import re
196|                
197|                # Look for text content in common Google Docs patterns
198|                text_patterns = [
199|                    r'<span[^>]*>([^<]+)</span>',
200|                    r'>([^<]{10,})<',  # Any text content longer than 10 characters
201|                ]
202|                
203|                extracted_text = []
204|                for pattern in text_patterns:
205|                    matches = re.findall(pattern, html_content)
206|                    for match in matches:
207|                        clean_text = re.sub(r'\s+', ' ', match).strip()
208|                        if len(clean_text) > 10 and clean_text not in extracted_text:
209|                            extracted_text.append(clean_text)
210|                
211|                if extracted_text:
212|                    content = ' '.join(extracted_text[:50])  # Limit to first 50 segments
213|                    return {"success": True, "content": content, "method": "html_parse"}
214|            
215|            return {
216|                "success": False, 
217|                "error": "Document is not publicly accessible or doesn't exist",
218|                "status_code": response.status_code
219|            }
220|            
221|    except httpx.TimeoutException:
222|        return {"success": False, "error": "Request timed out - document may be too large or server is slow"}
223|    except httpx.HTTPError as e:
224|        return {"success": False, "error": f"Network error: {str(e)}"}
225|    except Exception as e:
226|        return {"success": False, "error": f"Unexpected error: {str(e)}"}
227|
228|def check_user_access(user: dict) -> bool:
229|    """Check if user has access based on subscription status"""
230|    if user["subscription_status"] in ["pro", "business", "active"]:
231|        return True
232|    
233|    if user["subscription_status"] == "trial":
234|        trial_expires = user.get("trial_expires")
235|        if trial_expires and isinstance(trial_expires, datetime):
236|            return datetime.utcnow() < trial_expires
237|        return False
238|    
239|    return False
240|
241|# Routes
242|@app.get("/health")
243|async def health_check():
244|    return {"status": "healthy", "timestamp": datetime.utcnow()}
245|
246|@app.post("/api/auth/signup", response_model=Token)
247|async def signup(user_data: UserSignup):
248|    try:
249|        # Validate email
250|        validated_email = validate_email(user_data.email)
251|        email = validated_email.email
252|    except EmailNotValidError:
253|        raise HTTPException(status_code=400, detail="Invalid email address")
254|    
255|    # Check if user already exists
256|    existing_user = await db.users.find_one({"email": email})
257|    if existing_user:
258|        raise HTTPException(status_code=400, detail="Email already registered")
259|    
260|    # Hash password
261|    hashed_password = get_password_hash(user_data.password)
262|    
263|    # Create user
264|    user_id = str(uuid.uuid4())
265|    trial_expires = datetime.utcnow() + timedelta(days=3)
266|    
267|    user_doc = {
268|        "id": user_id,
269|        "email": email,
270|        "password_hash": hashed_password,
271|        "subscription_status": "trial",
272|        "trial_expires": trial_expires,
273|        "stripe_customer_id": None,
274|        "created_at": datetime.utcnow(),
275|        "updated_at": datetime.utcnow()
276|    }
277|    
278|    await db.users.insert_one(user_doc)
279|    
280|    # Send welcome email
281|    welcome_html = f"""
282|    <h2>Welcome to AI Writing Pattern Detector!</h2>
283|    <p>Hi there,</p>
284|    <p>Thanks for signing up! Your 3-day free trial is now active.</p>
285|    <p>During your trial, you have unlimited access to:</p>
286|    <ul>
287|        <li>Document analysis (TXT, DOC, DOCX, RTF)</li>
288|        <li>Google Docs integration</li>
289|        <li>Advanced AI pattern detection</li>
290|        <li>Detailed analysis reports</li>
291|    </ul>
292|    <p>Your trial expires on <strong>{trial_expires.strftime('%B %d, %Y at %I:%M %p UTC')}</strong>.</p>
293|    <p>Ready to get started? <a href="https://genuineaf.ai">Analyze your first document</a></p>
294|    <p>Best regards,<br>The AI Writing Detector Team</p>
295|    """
296|    
297|    await send_email(email, "Welcome to AI Writing Detector - Free Trial Started!", welcome_html)
298|    
299|    # Create access token
300|    access_token = create_access_token(data={"user_id": user_id})
301|    
302|    # Return user data
303|    user_response = User(
304|        id=user_id,
305|        email=email,
306|        subscription_status="trial",
307|        trial_expires=trial_expires,
308|        created_at=user_doc["created_at"],
309|        updated_at=user_doc["updated_at"]
310|    )
311|    
312|    return Token(access_token=access_token, token_type="bearer", user=user_response)
313|
314|@app.post("/api/auth/login", response_model=Token)
315|async def login(user_data: UserLogin):
316|    try:
317|        validated_email = validate_email(user_data.email)
318|        email = validated_email.email
319|    except EmailNotValidError:
320|        raise HTTPException(status_code=400, detail="Invalid email address")
321|    
322|    user = await db.users.find_one({"email": email})
323|    if not user or not verify_password(user_data.password, user["password_hash"]):
324|        raise HTTPException(status_code=400, detail="Incorrect email or password")
325|    
326|    # Create access token
327|    access_token = create_access_token(data={"user_id": user["id"]})
328|    
329|    # Return user data
330|    user_response = User(
331|        id=user["id"],
332|        email=user["email"],
333|        subscription_status=user["subscription_status"],
334|        trial_expires=user.get("trial_expires"),
335|        stripe_customer_id=user.get("stripe_customer_id"),
336|        created_at=user["created_at"],
337|        updated_at=user["updated_at"]
338|    )
339|    
340|    return Token(access_token=access_token, token_type="bearer", user=user_response)
341|
342|@app.get("/api/auth/me", response_model=User)
343|async def get_current_user_info(current_user: dict = Depends(get_current_user)):
344|    return User(
345|        id=current_user["id"],
346|        email=current_user["email"],
347|        subscription_status=current_user["subscription_status"],
348|        trial_expires=current_user.get("trial_expires"),
349|        stripe_customer_id=current_user.get("stripe_customer_id"),
350|        created_at=current_user["created_at"],
351|        updated_at=current_user["updated_at"]
352|    )
353|
354|@app.post("/api/analyze-google-doc")
355|async def analyze_google_doc(request: GoogleDocRequest, current_user: dict = Depends(get_current_user)):
356|    # Check user access
357|    if not check_user_access(current_user):
358|        if current_user["subscription_status"] == "trial":
359|            raise HTTPException(
360|                status_code=402, 
361|                detail="Your free trial has expired. Please upgrade to continue using the service."
362|            )
363|        else:
364|            raise HTTPException(
365|                status_code=402,
366|                detail="Please upgrade your subscription to access this feature."
367|            )
368|    
369|    # Extract document ID from URL
370|    doc_id = extract_google_doc_id(request.doc_url)
371|    if not doc_id:
372|        raise HTTPException(
373|            status_code=400, 
374|            detail="Invalid Google Docs URL. Please provide a valid Google Docs link."
375|        )
376|    
377|    # Fetch document content
378|    result = await fetch_google_doc_content(doc_id)
379|    
380|    if not result["success"]:
381|        if "not publicly accessible" in result.get("error", ""):
382|            raise HTTPException(
383|                status_code=400,
384|                detail="This Google Doc is not publicly accessible. Please make sure the document is shared with 'Anyone with the link can view' permissions."
385|            )
386|        else:
387|            raise HTTPException(
388|                status_code=400,
389|                detail=f"Failed to fetch Google Doc: {result.get('error', 'Unknown error')}"
390|            )
391|    
392|    return result
393|
394|# Stripe Routes
395|@app.get("/api/stripe/config")
396|async def get_stripe_config():
397|    return {"publishable_key": STRIPE_PUBLISHABLE_KEY}
398|
399|@app.post("/api/stripe/create-checkout-session")
400|async def create_checkout_session(
401|    request: StripeCheckoutRequest, 
402|    current_user: dict = Depends(get_current_user)
403|):
404|    try:
405|        # Get or create Stripe customer
406|        stripe_customer_id = current_user.get("stripe_customer_id")
407|        
408|        if not stripe_customer_id:
409|            # Create new Stripe customer
410|            customer = stripe.Customer.create(
411|                email=current_user["email"],
412|                metadata={"user_id": current_user["id"]}
413|            )
414|            stripe_customer_id = customer.id
415|            
416|            # Update user with Stripe customer ID
417|            await db.users.update_one(
418|                {"id": current_user["id"]},
419|                {"$set": {"stripe_customer_id": stripe_customer_id, "updated_at": datetime.utcnow()}}
420|            )
421|        
422|        # Create checkout session
423|        checkout_session = stripe.checkout.Session.create(
424|            customer=stripe_customer_id,
425|            payment_method_types=['card'],
426|            line_items=[{
427|                'price': request.price_id,
428|                'quantity': 1,
429|            }],
430|            mode='subscription',
431|            success_url=request.success_url or 'https://genuineaf.ai/success',
432|            cancel_url=request.cancel_url or 'https://genuineaf.ai/cancel',
433|            metadata={
434|                'user_id': current_user["id"],
435|                'price_id': request.price_id
436|            }
437|        )
438|        
439|        return {"checkout_url": checkout_session.url}
440|        
441|    except stripe.error.StripeError as e:
442|        logger.error(f"Stripe error: {str(e)}")
443|        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
444|    except Exception as e:
445|        logger.error(f"Checkout session creation error: {str(e)}")
446|        raise HTTPException(status_code=500, detail="Failed to create checkout session")
447|
448|@app.post("/api/stripe/webhook")
449|async def stripe_webhook(request: Request):
450|    payload = await request.body()
451|    sig_header = request.headers.get('stripe-signature')
452|    
453|    try:
454|        event = stripe.Webhook.construct_event(
455|            payload, sig_header, STRIPE_WEBHOOK_SECRET
456|        )
457|    except ValueError as e:
458|        logger.error(f"Invalid payload: {e}")
459|        raise HTTPException(status_code=400, detail="Invalid payload")
460|    except stripe.error.SignatureVerificationError as e:
461|        logger.error(f"Invalid signature: {e}")
462|        raise HTTPException(status_code=400, detail="Invalid signature")
463|    
464|    # Handle the event
465|    if event['type'] == 'checkout.session.completed':
466|        session = event['data']['object']
467|        user_id = session.get('metadata', {}).get('user_id')
468|        
469|        if user_id:
470|            # Update user subscription status
471|            subscription_status = "pro"  # Default to pro
472|            
473|            # Determine subscription type based on price_id or subscription details
474|            if session.get('subscription'):
475|                subscription = stripe.Subscription.retrieve(session['subscription'])
476|                price_id = subscription['items']['data'][0]['price']['id']
477|                
478|                # Map price IDs to subscription types
479|                if price_id == "price_1Rta8FGxbXNfm3xsX4SgFsYJ":  # Business plan
480|                    subscription_status = "business"
481|                elif price_id == "price_1Rta7fGxbXNfm3xszfM9Xanr":  # Pro plan
482|                    subscription_status = "pro"
483|            
484|            await db.users.update_one(
485|                {"id": user_id},
486|                {
487|                    "$set": {
488|                        "subscription_status": subscription_status,
489|                        "updated_at": datetime.utcnow()
490|                    },
491|                    "$unset": {"trial_expires": ""}
492|                }
493|            )
494|            
495|            # Get user for email
496|            user = await db.users.find_one({"id": user_id})
497|            if user:
498|                # Send confirmation email
499|                plan_name = "Business Plan" if subscription_status == "business" else "Pro Plan"
500|                confirmation_html = f"""
501|                <h2>Payment Successful - Welcome to {plan_name}!</h2>
502|                <p>Hi {user['email']},</p>
503|                <p>Thank you for upgrading to the <strong>{plan_name}</strong>!</p>
504|                <p>Your subscription is now active and you have unlimited access to all features:</p>
505|                <ul>
506|                    <li>Unlimited document analysis</li>
507|                    <li>Google Docs integration</li>
508|                    <li>Advanced AI pattern detection</li>
509|                    <li>Priority support</li>
510|                    {f'<li>Team collaboration features</li><li>API access</li>' if subscription_status == 'business' else ''}
511|                </ul>
512|                <p><a href="https://genuineaf.ai">Start analyzing your documents</a></p>
513|                <p>Best regards,<br>The AI Writing Detector Team</p>
514|                """
515|                
516|                await send_email(
517|                    user['email'], 
518|                    f"Welcome to {plan_name} - Payment Confirmed!", 
519|                    confirmation_html
520|                )
521|            
522|            logger.info(f"User {user_id} upgraded to {subscription_status}")
523|    
524|    elif event['type'] == 'customer.subscription.deleted':
525|        # Handle subscription cancellation
526|        subscription = event['data']['object']
527|        customer_id = subscription['customer']
528|        
529|        # Find user by Stripe customer ID
530|        user = await db.users.find_one({"stripe_customer_id": customer_id})
531|        if user:
532|            await db.users.update_one(
533|                {"id": user["id"]},
534|                {
535|                    "$set": {
536|                        "subscription_status": "cancelled",
537|                        "updated_at": datetime.utcnow()
538|                    }
539|                }
540|            )
541|            logger.info(f"User {user['id']} subscription cancelled")
542|    
543|    return {"status": "success"}
544|
545|@app.get("/api/stripe/subscription")
546|async def get_subscription_info(current_user: dict = Depends(get_current_user)):
547|    if current_user.get("stripe_customer_id"):
548|        try:
549|            # Get customer's subscriptions from Stripe
550|            subscriptions = stripe.Subscription.list(
551|                customer=current_user["stripe_customer_id"],
552|                status="active"
553|            )
554|            
555|            has_active = len(subscriptions.data) > 0
556|            return {"has_active_subscription": has_active}
557|            
558|        except stripe.error.StripeError as e:
559|            logger.error(f"Stripe error retrieving subscription: {e}")
560|            return {"has_active_subscription": False}
561|    
562|    return {"has_active_subscription": False}
563|
564|if __name__ == "__main__":
565|    import uvicorn
566|    uvicorn.run("server:app", host="0.0.0.0", port=8001, reload=True)

