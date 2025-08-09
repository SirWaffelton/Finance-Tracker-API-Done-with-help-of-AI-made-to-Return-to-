from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Config
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# App
app = FastAPI()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory DB
fake_users_db = {}
expenses_db = {}

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(BaseModel):
    email: str
    full_name: str
    hashed_password: str

class Expense(BaseModel):
    id: int
    description: str
    amount: float
    date: datetime

class ExpenseCreate(BaseModel):
    description: str
    amount: float
    date: datetime

class Token(BaseModel):
    access_token: str
    token_type: str

# Utils
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def authenticate_user(email: str, password: str):
    user = fake_users_db.get(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = fake_users_db.get(email)
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.post("/signup")
def signup(email: str, password: str, full_name: str):
    if email in fake_users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    fake_users_db[email] = User(
        email=email,
        full_name=full_name,
        hashed_password=get_password_hash(password)
    )
    expenses_db[email] = []
    return {"msg": "User created successfully"}

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/expenses", response_model=Expense)
def create_expense(expense: ExpenseCreate, current_user: User = Depends(get_current_user)):
    expense_id = len(expenses_db[current_user.email]) + 1
    new_expense = Expense(id=expense_id, **expense.dict())
    expenses_db[current_user.email].append(new_expense)
    return new_expense

@app.get("/expenses", response_model=List[Expense])
def list_expenses(current_user: User = Depends(get_current_user)):
    return expenses_db[current_user.email]

@app.delete("/expenses/{expense_id}")
def delete_expense(expense_id: int, current_user: User = Depends(get_current_user)):
    expenses = expenses_db[current_user.email]
    for i, exp in enumerate(expenses):
        if exp.id == expense_id:
            del expenses[i]
            return {"msg": "Expense deleted"}
    raise HTTPException(status_code=404, detail="Expense not found")

@app.get("/expenses/filter", response_model=List[Expense])
def filter_expenses(
    filter_by: Optional[str] = Query(None, regex="^(week|month|3months|custom)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(get_current_user)
):
    expenses = expenses_db[current_user.email]
    now = datetime.utcnow()

    if filter_by == "week":
        cutoff = now - timedelta(days=7)
        filtered = [e for e in expenses if e.date >= cutoff]

    elif filter_by == "month":
        cutoff = now - timedelta(days=30)
        filtered = [e for e in expenses if e.date >= cutoff]

    elif filter_by == "3months":
        cutoff = now - timedelta(days=90)
        filtered = [e for e in expenses if e.date >= cutoff]

    elif filter_by == "custom":
        if not start_date or not end_date:
            raise HTTPException(status_code=400, detail="start_date and end_date are required for custom filter")
        filtered = [e for e in expenses if start_date <= e.date <= end_date]

    else:
        filtered = expenses  # no filter, return all

    return filtered
