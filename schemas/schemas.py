from pydantic import BaseModel, EmailStr
from typing import Optional,List
from datetime import date

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    designation: str 

class UserLogin(BaseModel):
    username: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: str
    otp: str
    new_password: str
    token: str


class MasterCreate(BaseModel):
    task_name: str
    description: Optional[str] = None
    due_date: date
    assigned_to: int
    checklist_names: List[str]
    review: bool

class CreateSubTaskRequest(BaseModel):
    checklist_id: int
    sub_task_name: str
    description: Optional[str] = None
    assigned_to: int
    due_date:date
    checklist_name :List[str]
    review: bool
