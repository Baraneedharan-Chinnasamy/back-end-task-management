from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.sql import or_
from models.models import User,Task, TaskStatus, Checklist, TaskReview, TaskChecklistLink,ReviewStatus,ApprovalWorkflow,ApprovalStatus,TaskType,ReviewStatus,ApprovalStatus
from schemas.schemas import UserCreate, UserLogin, ForgotPasswordRequest, ResetPasswordRequest,MasterCreate,CreateSubTaskRequest
from schemas.authy import hash_password, verify_password, create_access_token, decode_token,send_email
from database.database import get_db
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta
from jose import JWTError
import logging
import random


router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@router.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    new_user = User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password),
        designation=user.designation
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}


@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.username, "employee_id": user.employee_id})
    return {"access_token": token, "token_type": "bearer"}


@router.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    otp = str(random.randint(100000, 999999))
    payload = {"sub": user.email, "otp": otp}
    token = create_access_token(payload, expires_delta=timedelta(minutes=10))

    email_body = f"Hi {user.username},\n\nYour OTP for password reset is: {otp}\n\nThis OTP is valid for 10 minutes."
    send_email(user.email, "Your OTP for Password Reset", email_body)

    return {"message": "OTP has been sent to your email", "token": token}



@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    payload = decode_token(data.token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    email = payload.get("sub")
    token_otp = payload.get("otp")

    if email != data.email or token_otp != data.otp:
        raise HTTPException(status_code=400, detail="Invalid email or OTP")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = hash_password(data.new_password)
    db.commit()
    return {"message": "Password reset successful"}



# ✅ Utility to get current logged-in user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)): 
    try:
        payload = decode_token(token)
        user_id = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.employee_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token decode failed")


# ✅ Example API using current logged-in user
@router.get("/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    return {
        "employee_id": current_user.employee_id,
        "username": current_user.username,
        "email": current_user.email,
        "designation": current_user.designation
    }

@router.post("/MasterCreateTask/")
def create_task_master(data: MasterCreate, db: Session = Depends(get_db), employee_id: int = Depends(get_current_user)):
    try:
        logger.info("Starting task creation process...")

        new_task = Task(
            task_name=data.task_name,
            description=data.description,
            due_date=data.due_date,
            assigned_to=data.assigned_to,
            status=TaskStatus.To_Do,
            created_by=employee_id
        )
        db.add(new_task)
        db.flush()
        logger.info(f"Task created successfully: {new_task.task_id}")

        for name in data.checklist_names:
            checklist = Checklist(
                checklist_name=name,
                is_completed=False,
                is_delete=False
            )
            db.add(checklist)
            db.flush()
            logger.info(f"Checklist created successfully: {checklist.checklist_id}")

            task_checklist_link = TaskChecklistLink(
                parent_task_id=new_task.task_id,
                checklist_id=checklist.checklist_id,
                sub_task_id=None
            )
            db.add(task_checklist_link)
            db.flush()
            logger.info(f"Task-Checklist link created for task {new_task.task_id}")

        if data.review == True:
            review_task = Task(
                task_name=f"Review - {new_task.task_name}",
                description="Review task",
                status=TaskStatus.To_Do.name,
                assigned_to=employee_id,  
                created_by=employee_id,  
                due_date=data.due_date,
                task_type = TaskType.Review,
                review_status=ReviewStatus.Not_Approved.name)
            db.add(review_task)
            db.flush()
            logger.info(f"Review task created: {review_task.task_id}")

            task_review = TaskReview(
                review_task_id=review_task.task_id,
                original_task_id=new_task.task_id,
                reviewer_id=employee_id
                
            )
            db.add(task_review)
            db.flush()
            logger.info(f"Task review linked: {task_review.review_id}")
        
        db.commit()
        logger.info("Task creation process completed successfully.")
        return {"message": "Task created successfully"}
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while creating task: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
@router.post("/Add_Subtask")
def add_checklist_subtask(data: CreateSubTaskRequest, db: Session = Depends(get_db), employee_id: int = Depends(get_current_user)):
    try:
        parent_task_id = db.query(TaskChecklistLink.parent_task_id).filter(TaskChecklistLink.checklist_id == data.checklist_id).first()
        
        task = db.query(Task).filter(
            Task.task_id == parent_task_id[0],
            or_(Task.created_by == employee_id, Task.assigned_to == employee_id),
            Task.is_delete == False).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or creator is not you")
        
        logger.info("Starting task creation process...")

        new_task = Task(
            task_name=data.sub_task_name,
            description=data.description,
            due_date=data.due_date,
            assigned_to=data.assigned_to,
            status=TaskStatus.To_Do,
            created_by=employee_id
        )
        db.add(new_task)
        db.flush()
        logger.info(f"Task created successfully: {new_task.task_id}")

        for name in data.checklist_names:
            checklist = Checklist(
                checklist_name=name,
                is_completed=False,
                is_delete=False
            )
            db.add(checklist)
            db.flush()
            logger.info(f"Checklist created successfully: {checklist.checklist_id}")

            task_checklist_link = TaskChecklistLink(
                parent_task_id=new_task.task_id,
                checklist_id=checklist.checklist_id,
                sub_task_id=None
            )
            db.add(task_checklist_link)
            db.flush()
            logger.info(f"Task-Checklist link created for task {new_task.task_id}")

        if data.review == True:
            review_task = Task(
                task_name=f"Review - {new_task.task_name}",
                description="Review task",
                status=TaskStatus.To_Do.name,
                assigned_to=employee_id,  
                created_by=employee_id,  
                due_date=data.due_date,
                task_type = TaskType.Review,
                review_status=ReviewStatus.Not_Approved.name)
            db.add(review_task)
            db.flush()
            logger.info(f"Review task created: {review_task.task_id}")

            task_review = TaskReview(
                review_task_id=review_task.task_id,
                original_task_id=new_task.task_id,
                reviewer_id=employee_id
                
            )
            db.add(task_review)
            db.flush()
            logger.info(f"Task review linked: {task_review.review_id}")
        
        db.commit()
        logger.info("Task creation process completed successfully.")
        return {"message": "Task created successfully"}
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while creating task: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

