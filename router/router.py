from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from sqlalchemy.sql import or_, update
from models.models import User,Task, TaskStatus, Checklist, TaskChecklistLink,TaskType,ChatRoom,ChatMessage,TaskStatusLog
from schemas.schemas import UserCreate, UserLogin, ForgotPasswordRequest, ResetPasswordRequest,MasterCreate,CreateSubTaskRequest,CreateChecklistRequest,UpdateStatus,MarkComplete,UpdateTaskRequest,SendForReview,UpdateChecklistRequest,DeleteItemsRequest,ChatMessageCreate,ChatManager,EmployeeIDList,TaskIDPayload,ChecklistIDPayload
from schemas.authy import hash_password, verify_password, create_access_token, decode_token,send_email,propagate_incomplete_upwards,update_parent_task_status,Mark_complete_help,propagate_incomplete_upwards_from_task,upload_output_to_all_reviews,log_status_change,get_related_tasks_checklists_logic
from database.database import get_db
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta, datetime
from jose import JWTError
import logging
import random
from fastapi.responses import JSONResponse
from typing import Dict, List, Optional
from fastapi import WebSocket, WebSocketDisconnect
from fastapi import Request


router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

blacklisted_tokens = set()
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

def verify_token(token: str = Depends(oauth2_scheme)):
    if token in blacklisted_tokens:
        raise HTTPException(status_code=401, detail="Token has been invalidated")
    
@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user.username, "employee_id": user.employee_id})

    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=60 * 60,  # 1 hour
        expires=60 * 60,
        secure=False  # Set to True in production (with HTTPS)
    )
    return response


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

def get_current_back(token: str = Depends(oauth2_scheme)):
    # Implement your token verification logic here
    if not token:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return {"token": token}

def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
):
    token = request.cookies.get("access_token")  # Make sure this matches the actual cookie name!
    if token is None:
        raise HTTPException(status_code=401, detail="Not authenticated (token missing)")

    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    employee_id = payload.get("employee_id")
    if employee_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.query(User).filter(User.employee_id == employee_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user
@router.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    return {"token": token}
@router.get("/dashboard")
def dashboard(current_user: User = Depends(get_current_user)):
    return {
        "message": "Welcome to your dashboard!",
        "employee_id": current_user.employee_id,
        "username": current_user.username,
        "email": current_user.email
    }

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(
        key="access_token",
        path="/",         
        httponly=True,    
        samesite="lax"    
    )
    return {"message": "Logged out"}

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
def create_task_master(data: MasterCreate, db: Session = Depends(get_db), Current_user: int = Depends(get_current_user)):
    try:
        logger.info("Starting task creation process...")

        new_task = Task(
            task_name=data.task_name,
            description=data.description,
            due_date=data.due_date,
            assigned_to=data.assigned_to,
            status=TaskStatus.To_Do,
            created_by=Current_user.employee_id,
            is_review_required =data.is_review_required
        )
        db.add(new_task)
        db.flush()
        logger.info(f"Task created successfully: {new_task.task_id}")
        new_chat_room = ChatRoom(task_id=new_task.task_id)
        db.add(new_chat_room)
        db.flush()
        log_status_change(db, new_task.task_id, None, "To_Do")

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

        if data.is_review_required == True:
            review_task = Task(
                task_name=f"Review - {new_task.task_name}",
                description="Review task",
                status=TaskStatus.To_Do.name,
                assigned_to=Current_user.employee_id,  
                created_by=Current_user.employee_id,  
                due_date=data.due_date,
                task_type = TaskType.Review,
                parent_task_id = new_task.task_id
                )
            db.add(review_task)
            db.flush()
            logger.info(f"Review task created: {review_task.task_id}")
        
        db.commit()
        logger.info("Task creation process completed successfully.")
        return {"message": "Task created successfully"}
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while creating task: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
@router.post("/Add_Subtask")
def add_checklist_subtask(data: CreateSubTaskRequest, db: Session = Depends(get_db), Current_user: int = Depends(get_current_user)):
    try:
        parent_task_id = db.query(TaskChecklistLink.parent_task_id).filter(
            TaskChecklistLink.checklist_id == data.checklist_id).first()

        task = db.query(Task).filter(
            Task.task_id == parent_task_id[0],
            or_(Task.created_by == Current_user.employee_id, Task.assigned_to == Current_user.employee_id),
            Task.is_delete == False
        ).first()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found or creator is not you")
        
        if task.task_type == TaskType.Review:
            raise HTTPException(status_code=400, detail="Cannot add subtask to a review task")

        logger.info("Starting task creation process...")

        new_task = Task(
            task_name=data.sub_task_name,
            description=data.description,
            due_date=data.due_date,
            assigned_to=data.assigned_to,
            status=TaskStatus.To_Do,
            created_by=Current_user.employee_id,
            is_review_required=data.is_review_required
        )
        db.add(new_task)
        db.flush()

        logger.info(f"Task created successfully: {new_task.task_id}")
        new_chat_room = ChatRoom(task_id=new_task.task_id)
        db.add(new_chat_room)
        db.flush()
        log_status_change(db, new_task.task_id, None, "To_Do")

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

        task_checklist_link_sub = TaskChecklistLink(
            parent_task_id=None,
            checklist_id=data.checklist_id,
            sub_task_id=new_task.task_id
        )
        db.add(task_checklist_link_sub)
        db.flush()

        if data.is_review_required:
            review_task = Task(
                task_name=f"Review - {new_task.task_name}",
                description="Review task",
                status=TaskStatus.To_Do.name,
                assigned_to=Current_user.employee_id,
                created_by=Current_user.employee_id,
                due_date=data.due_date,
                task_type=TaskType.Review,
                parent_task_id = new_task.task_id
            )
            db.add(review_task)
            db.flush()
            logger.info(f"Review task created: {review_task.task_id}")

        db.commit()
        logger.info("Task creation process completed successfully.")
        return {"message": "Task created successfully"}

    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error occurred while creating task: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
    
@router.post("/add_checklist")
def add_checklist(data: CreateChecklistRequest, db: Session = Depends(get_db),Current_user: int = Depends(get_current_user)):
    try:
        check_type = db.query(Task).filter(Task.task_id == data.task_id,
                                           Task.is_delete == False).first()
        if not check_type:
            raise HTTPException(status_code=404, detail="Task not found")
        
        if check_type.task_type == TaskType.Review:
            print("Hi")
            checklist = Checklist(
            checklist_name=data.checklist_name,
            is_completed=False,
            is_delete=False)
            db.add(checklist)
            db.flush()
            db.refresh(checklist)

            task_checklist_link = TaskChecklistLink(
                parent_task_id=check_type.parent_task_id,
                checklist_id=checklist.checklist_id,
                sub_task_id=None   )
            db.add(task_checklist_link)
            db.flush()

            logger.info(f"Task-Checklist link created for task {check_type.task_id}")

            task = db.query(Task).filter(Task.task_id == check_type.parent_task_id,Task.is_delete == False).first()
            if not task:
                raise HTTPException(status_code=404, detail="Task not found")
            
            if task.task_type == TaskType.Normal:
                print("Hi")
                log_status_change(db, task.task_id, task.status, "In_Process")
                db.flush()
                task.status = TaskStatus.In_Process
                db.flush()
            if task.task_type == TaskType.Review:
                log_status_change(db, task.task_id, task.status,"To_Do")
                db.flush()
                task.status = TaskStatus.To_Do
                db.flush()

        if check_type.task_type == TaskType.Normal:
            task = db.query(Task).filter(
            Task.task_id == data.task_id,
            or_(Task.created_by == Current_user.employee_id, Task.assigned_to == Current_user.employee_id),
            Task.is_delete == False).first()
            if not task:
                raise HTTPException(status_code=404, detail="Creator?Assined To is not you")
            
            checklist = Checklist(
                checklist_name=data.checklist_name,
                is_completed=False,
                is_delete=False
            )
            db.add(checklist)
            db.flush()
            db.refresh(checklist)
            task_checklist_link = TaskChecklistLink(
                parent_task_id=data.task_id,
                checklist_id=checklist.checklist_id,
                sub_task_id=None
            )
            db.add(task_checklist_link)
            db.flush()
            logger.info(f"Task-Checklist link created for task {check_type.task_id}")
            if task.task_type == TaskType.Normal:
                if task.status == TaskStatus.In_Review or task.status == TaskStatus.Completed:
                    log_status_change(db, task.task_id, task.status.name, "In_Process")
                    db.flush()
                    task.status = TaskStatus.In_Process
                    db.flush()

        db.commit()
        return {"message": "Checklist created successfully"}

    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while creating task: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post("/update_Checklist_Status/")
def update_Status(data: UpdateStatus, db: Session = Depends(get_db),Current_user: int = Depends(get_current_user)):
    try:
        parent_task_id = db.query(TaskChecklistLink.parent_task_id).filter(TaskChecklistLink.checklist_id == data.checklist_id).first()
        if not parent_task_id:
            raise HTTPException(status_code=404, detail="Parent task not found")
        
    
        task = db.query(Task).filter(Task.task_id == parent_task_id[0],
            or_(Task.created_by == Current_user.employee_id, Task.assigned_to == Current_user.employee_id),
            Task.is_delete == False
        ).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or creator is not you")
        
        if task.task_type == TaskType.Normal:
            if data.is_completed == True:
                # Check if the checklist exists
                checklist = db.query(Checklist).filter(
                    Checklist.checklist_id == data.checklist_id,
                    Checklist.is_delete == False
                ).first()
                if not checklist:
                    raise HTTPException(status_code=404, detail="Checklist not found")
                # Check if the checklist has any sub-tasks
                subtask_exists = db.query(TaskChecklistLink).filter(
                    TaskChecklistLink.checklist_id == data.checklist_id,
                    TaskChecklistLink.sub_task_id.isnot(None)
                ).first()
                if subtask_exists:
                    return JSONResponse(
                            status_code=status.HTTP_404_NOT_FOUND,
                            content={"detail": "Checklist has sub-tasks and cannot be marked as complete"}
                        )
                # Mark checklist as complete
                checklist.is_completed = True
                db.flush()
                parent_task_links = db.query(TaskChecklistLink).filter(
                TaskChecklistLink.checklist_id == data.checklist_id,
                TaskChecklistLink.parent_task_id.isnot(None)).all()
                for link in parent_task_links:
                    update_parent_task_status(link.parent_task_id,db)
                db.commit()
                return {"message": "Checklist marked as complete successfully"}
            
            if data.is_completed == False:
                checklist = db.query(Checklist).filter(
                    Checklist.checklist_id == data.checklist_id,
                    Checklist.is_delete == False
                ).first()

                if not checklist:
                    raise HTTPException(status_code=404, detail="Checklist not found")
                
                # Check if the checklist has any sub-tasks
                subtask_exists = db.query(TaskChecklistLink).filter(
                    TaskChecklistLink.checklist_id == data.checklist_id,
                    TaskChecklistLink.sub_task_id.isnot(None)
                ).first()
                if subtask_exists:
                    return JSONResponse(
                            status_code=status.HTTP_404_NOT_FOUND,
                            content={"detail": "Checklist has sub-tasks and cannot be marked as complete"}
                        )

                checklist.is_completed = False
                db.flush()
                propagate_incomplete_upwards(data.checklist_id,db)
                db.commit()
                return {"message": "Checklist marked as incomplete and propagated up"}
        
        if task.task_type == TaskType.Review:
            if data.is_completed == True:
                
                # Check if the checklist exists
                checklist = db.query(Checklist).filter(
                    Checklist.checklist_id == data.checklist_id,
                    Checklist.is_delete == False
                ).first()
                if not checklist:
                    raise HTTPException(status_code=404, detail="Checklist not found")
                # Check if the checklist has any sub-tasks
                subtask_exists = db.query(TaskChecklistLink).filter(
                    TaskChecklistLink.checklist_id == data.checklist_id,
                    TaskChecklistLink.sub_task_id.isnot(None)
                ).first()
                if subtask_exists:
                    return JSONResponse(
                            status_code=status.HTTP_404_NOT_FOUND,
                            content={"detail": "Checklist has sub-tasks and cannot be marked as complete"}
                        )
                # Mark checklist as complete
                checklist.is_completed = True
                db.flush()
                
                parent_task_links = db.query(TaskChecklistLink).filter(
                TaskChecklistLink.checklist_id == data.checklist_id,
                TaskChecklistLink.parent_task_id.isnot(None)).all()
                parent_task_ids = set()
                for link in parent_task_links:
                    parent_task_ids.add(link.parent_task_id)
                parent_task_ids = list(parent_task_ids)
                if len(parent_task_ids) == 1:
                    task_parent = db.query(Task).filter(Task.task_id == parent_task_ids[0],Task.is_delete == False).first()
                    if not task:
                        raise HTTPException(status_code=404, detail=" Parent Task not found")
                    if task_parent.task_type == TaskType.Review:
                        
                        Checklist_id  = db.query(TaskChecklistLink).filter(TaskChecklistLink.parent_task_id == parent_task_ids[0]).all()
                        checklist_ids = [link.checklist_id for link in Checklist_id]
                        checklists = db.query(Checklist).filter(
                            Checklist.checklist_id.in_(checklist_ids),
                            Checklist.is_delete == False
                        ).all()

                        # Proceed only if all checklists are completed
                        if all(checklist.is_completed for checklist in checklists):
                            print("hi")
                            task = db.query(Task).filter(Task.parent_task_id == parent_task_ids[0],Task.is_delete == False).first()
                            log_status_change(db, task.task_id, task.status.name, "To_Do")
                            task.status = TaskStatus.To_Do
                            db.flush()
                            task.output = task_parent.output
                            db.flush()
                
            
            if data.is_completed == False:
                # Mark checklist as not completed
                checklist = db.query(Checklist).filter(
                    Checklist.checklist_id == data.checklist_id,
                    Checklist.is_delete == False
                ).first()
                if not checklist:
                    raise HTTPException(status_code=404, detail="Checklist not found")
                
                checklist.is_completed = False
                db.flush()

                # Get parent task(s) of the checklist
                parent_task_links = db.query(TaskChecklistLink).filter(
                    TaskChecklistLink.checklist_id == data.checklist_id,
                    TaskChecklistLink.parent_task_id.isnot(None)
                ).all()
                parent_task_ids = [link.parent_task_id for link in parent_task_links]

                if len(parent_task_ids) == 1:
                    task_parent = db.query(Task).filter(
                        Task.task_id == parent_task_ids[0],
                        Task.is_delete == False
                    ).first()
                    if not task_parent:
                        raise HTTPException(status_code=404, detail="Parent Task not found")

                    # If it’s a Review type, and checklist becomes incomplete, reset the child task
                    if task_parent.task_type == TaskType.Review:
                        task = db.query(Task).filter(
                            Task.parent_task_id == parent_task_ids[0],
                            Task.is_delete == False
                        ).first()
                        if task:
                            log_status_change(db, task.task_id, task.status, "Completed")
                            task.status = TaskStatus.Completed
                            db.flush()
                            task.output = None 
                            db.flush()    
        db.commit()
        return {"message": "Checklist Status Updated successfully"}
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while creating task: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
@router.post("/Mark_Complete/")
def Mark_Complete(data: MarkComplete, db: Session = Depends(get_db),Current_user: int = Depends(get_current_user)):
    try:
        task = db.query(Task).filter(Task.task_id == data.task_id,
                                     or_(Task.created_by == Current_user.employee_id, Task.assigned_to == Current_user.employee_id),
                                    Task.is_delete == False,
                                    Task.status == TaskStatus.In_Review).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or creator is not you")
        
        log_status_change(db, task.task_id, task.status,"Completed")
        task.status = TaskStatus.Completed
        db.flush()
        Mark_complete_help(task.task_id,db)
        db.commit()
        return {"message": "Task marked as complete successfully"}
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while creating task: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    

@router.post("/update_task_Normal/{task_id}")
def update_task(task_id: int, task_data: UpdateTaskRequest, db: Session = Depends(get_db), Current_user: int = Depends(get_current_user)):
    try:
        task = db.query(Task).filter(
            Task.task_id == task_id,
            or_(Task.created_by == Current_user.employee_id, Task.assigned_to == Current_user.employee_id),
            Task.is_delete == False
        ).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or creator is not you")
        
        update_fields = {}
        if task_data.assigned_to is not None:
            task = db.query(Task).filter(
            Task.task_id == task_id,
            Task.created_by == Current_user.employee_id,
            Task.is_delete == False).first()
            if not task:
                raise HTTPException(status_code=404, detail="creator is not you")
            task.assigned_to = task_data.assigned_to
            update_fields['assigned_to'] = task_data.assigned_to
        if task_data.task_name is not None:
            task.task_name = task_data.task_name
            update_fields['task_name'] = task_data.task_name
        if task_data.description is not None:
            task.description = task_data.description
            update_fields['description'] = task_data.description
        if task_data.due_date is not None:
            task = db.query(Task).filter(
            Task.task_id == task_id,
            Task.created_by == Current_user.employee_id,
            Task.is_delete == False).first()
            if not task:
                raise HTTPException(status_code=404, detail="creator is not you")
            task.due_date = task_data.due_date
            update_fields['due_date'] = task_data.due_date
        if task_data.output is not None:
            task.output = task_data.output
            update_fields['output'] = task_data.output
            if task.is_review_required == True:
                task_review = db.query(Task).filter(Task.task_type == TaskType.Review,Task.parent_task_id == task.task_id,Task.is_delete == False).first()
                if not task_review:
                    raise HTTPException(status_code=404, detail="Review task not found")
                task_review.output = task_data.output
                db.flush()         
        if task_data.is_review_required is not None:
            if task_data.is_review_required == True:
                task = db.query(Task).filter(
                Task.task_id == task_id,
                Task.created_by == Current_user.employee_id,
                Task.is_delete == False).first()
                if not task:
                    raise HTTPException(status_code=404, detail="creator is not you")
                check = db.query(Task).filter(Task.parent_task_id ==task_id,Task.is_delete == False).first()
                if check:
                    logger.info(f"Review Task Already Linked: {Task.task_id}")
                if not check:
                    task.is_review_required = True
                    db.flush()
                    review_task = Task(
                    task_name=f"Review - {task.task_name}",
                    description="Review task",
                    status=TaskStatus.To_Do.name,
                    assigned_to=task.created_by,  
                    created_by=Current_user.employee_id,  
                    due_date=task.due_date,
                    task_type = TaskType.Review,
                    parent_task_id = task.task_id)
                    db.add(review_task)
                    db.flush()
                    logger.info(f"Review task created: {review_task.task_id}")
            elif task_data.is_review_required == False:
                task = db.query(Task).filter(
                Task.task_id == task_id,
                Task.created_by == Current_user.employee_id,
                Task.is_delete == False).first()
                if not task:
                    raise HTTPException(status_code=404, detail="creator is not you")
                task.is_review_required = False
                db.flush()
                task_review = db.query(Task).filter(Task.parent_task_id == task_id,Task.is_delete == False).first()
                if task_review:
                    task_review_2 = db.query(Task).filter(Task.parent_task_id == task_review.task_id,Task.is_delete == False).first()
                    if task_review_2:
                        return JSONResponse(
                            status_code=status.HTTP_404_NOT_FOUND,
                            content={"detail": "There are more than one Review tasks linked to this task"}
                        )
                    else:
                        task_review.is_delete = True
                        db.flush()
        if task_data.is_reviewed is not None:
            if task_data.is_reviewed == True:
                task.is_reviewed = True
                db.flush()
                task.status = TaskStatus.Completed
                db.flush()
            if task_data.is_reviewed == False:
                task.is_reviewed = False
                db.flush()
                task.status = TaskStatus.To_Do
                db.flush()
        
        
        db.commit()
        return {"message": "Task updated successfully", "updated_fields": update_fields}
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while updating task: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
@router.post("/Send_For_Review/")
def send_for_review(data: SendForReview, db: Session = Depends(get_db),Current_user: int = Depends(get_current_user)):
    try:
        task = db.query(Task).filter(Task.task_id == data.task_id,Task.task_type == TaskType.Review,
                                     or_(Task.created_by == Current_user.employee_id, Task.assigned_to == Current_user.employee_id),
                                    Task.is_delete == False).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or creator is not you")
        
        if task:
            review_task = Task(
                    task_name=task.task_name,
                    description="Review task",
                    status=TaskStatus.To_Do.name,
                    assigned_to=data.assigned_to,  
                    created_by=Current_user.employee_id,  
                    due_date=task.due_date,
                    task_type = TaskType.Review,
                    parent_task_id = task.task_id,
                    output = task.output)
        db.add(review_task)
        db.commit()
        return {"message": "Review Task Created successfully"}
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while Sending for review: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")
                    
@router.post("/update-checklist")
def update_checklist(data: UpdateChecklistRequest, db: Session = Depends(get_db),current_user: str = Depends(get_current_user)):
    try:
        checklist = db.query(Checklist).filter(Checklist.checklist_id == data.checklist_id, Checklist.is_delete == False).first()
        if not checklist:
            raise HTTPException(status_code=404, detail="Checklist not found")
        
        checklist.checklist_name = data.checklist_name
        
        db.commit()
        
        return {"message": "Checklist updated successfully", "updated_checklist_name": data.checklist_name}
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while Updating Checklist: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post("/delete-related-items/")
def delete_related_items(
    delete_request: DeleteItemsRequest, db: Session = Depends(get_db), Current_user: int = Depends(get_current_user)
):
    # Validate the request
    task_id = delete_request.task_id
    checklist_id = delete_request.checklist_id

    # employee id and created by id should be same
    if task_id:
        task = db.query(Task).filter(Task.task_id == task_id, Task.created_by == Current_user.employee_id).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or employee is not the creator of the task.")
    elif checklist_id:
        parent_task = db.query(TaskChecklistLink).filter(
            TaskChecklistLink.checklist_id == checklist_id,
            TaskChecklistLink.parent_task_id.isnot(None)
        ).first()
        task = db.query(Task).filter(Task.task_id == parent_task, Task.created_by == Current_user.employee_id).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or employee is not the creator of the task.")


    # Get the related tasks and checklists
    result = get_related_tasks_checklists_logic(db, task_id, checklist_id)
    tasks_to_delete = result.get("tasks", [])
    checklists_to_delete = result.get("checklists", [])

    if not tasks_to_delete and not checklists_to_delete:
        raise HTTPException(status_code=404, detail="No related tasks or checklists found")
    
    def get_all_review_tasks(db: Session, base_task_ids: list[int]) -> set[int]:
        all_task_ids = set(base_task_ids)
        queue = list(base_task_ids)

        while queue:
            current_id = queue.pop(0)
            child_tasks = db.query(Task).filter(
                Task.parent_task_id == current_id,
                Task.is_delete == False
            ).all()

            for task in child_tasks:
                if task.task_id not in all_task_ids:
                    all_task_ids.add(task.task_id)
                    queue.append(task.task_id)

        return all_task_ids
    
    tasks_to_delete = get_all_review_tasks(db, tasks_to_delete)


    # Mark tasks as deleted
    if tasks_to_delete:
        db.execute(
            update(Task)
            .where(Task.task_id.in_(tasks_to_delete))
            .values(is_delete=True)
        )

    # Mark checklists as deleted
    if checklists_to_delete:
        db.execute(
            update(Checklist)
            .where(Checklist.checklist_id.in_(checklists_to_delete))
            .values(is_delete=True)
        )

    db.commit()  # Commit the transaction

    return {"message": "Related tasks and checklists marked as deleted", "tasks": tasks_to_delete, "checklists": checklists_to_delete}


chat_manager = ChatManager()

@router.websocket("/ws/chat/{chat_room_id}")
async def chat_websocket(
    websocket: WebSocket,
    chat_room_id: int,
    user_id: int,  # From query params: ?user_id=5
    db: Session = Depends(get_db)
):
    websocket.scope["user_id"] = user_id  # Save for filtering
    await chat_manager.connect(websocket, chat_room_id)

    try:
        while True:
            data = await websocket.receive_json()

            message_text = data["message"]
            sender_id = data["sender_id"]
            visible_to = data.get("visible_to")  # Optional

            # Save message to DB
            chat_message = ChatMessage(
                chat_room_id=chat_room_id,
                sender_id=sender_id,
                message=message_text,
                visible_to=visible_to
            )
            db.add(chat_message)
            db.commit()
            db.refresh(chat_message)

            message_payload = {
                "sender_id": sender_id,
                "message": message_text,
                "visible_to": visible_to,
                "timestamp": str(chat_message.timestamp)
            }

            # Broadcast based on visibility
            if not visible_to:  # None or empty list means broadcast to all
                await chat_manager.broadcast(chat_room_id, message_payload)
            else:
                await chat_manager.broadcast_to_users(chat_room_id, message_payload, visible_to)

    except WebSocketDisconnect:
        chat_manager.disconnect(websocket, chat_room_id)

@router.get("/chat/{chat_room_id}/history")
def get_chat_history(
    chat_room_id: int,
    user_id: int,
    limit: int = 20,
    before_timestamp: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ChatMessage).filter(ChatMessage.chat_room_id == chat_room_id)

    if before_timestamp:
        query = query.filter(ChatMessage.timestamp < before_timestamp)

    messages = query.order_by(ChatMessage.timestamp.desc()).limit(limit).all()
    messages.reverse()  # To return in ascending order

    visible_messages = []
    for msg in messages:
        if not msg.visible_to or user_id in msg.visible_to:
            visible_messages.append({
                "sender_id": msg.sender_id,
                "message": msg.message,
                "timestamp": str(msg.timestamp)
            })

    return visible_messages


@router.get("/task/{task_id}/status-history")
def get_status_history(task_id: int, db: Session = Depends(get_db)):
    logs = (
        db.query(TaskStatusLog)
        .filter(TaskStatusLog.task_id == task_id)
        .order_by(TaskStatusLog.changed_at)
        .all()
    )

    if not logs:
        return {"message": "No logs found for this task."}

    history = []

    # Add the first log — task created with initial status
    history.append({
        "old_status": None,
        "new_status": logs[0].new_status,
        "duration": None,
        "changed_at": str(logs[0].changed_at)
    })

    for i in range(1, len(logs)):
        duration = logs[i].changed_at - logs[i - 1].changed_at
        history.append({
            "old_status": logs[i - 1].new_status,
            "new_status": logs[i].new_status,
            "duration": str(duration),
            "changed_at": str(logs[i].changed_at)
        })

    return history

@router.post("/tasks/by-employees")
def get_tasks_by_employees(
    payload: EmployeeIDList,
    db: Session = Depends(get_db)
):
    tasks = db.query(Task).filter(Task.assigned_to.in_(payload.employee_ids),Task.is_delete == False).all()

    result = []
    for task in tasks:
        result.append({
            "task_id": task.task_id,
            "task_name": task.task_name,
            "description": task.description,
            "due_date": task.due_date,
            "assigned_to": task.assigned_to,
            "created_by": task.created_by,
            "status": task.status,
            "output": task.output,
            "created_at": task.created_at,
            "updated_at": task.updated_at,
            "task_type": task.task_type,
            "is_review_required": task.is_review_required,
            "is_reviewed": task.is_reviewed
        })

    return result

@router.post("/task/checklists")
def get_checklists_by_task(payload: TaskIDPayload, db: Session = Depends(get_db)):
    links = db.query(TaskChecklistLink).filter(TaskChecklistLink.task_id == payload.task_id).all()

    checklist_data = []
    for link in links:
        checklist = link.checklist
        checklist_data.append({
            "checklist_id": checklist.checklist_id,
            "checklist_name": checklist.name,
            "is_completed": checklist.is_completed
        })

    return checklist_data

@router.post("/checklist/subtasks")
def get_subtasks_by_checklist(payload: ChecklistIDPayload, db: Session = Depends(get_db)):
    links = db.query(TaskChecklistLink).filter(TaskChecklistLink.checklist_id == payload.checklist_id).all()

    subtasks = []
    for link in links:
        task = link.task
        subtasks.append({
            "task_id": task.task_id,
            "task_name": task.task_name,
            "description": task.description,
            "status": task.status,
            "assigned_to": task.assigned_to,
            "due_date": task.due_date,
            "created_by": task.created_by,
            "created_at": task.created_at,
            "updated_at": task.updated_at,
            "task_type": task.task_type,
            "is_review_required": task.is_review_required,
            "output": task.output
        })

    return subtasks

@router.post("/get-Employee-Name")
def get_employee_name(db: Session = Depends(get_db), Current_user: int = Depends(get_current_user)):
    try:
        employee = db.query(User).all()
        if not employee:
            raise HTTPException(status_code=404, detail="Employee not found")
        employee_data = [{"employee_id": emp.employee_id, "Name": emp.username} for emp in employee]
        return {"employees": employee_data}
    
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error occurred while fetching employee list: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
    