from passlib.context import CryptContext
from models.models import User,Task, TaskStatus, Checklist, TaskChecklistLink,TaskType,TaskStatusLog
from schemas.schemas import UserCreate, UserLogin, ForgotPasswordRequest, ResetPasswordRequest,MasterCreate,CreateSubTaskRequest,CreateChecklistRequest
from jose import jwt, JWTError
from datetime import datetime, timedelta
from enum import Enum
from fastapi import Depends
from sqlalchemy import select
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
import logging

load_dotenv()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config
SECRET_KEY = "your-secret-key"  # Replace with env variable in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def send_email(to_email: str, subject: str, body: str):
    

    if not EMAIL_USER or not EMAIL_PASS:
        print("❌ Email credentials not loaded. Check your .env file.")
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
            print("✅ Email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def log_status_change(db, task_id, old_status, new_status):
    if old_status == new_status:
        return
    log = TaskStatusLog(
        task_id=task_id,
        old_status=old_status.name if isinstance(old_status, Enum) else old_status,
        new_status=new_status.name if isinstance(new_status, Enum) else new_status,
    )
    db.add(log)
    db.flush()

def update_checklist_completion_status(checklist_id, db):
    print(f"Checking completion status of checklist: {checklist_id}")
    subtask_ids = db.query(TaskChecklistLink.sub_task_id).filter(
        TaskChecklistLink.checklist_id == checklist_id,
        TaskChecklistLink.sub_task_id.isnot(None)
    ).all()

    subtask_ids = [st_id[0] for st_id in subtask_ids if st_id[0] is not None]
    if not subtask_ids:
        return

    subtask_statuses = db.query(Task.status).filter(
        Task.task_id.in_(subtask_ids),
        Task.is_delete == False
    ).all()

    subtask_statuses = [status[0] for status in subtask_statuses]

    if all(status == "Completed" for status in subtask_statuses):
        checklist = db.query(Checklist).filter(Checklist.checklist_id == checklist_id).first()
        if checklist:
            checklist.is_completed = True
            db.flush()


def update_parent_task_status(task_id, db):
    print(f"Checking parent task status: {task_id}")
    if not task_id:
        return

    task_checklists = db.query(Checklist).join(
        TaskChecklistLink, Checklist.checklist_id == TaskChecklistLink.checklist_id
    ).filter(
        TaskChecklistLink.parent_task_id == task_id,
        Checklist.is_delete == False
    ).all()

    task = db.query(Task).filter(Task.task_id == task_id).first()

    if not task:
        return

    if all(cl.is_completed for cl in task_checklists):
        new_status = "In_Review" if task.is_review_required else "Completed"
        if task.status != new_status:
            old_status = task.status
            print(f"Marking task {task_id} as {new_status}")
            task.status = new_status
            log_status_change(db, task.task_id, old_status, task.status)
            db.flush()

        parent_checklists = db.query(TaskChecklistLink.checklist_id).filter(
            TaskChecklistLink.sub_task_id == task_id
        ).all()

        for parent_checklist in parent_checklists:
            update_checklist_for_subtask_completion(parent_checklist[0], db)
    else:
        if task.status != "In_Process":
            old_status = task.status
            print(f"Marking task {task_id} as In_Process")
            task.status = "In_Process"
            log_status_change(db, task.task_id, old_status, task.status)
            db.flush()


def update_checklist_for_subtask_completion(checklist_id, db):
    print(f"Checking if all subtasks of checklist {checklist_id} are completed")

    subtask_ids = db.query(TaskChecklistLink.sub_task_id).filter(
        TaskChecklistLink.checklist_id == checklist_id,
        TaskChecklistLink.sub_task_id.isnot(None)
    ).all()
    subtask_ids = [st_id[0] for st_id in subtask_ids if st_id[0] is not None]
    if not subtask_ids:
        return

    subtask_statuses = db.query(Task.status).filter(
        Task.task_id.in_(subtask_ids),
        Task.is_delete == False
    ).all()

    all_completed = all(str(status[0]) == "Completed" for status in subtask_statuses)

    if subtask_statuses and all_completed:
        checklist = db.query(Checklist).filter(
            Checklist.checklist_id == checklist_id
        ).first()
        if checklist and not checklist.is_completed:
            print(f"Marking checklist {checklist_id} as completed")
            checklist.is_completed = True
            db.flush()

            parent_tasks = db.query(TaskChecklistLink.parent_task_id).filter(
                TaskChecklistLink.checklist_id == checklist_id,
                TaskChecklistLink.parent_task_id.isnot(None)
            ).all()

            for parent in parent_tasks:
                update_parent_task_status(parent[0], db)


def propagate_incomplete_upwards(checklist_id, db, visited_checklists=set()):
    if checklist_id in visited_checklists:
        return
    visited_checklists.add(checklist_id)

    print(f"🔁 Propagating incompletion from checklist {checklist_id}")

    checklist = db.query(Checklist).filter(
        Checklist.checklist_id == checklist_id,
        Checklist.is_delete == False
    ).first()

    if checklist and checklist.is_completed:
        print(f"❌ Marking checklist {checklist_id} as incomplete")
        checklist.is_completed = False
        db.flush()

    parent_tasks = db.query(TaskChecklistLink.parent_task_id).filter(
        TaskChecklistLink.checklist_id == checklist_id,
        TaskChecklistLink.parent_task_id.isnot(None)
    ).all()

    for pt in parent_tasks:
        parent_task_id = pt[0]
        task = db.query(Task).filter(Task.task_id == parent_task_id).first()
        if task and task.status != "In_Process":
            old_status = task.status
            print(f"🔄 Marking parent task {parent_task_id} as In_Process due to child checklist incomplete")
            task.status = "In_Process"
            log_status_change(db, task.task_id, old_status, task.status)
            db.flush()

        parent_checklists = db.query(TaskChecklistLink.checklist_id).filter(
            TaskChecklistLink.sub_task_id == parent_task_id
        ).all()

        for pcl in parent_checklists:
            propagate_incomplete_upwards(pcl[0], db)


def Mark_complete_help(task_id, db, visited_tasks=set()):
    if task_id in visited_tasks:
        return
    visited_tasks.add(task_id)

    subtask_links = db.query(TaskChecklistLink).filter(TaskChecklistLink.sub_task_id == task_id).all()
    for link in subtask_links:
        checklist_id = link.checklist_id

        sibling_subtasks = db.query(Task).join(TaskChecklistLink, TaskChecklistLink.sub_task_id == Task.task_id)\
            .filter(TaskChecklistLink.checklist_id == checklist_id, Task.is_delete == False).all()

        all_completed = all(task.status == TaskStatus.Completed for task in sibling_subtasks)

        if all_completed:
            checklist = db.query(Checklist).filter(Checklist.checklist_id == checklist_id, Checklist.is_delete == False).first()
            if checklist and not checklist.is_completed:
                checklist.is_completed = True
                db.flush()

                parent_links = db.query(TaskChecklistLink).filter(
                    TaskChecklistLink.checklist_id == checklist_id,
                    TaskChecklistLink.parent_task_id.isnot(None)
                ).all()

                for parent_link in parent_links:
                    parent_task_id = parent_link.parent_task_id

                    all_checklists = db.query(Checklist).join(TaskChecklistLink, TaskChecklistLink.checklist_id == Checklist.checklist_id)\
                        .filter(TaskChecklistLink.parent_task_id == parent_task_id, Checklist.is_delete == False).all()

                    if all(c.is_completed for c in all_checklists):
                        parent_task = db.query(Task).filter(Task.task_id == parent_task_id, Task.is_delete == False).first()
                        if parent_task:
                            new_status = TaskStatus.In_Review if parent_task.is_review_required else TaskStatus.Completed
                            if parent_task.status != new_status:
                                old_status = parent_task.status
                                parent_task.status = new_status
                                log_status_change(db, parent_task.task_id, old_status, new_status)
                                db.flush()
                                Mark_complete_help(parent_task_id, db, visited_tasks)


def propagate_incomplete_upwards_from_task(task_id, db, visited_checklists=set(), visited_tasks=set()):
    if task_id in visited_tasks:
        return
    visited_tasks.add(task_id)

    print(f"🔁 Task {task_id} changed to In_Process — rewiring upward...")

    checklist_links = db.query(TaskChecklistLink.checklist_id).filter(
        TaskChecklistLink.sub_task_id == task_id
    ).all()

    for (checklist_id,) in checklist_links:
        if checklist_id in visited_checklists:
            continue
        visited_checklists.add(checklist_id)

        checklist = db.query(Checklist).filter(
            Checklist.checklist_id == checklist_id,
            Checklist.is_delete == False
        ).first()

        if checklist and checklist.is_completed:
            checklist.is_completed = False
            db.flush()
            print(f"❌ Checklist {checklist_id} marked as incomplete")

        parent_links = db.query(TaskChecklistLink.parent_task_id).filter(
            TaskChecklistLink.checklist_id == checklist_id,
            TaskChecklistLink.parent_task_id.isnot(None)
        ).all()

        for (parent_task_id,) in parent_links:
            parent_task = db.query(Task).filter(
                Task.task_id == parent_task_id,
                Task.is_delete == False
            ).first()

            if parent_task and parent_task.status in [TaskStatus.Completed, TaskStatus.In_Review]:
                old_status = parent_task.status
                parent_task.status = TaskStatus.In_Process
                log_status_change(db, parent_task.task_id, old_status, TaskStatus.In_Process)
                db.flush()
                print(f"🔄 Parent Task {parent_task_id} status rewired to In_Process")

            propagate_incomplete_upwards_from_task(parent_task_id, db, visited_checklists, visited_tasks)


def upload_output_to_all_reviews(task_id, output, db):
    while True:
        task = db.query(Task).filter(Task.task_id == task_id, Task.is_delete == False).first()
        if not task:
            break

        old_status = task.status
        task.output = output
        task.is_reviewed = False
        task.status = TaskStatus.To_Do
        log_status_change(db, task.task_id, old_status, TaskStatus.To_Do)
        db.flush()

        next_review = db.query(Task).filter(Task.parent_task_id == task_id, Task.is_delete == False).first()
        if next_review:
            task_id = next_review.task_id
        else:
            break



def collect_entities_to_delete(entity_id, entity_type, deleted_tasks, deleted_checklists, db):
    if entity_type.lower() == 'task':
        # Add the task itself
        deleted_tasks.add(entity_id)
        
        # Get all checklists owned by this task
        owned_checklists = db.query(TaskChecklistLink.checklist_id).filter(
            TaskChecklistLink.parent_task_id == entity_id,
            TaskChecklistLink.checklist_id.isnot(None)
        ).all()
        
        # Process each owned checklist
        for (checklist_id,) in owned_checklists:
            if checklist_id not in deleted_checklists:
                collect_entities_to_delete(checklist_id, 'checklist', deleted_tasks, deleted_checklists, db)
    
    elif entity_type.lower() == 'checklist':
        # Add the checklist itself
        deleted_checklists.add(entity_id)
        
        # Get all subtasks in this checklist
        subtasks = db.query(TaskChecklistLink.sub_task_id).filter(
            TaskChecklistLink.checklist_id == entity_id,
            TaskChecklistLink.sub_task_id.isnot(None)
        ).all()
        
        # Process each subtask
        for (subtask_id,) in subtasks:
            if subtask_id not in deleted_tasks:
                collect_entities_to_delete(subtask_id, 'task', deleted_tasks, deleted_checklists, db)

def get_related_tasks_checklists_logic(session, task_id, checklist_id):
    tasks_to_process = set()
    processed_tasks = set()
    processed_checklists = set()

    if task_id:
        tasks_to_process.add(task_id)
        logging.info(f"Starting with task_id: {task_id}")
    elif checklist_id:
        logging.info(f"Starting with checklist_id: {checklist_id}")

        # Start with checklist and find linked tasks
        results = session.execute(
            select(TaskChecklistLink.sub_task_id)
            .where(TaskChecklistLink.checklist_id == checklist_id)
        ).scalars().all()
        results = [task for task in results if task is not None]

        if results:
            tasks_to_process.update(results)

           
            processed_checklists.add(checklist_id)
            logging.info(f"Found tasks linked to Checklist ID: {checklist_id} -> Tasks: {results}")
        else:
            logging.info(f"No tasks found for Checklist ID: {checklist_id}")
            return {"tasks": [], "checklists": [checklist_id]}  # Return only the given checklist if no tasks found
    else:
        logging.error("No task_id or checklist_id provided")
        return {"tasks": [], "checklists": []}  # No valid input

    while tasks_to_process:
        new_tasks = set()
        new_checklists = set()

        for tid in tasks_to_process:
            if tid in processed_tasks:
                continue
            processed_tasks.add(tid)
            logging.info(f"Processing Task ID: {tid}")

            # Find all checklists linked to this parent task
            results = session.execute(
                select(TaskChecklistLink.checklist_id, TaskChecklistLink.sub_task_id)
                .where(TaskChecklistLink.parent_task_id == tid)
            ).all()
            logging.info(f"Found checklists/subtasks for Task ID: {tid} -> {results}")

            for checklist_id, sub_task_id in results:
                if checklist_id and checklist_id not in processed_checklists:
                    new_checklists.add(checklist_id)
                    processed_checklists.add(checklist_id)
                    logging.info(f"Found Checklist ID: {checklist_id} for Task ID: {tid}")

                if sub_task_id and sub_task_id not in processed_tasks:
                    new_tasks.add(sub_task_id)
                    logging.info(f"Found Sub-task ID: {sub_task_id} for Task ID: {tid} (Checklist ID: {checklist_id})")

        # Process new checklists and link subtasks to them
        for checklist_id in new_checklists:
            results = session.execute(
                select(TaskChecklistLink.sub_task_id)
                .where(TaskChecklistLink.checklist_id == checklist_id)
            ).scalars().all()

            for sub_task_id in results:
                if sub_task_id and sub_task_id not in processed_tasks:
                    new_tasks.add(sub_task_id)
                    logging.info(f"Found Sub-task ID: {sub_task_id} for Checklist ID: {checklist_id}")

        tasks_to_process = new_tasks

    logging.info(f"Final Processed Tasks: {processed_tasks}")
    logging.info(f"Final Processed Checklists: {processed_checklists}")

    return {
        "tasks": list(processed_tasks),
        "checklists": list(processed_checklists)
    }