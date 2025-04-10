from datetime import datetime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Column, Integer, String, Text, Enum, Boolean, Date, TIMESTAMP, ForeignKey, func
)
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum
from sqlalchemy.dialects.mysql import LONGTEXT

Base = declarative_base()

class TaskStatus(PyEnum):
    To_Do = "To_Do"
    In_Process = "In_Process"
    Completed = "Completed"


class TaskType(PyEnum):
    Normal = "Normal"
    Review = "Review"
    Approval = "Approval"

class ReviewStatus(PyEnum):
    Approved = "Approved"
    Corrections_Needed = "Corrections_Needed"
    Not_Approved = "Not_Approved"

class ApprovalStatus(PyEnum):
    Not_Approved = "Not_Approved"
    Changes_Required = "Changes_Required"
    Approved = "Approved"


class User(Base):
    __tablename__ = "users"
    employee_id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    designation = Column(String(100), nullable=True)  
    is_active = Column(Boolean, default=True)
    updated_at = Column(TIMESTAMP, server_default=func.current_timestamp(), onupdate=func.current_timestamp())
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())

class Task(Base):
    __tablename__ = "tasks"

    task_id = Column(Integer, primary_key=True, autoincrement=True)
    assigned_to = Column(Integer, ForeignKey("users.employee_id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.employee_id"), nullable=True)
    task_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(TaskStatus), nullable=False, default=TaskStatus.To_Do.name)
    task_type = Column(Enum(TaskType), nullable=False, default=TaskType.Normal.name)
    due_date = Column(Date, nullable=True)
    is_delete = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())
    updated_at = Column(TIMESTAMP, server_default=func.current_timestamp(), onupdate=func.current_timestamp())
    output = Column(LONGTEXT, nullable=True)

    # Status for Review and Approval tasks
    review_status = Column(Enum(ReviewStatus), nullable=True)
    approval_status = Column(Enum(ApprovalStatus), nullable=True)

    # Relationships
    reviews = relationship("TaskReview", back_populates="review_task", foreign_keys="[TaskReview.review_task_id]")
    approvals = relationship("ApprovalWorkflow", back_populates="approval_task", foreign_keys="[ApprovalWorkflow.approval_task_id]")


class Checklist(Base):
    __tablename__ = "checklist"

    checklist_id = Column(Integer, primary_key=True, autoincrement=True)
    checklist_name = Column(String(255), nullable=False)
    is_completed = Column(Boolean, default=False)
    is_delete = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())
    updated_at = Column(TIMESTAMP, server_default=func.current_timestamp(), onupdate=func.current_timestamp())


class TaskChecklistLink(Base):
    __tablename__ = "task_checklist_link"

    link_id = Column(Integer, primary_key=True, autoincrement=True)
    parent_task_id = Column(Integer, ForeignKey("tasks.task_id", ondelete="CASCADE"), nullable=True)
    checklist_id = Column(Integer, ForeignKey("checklist.checklist_id", ondelete="CASCADE"), nullable=True)
    sub_task_id = Column(Integer, ForeignKey("tasks.task_id", ondelete="CASCADE"), nullable=True)


class TaskReview(Base):
    __tablename__ = "task_review"

    review_id = Column(Integer, primary_key=True, autoincrement=True)
    review_task_id = Column(Integer, ForeignKey("tasks.task_id", ondelete="CASCADE"), nullable=False)  # Review task
    original_task_id = Column(Integer, ForeignKey("tasks.task_id", ondelete="CASCADE"), nullable=False)  # Task under review
    reviewer_id = Column(Integer, ForeignKey("users.employee_id"), nullable=False)
    is_delete = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())
    updated_at = Column(TIMESTAMP, server_default=func.current_timestamp(), onupdate=func.current_timestamp())

    # Relationships
    review_task = relationship("Task", foreign_keys=[review_task_id], back_populates="reviews")
    original_task = relationship("Task", foreign_keys=[original_task_id])

# ------------------ APPROVAL WORKFLOW ------------------
class ApprovalWorkflow(Base):
    __tablename__ = "approval_workflow"

    approval_id = Column(Integer, primary_key=True, autoincrement=True)
    approval_task_id = Column(Integer, ForeignKey("tasks.task_id", ondelete="CASCADE"), nullable=False)  # Approval task
    original_task_id = Column(Integer, ForeignKey("tasks.task_id", ondelete="CASCADE"), nullable=False)  # Task under approval
    reviewer_id = Column(Integer, ForeignKey("users.employee_id"), nullable=False)
    comments = Column(Text, nullable=True)
    requires_reapproval = Column(Boolean, default=False)
    is_delete = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())
    updated_at = Column(TIMESTAMP, server_default=func.current_timestamp(), onupdate=func.current_timestamp())

    # Relationships
    approval_task = relationship("Task", foreign_keys=[approval_task_id], back_populates="approvals")
    original_task = relationship("Task", foreign_keys=[original_task_id])

