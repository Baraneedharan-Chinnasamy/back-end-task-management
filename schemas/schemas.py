from pydantic import BaseModel, EmailStr
from typing import Optional,List
from datetime import date
from typing import Dict, List
from fastapi import WebSocket, WebSocketDisconnect

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
    is_review_required : bool

class CreateSubTaskRequest(BaseModel):
    checklist_id: int
    sub_task_name: str
    description: Optional[str] = None
    assigned_to: int
    due_date:date
    checklist_names :List[str]
    is_review_required : bool

class CreateChecklistRequest(BaseModel):
    task_id: int
    checklist_name: str

class UpdateStatus(BaseModel):
    checklist_id: int
    is_completed: bool 

class MarkComplete(BaseModel):
    task_id: int

class UpdateTaskRequest(BaseModel):
    assigned_to: Optional[int] = None
    task_name: Optional[str] = None
    description: Optional[str] = None
    due_date: Optional[str] = None
    output :Optional[str] = None
    is_review_required: Optional[bool] = None
    is_reviewed: Optional[bool] = None

class SendForReview(BaseModel):
    task_id: int
    assigned_to: int

class UpdateChecklistRequest(BaseModel):
    checklist_id: int
    checklist_name: str

class DeleteItemsRequest(BaseModel):
    task_id: int = None
    checklist_id: int = None


class ChatMessageCreate(BaseModel):
    sender_id: int
    message: str
    visible_to: Optional[List[int]] = None

class ChatManager:
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, chat_room_id: int):
        await websocket.accept()
        if chat_room_id not in self.active_connections:
            self.active_connections[chat_room_id] = []
        self.active_connections[chat_room_id].append(websocket)

    def disconnect(self, websocket: WebSocket, chat_room_id: int):
        if chat_room_id in self.active_connections:
            if websocket in self.active_connections[chat_room_id]:
                self.active_connections[chat_room_id].remove(websocket)

    async def broadcast(self, chat_room_id: int, message: dict):
        connections = self.active_connections.get(chat_room_id, [])
        to_remove = []

        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception:
                to_remove.append(connection)

        for conn in to_remove:
            self.disconnect(conn, chat_room_id)

    async def broadcast_to_users(self, chat_room_id: int, message: dict, user_ids: List[int]):
        connections = self.active_connections.get(chat_room_id, [])
        to_remove = []

        for connection in connections:
            try:
                user_id = connection.scope.get("user_id")
                if user_id in user_ids:
                    await connection.send_json(message)
            except Exception:
                to_remove.append(connection)

        for conn in to_remove:
            self.disconnect(conn, chat_room_id)

class EmployeeIDList(BaseModel):
    employee_ids: List[int]

class TaskIDPayload(BaseModel):
    task_id: int

class ChecklistIDPayload(BaseModel):
    checklist_id: int