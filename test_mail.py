import smtplib

EMAIL_USER = "advarttaskmanagement@gmail.com"
EMAIL_PASS = "xsunmuajhlppmqsh"  # paste app password here

try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        print("✅ Login successful! App password is correct.")
except smtplib.SMTPAuthenticationError as e:
    print("❌ Authentication failed:", e.smtp_error.decode())
except Exception as e:
    print("❌ Some other error occurred:", e)




    task = db.query(Task).filter(Task.task_id == data.task_id, Task.is_delete == False).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        task = db.query(Task).filter(
            Task.task_id == data.task_id,
            or_(Task.created_by == Current_user.employee_id, Task.assigned_to == Current_user.employee_id),
            Task.is_delete == False).first()
        if not task:
            raise HTTPException(status_code=404, detail="Creator is not you")
        checklist = Checklist(
            checklist_name=data.checklist_name,
            is_completed=False,
            is_delete=False
        )
        db.add(checklist)
        db.flush()
        db.refresh(checklist)
        task_checklist_link = TaskChecklistLink(
            parent_task_id=task.task_id,
            checklist_id=checklist.checklist_id,
            sub_task_id=None   )
        db.add(task_checklist_link)
        db.flush()

        if task.status == TaskStatus.In_Review:
            log_status_change(db, task.task_id, TaskStatus.In_Review, TaskStatus.In_Process)
            task.status = TaskStatus.In_Process

        if task.status == TaskStatus.Completed:
            log_status_change(db, task.task_id, TaskStatus.Completed, TaskStatus.In_Process)
            task.status = TaskStatus.In_Process
            propagate_incomplete_upwards_from_task(task.task_id, db)

        db.commit()
        return {"message": "Checklist added successfully", "checklist_id": checklist.checklist_id}






if task_data.is_reviewed is not None:
            task_review_done = db.query(Task).filter(Task.task_type == TaskType.Review,Task.task_id == task_id,Task.is_delete == False).first()
            if not task_review_done:
                return JSONResponse(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content={"detail": "This task is not a review task/task not found"}
                )
            if task_review_done:
                task_review_done.is_reviewed = True
                db.flush()
                log_status_change(db, task.task_id, task_review_done.status, TaskStatus.Completed)
                task_review_done.status = TaskStatus.Completed
                db.flush()