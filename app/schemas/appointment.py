from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

class AppointmentStatus(str, Enum):
    SCHEDULED = "scheduled"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    NO_SHOW = "no_show"

# Shared properties
class AppointmentBase(BaseModel):
    patient_id: int
    doctor_id: int
    start_time: datetime
    end_time: datetime
    status: AppointmentStatus = AppointmentStatus.SCHEDULED
    notes: Optional[str] = None

# Properties to receive on appointment creation
class AppointmentCreate(AppointmentBase):
    pass

# Properties to receive on appointment update
class AppointmentUpdate(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status: Optional[AppointmentStatus] = None
    notes: Optional[str] = None

# Properties shared by models stored in DB
class AppointmentInDBBase(AppointmentBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# Properties to return to client
class Appointment(AppointmentInDBBase):
    pass

# Properties stored in DB
class AppointmentInDB(AppointmentInDBBase):
    pass

# Appointment with patient and doctor details
class AppointmentDetail(Appointment):
    patient_name: str
    doctor_name: str
    doctor_specialization: str
