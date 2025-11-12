from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime, time

# Shared properties
class DoctorBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    specialization: str

# Properties to receive on doctor creation
class DoctorCreate(DoctorBase):
    pass

# Properties to receive on doctor update
class DoctorUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    specialization: Optional[str] = None

# Properties shared by models stored in DB
class DoctorInDBBase(DoctorBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

# Properties to return to client
class Doctor(DoctorInDBBase):
    pass

# Properties stored in DB
class DoctorInDB(DoctorInDBBase):
    pass

# Availability schemas
class AvailabilityBase(BaseModel):
    day_of_week: int = Field(..., ge=0, le=6)
    start_time: time
    end_time: time
    is_available: bool = True

class AvailabilityCreate(AvailabilityBase):
    pass

class AvailabilityUpdate(BaseModel):
    day_of_week: Optional[int] = Field(None, ge=0, le=6)
    start_time: Optional[time] = None
    end_time: Optional[time] = None
    is_available: Optional[bool] = None

class AvailabilityInDBBase(AvailabilityBase):
    id: int
    doctor_id: int

    class Config:
        orm_mode = True

class Availability(AvailabilityInDBBase):
    pass

class DoctorWithAvailability(Doctor):
    availabilities: List[Availability] = []
