from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from sqlalchemy.orm import Session
import uvicorn
from app.api.routes import patient_router, doctor_router, appointment_router, auth_router
from app.core.config import settings
from app.db.session import engine, get_db
from app.db import models
from app.api.deps import get_current_user

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Healthcare Appointment System",
    description="API for managing healthcare appointments",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication router with no security
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])

app.include_router(
    patient_router,
    prefix="/api/patients",
    tags=["Patients"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    doctor_router,
    prefix="/api/doctors",
    tags=["Doctors"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    appointment_router,
    prefix="/api/appointments",
    tags=["Appointments"],
    dependencies=[Depends(get_current_user)]
)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    openapi_schema["components"] = {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Enter JWT token with 'Bearer ' prefix"
            }
        }
    }

    for path, path_item in openapi_schema["paths"].items():
        if path == "/api/auth/login" or path == "/api/auth/register":
            continue

        for method in path_item.values():
            method.setdefault("security", [{"bearerAuth": []}])

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.get("/", tags=["Root"])
async def root():
    return {"message": "Welcome to the Healthcare Appointment System API /docs for docs"}

@app.get("/health", tags=["Health"])
async def health_check(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
