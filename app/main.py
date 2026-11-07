from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.api.recon import router as recon_router
from app.core.database import initialize_database
from app.core.runtime_settings import initialize_runtime_settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    initialize_runtime_settings()
    yield


app = FastAPI(title="AI BugHunter", version="0.1.0", lifespan=lifespan)
app.include_router(router, prefix="/api")
app.include_router(recon_router, prefix="/api/recon", tags=["reconnaissance"])
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(FRONTEND_DIR / "index.html")
