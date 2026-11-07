from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.api.routes import router
from app.core.database import initialize_database


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="AI BugHunter", version="0.1.0", lifespan=lifespan)
app.include_router(router, prefix="/api")


@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse(url="/docs")
