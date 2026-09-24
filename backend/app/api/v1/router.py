from fastapi import APIRouter

from app.api.v1.analyses.router import router as analyses_router
from app.api.v1.captures.router import router as captures_router
from app.api.v1.datasets.router import router as datasets_router
from app.api.v1.live_captures.router import router as live_captures_router
from app.api.v1.reconstruction.router import router as reconstruction_router
from app.api.v1.reporting.router import router as reporting_router
from app.api.v1.security.router import router as security_router
from app.api.v1.system.health import router as health_router
from app.api.v1.websocket.router import router as ws_router

api_v1_router = APIRouter(prefix="/v1")

# Mount system health endpoints
api_v1_router.include_router(health_router, prefix="/system")

# Mount Stage 3 capture and protocol forensics endpoints
api_v1_router.include_router(captures_router)
api_v1_router.include_router(analyses_router)
api_v1_router.include_router(live_captures_router)

# Mount Stage 4 reconstruction endpoints
api_v1_router.include_router(reconstruction_router)

# Mount Stage 5 dataset factory and benchmark endpoints
api_v1_router.include_router(datasets_router)

# Mount Stage 8 security, compliance, evidence and scoring endpoints
api_v1_router.include_router(security_router)

# Mount Stage 9 reporting endpoints
api_v1_router.include_router(reporting_router)

# Mount Stage 9 realtime WebSocket endpoints
api_v1_router.include_router(ws_router)


