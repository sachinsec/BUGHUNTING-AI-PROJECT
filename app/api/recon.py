from fastapi import APIRouter, HTTPException, Query, status

from app.models.recon import ReconScan, SubdomainScanList, SubdomainScanStart
from app.services.subdomain_recon import (
    ReconError,
    cancel_subdomain_scan,
    get_subdomain_scan,
    list_subdomains,
    start_subdomain_scan,
)
from app.models.recon import LiveHostScanStart
from app.services.live_host_recon import (
    LiveHostError,
    cancel_live_host_scan,
    get_live_host_scan,
    list_live_hosts,
    start_live_host_scan,
)
from app.models.recon import URLScanStart
from app.services.url_recon import URLReconError, cancel_url_scan, get_url_scan, list_historical_urls, start_url_scan
from app.models.recon import EndpointScanStart
from app.services.endpoint_recon import EndpointReconError, cancel_endpoint_scan, get_endpoint_scan, list_endpoints, start_endpoint_scan
from app.services.parameter_recon import list_parameters
from app.models.recon import TechnologyScanStart
from app.services.technology_recon import (TechnologyReconError, cancel_technology_scan,
    get_technology_scan, list_technologies, start_technology_scan)
from app.models.recon import ReconOrchestrationStart
from app.services.recon_orchestrator import (OrchestrationError, cancel_reconnaissance_job,
    get_reconnaissance_job, list_reconnaissance_jobs, start_reconnaissance)
from app.models.recon import URLScanStart
from app.services.url_recon import URLReconError, cancel_url_scan, get_url_scan, list_historical_urls, start_url_scan

router = APIRouter()


def _translate_error(error: ReconError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


@router.post("/subdomains/start", response_model=ReconScan, status_code=status.HTTP_202_ACCEPTED)
def start_subdomains(payload: SubdomainScanStart):
    try:
        return start_subdomain_scan(payload.scope_id)
    except ReconError as exc:
        raise _translate_error(exc) from exc


@router.get("/subdomains", response_model=SubdomainScanList)
def subdomains(scope_id: int | None = Query(default=None, gt=0), scan_id: int | None = Query(default=None, gt=0)):
    try:
        return list_subdomains(scope_id=scope_id, scan_id=scan_id)
    except ReconError as exc:
        raise _translate_error(exc) from exc


@router.get("/subdomains/{scan_id}", response_model=ReconScan)
def subdomain_scan(scan_id: int):
    try:
        return get_subdomain_scan(scan_id)
    except ReconError as exc:
        raise _translate_error(exc) from exc


@router.post("/subdomains/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def stop_subdomain_scan(scan_id: int):
    try:
        return cancel_subdomain_scan(scan_id)
    except ReconError as exc:
        raise _translate_error(exc) from exc


def _translate_live_error(error: LiveHostError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


@router.post("/live-hosts/start", status_code=status.HTTP_202_ACCEPTED)
def start_live_hosts(payload: LiveHostScanStart):
    try:
        return start_live_host_scan(payload.scope_id)
    except LiveHostError as exc:
        raise _translate_live_error(exc) from exc


@router.get("/live-hosts")
def live_hosts(scope_id: int | None = Query(default=None, gt=0)):
    try:
        return list_live_hosts(scope_id)
    except LiveHostError as exc:
        raise _translate_live_error(exc) from exc


@router.get("/live-hosts/{scan_id}")
def live_host_scan(scan_id: int):
    try:
        return get_live_host_scan(scan_id)
    except LiveHostError as exc:
        raise _translate_live_error(exc) from exc


@router.post("/live-hosts/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_live_hosts(scan_id: int):
    try:
        return cancel_live_host_scan(scan_id)
    except LiveHostError as exc:
        raise _translate_live_error(exc) from exc


def _translate_url_error(error: URLReconError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


@router.post("/urls/start", status_code=status.HTTP_202_ACCEPTED)
def start_urls(payload: URLScanStart):
    try:
        return start_url_scan(payload.scope_id)
    except URLReconError as exc:
        raise _translate_url_error(exc) from exc


@router.get("/urls")
def historical_urls(scope_id: int | None = Query(default=None, gt=0)):
    try:
        return list_historical_urls(scope_id)
    except URLReconError as exc:
        raise _translate_url_error(exc) from exc


@router.get("/urls/{scan_id}")
def url_scan(scan_id: int):
    try:
        return get_url_scan(scan_id)
    except URLReconError as exc:
        raise _translate_url_error(exc) from exc


@router.post("/urls/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_urls(scan_id: int):
    try:
        return cancel_url_scan(scan_id)
    except URLReconError as exc:
        raise _translate_url_error(exc) from exc


def _translate_endpoint_error(error: EndpointReconError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


@router.post("/endpoints/start", status_code=status.HTTP_202_ACCEPTED)
def start_endpoints(payload: EndpointScanStart):
    try:
        return start_endpoint_scan(payload.scope_id, payload.target_host, payload.approval_confirmed)
    except EndpointReconError as exc:
        raise _translate_endpoint_error(exc) from exc


@router.get("/endpoints")
def endpoints(scope_id: int | None = Query(default=None, gt=0)):
    try:
        return list_endpoints(scope_id)
    except EndpointReconError as exc:
        raise _translate_endpoint_error(exc) from exc


@router.get("/endpoints/{scan_id}")
def endpoint_scan(scan_id: int):
    try:
        return get_endpoint_scan(scan_id)
    except EndpointReconError as exc:
        raise _translate_endpoint_error(exc) from exc


@router.post("/endpoints/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_endpoints(scan_id: int):
    try:
        return cancel_endpoint_scan(scan_id)
    except EndpointReconError as exc:
        raise _translate_endpoint_error(exc) from exc


@router.get("/parameters")
def parameters(scope_id: int | None = Query(default=None, gt=0)):
    return list_parameters(scope_id)


def _translate_technology_error(error: TechnologyReconError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


@router.post("/technologies/start", status_code=status.HTTP_202_ACCEPTED)
def start_technologies(payload: TechnologyScanStart):
    try:
        return start_technology_scan(payload.scope_id, payload.target_host)
    except TechnologyReconError as exc:
        raise _translate_technology_error(exc) from exc


@router.get("/technologies")
def technologies(scope_id: int | None = Query(default=None, gt=0)):
    try:
        return list_technologies(scope_id)
    except TechnologyReconError as exc:
        raise _translate_technology_error(exc) from exc


@router.get("/technologies/{scan_id}")
def technology_scan(scan_id: int):
    try:
        return get_technology_scan(scan_id)
    except TechnologyReconError as exc:
        raise _translate_technology_error(exc) from exc


@router.post("/technologies/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_technologies(scan_id: int):
    try:
        return cancel_technology_scan(scan_id)
    except TechnologyReconError as exc:
        raise _translate_technology_error(exc) from exc


def _translate_orchestration_error(error: OrchestrationError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
def start_reconnaissance_job(payload: ReconOrchestrationStart):
    try:
        return start_reconnaissance(payload.scope_id, payload.active_crawl_approved)
    except OrchestrationError as exc:
        raise _translate_orchestration_error(exc) from exc


@router.get("/scans/{job_id}")
def reconnaissance_job(job_id: int):
    try:
        return get_reconnaissance_job(job_id)
    except OrchestrationError as exc:
        raise _translate_orchestration_error(exc) from exc


@router.get("/scans")
def reconnaissance_jobs(scope_id: int | None = Query(default=None, gt=0)):
    return list_reconnaissance_jobs(scope_id)


@router.post("/scans/{job_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_reconnaissance(job_id: int):
    try:
        return cancel_reconnaissance_job(job_id)
    except OrchestrationError as exc:
        raise _translate_orchestration_error(exc) from exc


def _translate_url_error(error: URLReconError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


@router.post("/urls/start", status_code=status.HTTP_202_ACCEPTED)
def start_urls(payload: URLScanStart):
    try:
        return start_url_scan(payload.scope_id)
    except URLReconError as exc:
        raise _translate_url_error(exc) from exc


@router.get("/urls")
def historical_urls(scope_id: int | None = Query(default=None, gt=0)):
    try:
        return list_historical_urls(scope_id)
    except URLReconError as exc:
        raise _translate_url_error(exc) from exc


@router.get("/urls/{scan_id}")
def url_scan(scan_id: int):
    try:
        return get_url_scan(scan_id)
    except URLReconError as exc:
        raise _translate_url_error(exc) from exc


@router.post("/urls/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_urls(scan_id: int):
    try:
        return cancel_url_scan(scan_id)
    except URLReconError as exc:
        raise _translate_url_error(exc) from exc
