from fastapi import APIRouter, Request

from lifecycle.job.audit import read_audit_log_user_events
from lifecycle.auth.authenticate import get_username_from_token
from lifecycle.auth.check import check_auth
from racetrack_client.utils.time import timestamp_pretty_ago
from racetrack_commons.auth.auth import AuthSubjectType
from racetrack_commons.entities.audit import explain_audit_log_event
from racetrack_commons.entities.dto import AuditLogEventDto


def setup_audit_endpoints(api: APIRouter):

    @api.get('/audit/activity')
    def _get_jobs_audit(request: Request, job_name: str = '', job_version: str = '', related_to_me: str = '') -> dict:
        """Get Audit Log activity events"""
        check_auth(request, subject_types=[AuthSubjectType.USER])
        filter_related_to_me: bool = related_to_me.lower() in {'true', 'yes', '1'}
        username = get_username_from_token(request) if filter_related_to_me else None
        return _build_job_activity_data(username, job_name, job_version, filter_related_to_me)

    @api.get('/audit/user_events')
    def _get_autdit_user_events(request: Request):
        """List all audit log events for the current user"""
        check_auth(request, subject_types=[AuthSubjectType.USER])
        username = get_username_from_token(request)
        return read_audit_log_user_events(username)

    @api.get('/audit/user_events/job/{job_name}')
    def _get_audit_user_events_job_endpoint(job_name: str, request: Request):
        """List all audit log events for the current user and job family"""
        check_auth(request, subject_types=[AuthSubjectType.USER])
        username = get_username_from_token(request)
        return read_audit_log_user_events(username, job_name)

    @api.get('/audit/user_events/job/{job_name}/{job_version}')
    def _get_audit_user_events_job_version_endpoint(job_name: str, job_version: str, request: Request):
        """List all audit log events for the current user and particular job"""
        check_auth(request, subject_types=[AuthSubjectType.USER])
        username = get_username_from_token(request)
        return read_audit_log_user_events(username, job_name, job_version)

    @api.get('/audit/events')
    def _get_audit_events(request: Request):
        """List all audit log events"""
        check_auth(request)
        return read_audit_log_user_events(None)

    @api.get('/audit/events/job/{job_name}')
    def _get_audit_events_job(request: Request, job_name: str):
        """List all audit log events for the job family"""
        check_auth(request)
        return read_audit_log_user_events(None, job_name)

    @api.get('/audit/events/job/{job_name}/{job_version}')
    def _get_audit_events_job_version(request: Request, job_name: str, job_version: str):
        """List all audit log events for the particular job"""
        check_auth(request)
        return read_audit_log_user_events(None, job_name, job_version)


def _build_job_activity_data(username: str | None, job_name: str, job_version: str, related_to_me: bool) -> dict:
    events: list[AuditLogEventDto] = read_audit_log_user_events(username, job_name, job_version)
    event_dicts = []
    for event in events:
        event_dict = event.dict()
        event_dict['explanation'] = explain_audit_log_event(event)
        event_dict['time_ago'] = timestamp_pretty_ago(event.timestamp)
        event_dicts.append(event_dict)
    return {
        'filter_job_name': job_name,
        'filter_job_version': job_version,
        'filter_related_to_me': related_to_me,
        'events': event_dicts,
    }
