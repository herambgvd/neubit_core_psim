"""
Shared service classes for Neubit PSIM Core Platform Service.

This module provides common services that are used across multiple
applications within the Core Platform, including:
- HTTP client for inter-service communication
- Notification services
- Caching utilities
- Service discovery
- Configuration management

All services are designed to be thread-safe and production-ready.
"""

import json
import time
import asyncio
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone

import structlog

# Configure structured logger
logger = structlog.get_logger(__name__)


@dataclass
class ServiceEndpoint:
    """Data class for service endpoint information."""
    name: str
    url: str
    version: str
    health_url: str
    timeout: int = 30
    retries: int = 3


class HTTPClientService:
    """
    HTTP client service for inter-service communication.

    This service provides a standardized way to communicate with other
    microservices in the PSIM ecosystem, including authentication,
    retry logic, and error handling.
    """

    def __init__(self):
        """Initialize HTTP client with default configuration."""
        self.timeout = httpx.Timeout(30.0)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=True
        )
        self.sync_client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            verify=True
        )

    async def request(
            self,
            method: str,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            data: Optional[Dict[str, Any]] = None,
            json_data: Optional[Dict[str, Any]] = None,
            params: Optional[Dict[str, Any]] = None,
            timeout: Optional[float] = None,
            retries: int = 3,
            correlation_id: Optional[str] = None
    ) -> httpx.Response:
        """
        Make an async HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Request URL
            headers: Additional headers
            data: Form data
            json_data: JSON data
            params: Query parameters
            timeout: Request timeout
            retries: Number of retry attempts
            correlation_id: Correlation ID for request tracking

        Returns:
            HTTP response object

        Raises:
            httpx.HTTPError: On HTTP errors
            httpx.RequestError: On request errors
        """
        # Prepare headers
        request_headers = self._prepare_headers(headers, correlation_id)

        # Prepare request kwargs
        kwargs = {
            'headers': request_headers,
            'params': params,
        }

        if json_data:
            kwargs['json'] = json_data
        elif data:
            kwargs['data'] = data

        if timeout:
            kwargs['timeout'] = timeout

        # Retry logic
        last_exception = None
        for attempt in range(retries + 1):
            try:
                logger.info(
                    "http_request_started",
                    method=method,
                    url=url,
                    attempt=attempt + 1,
                    correlation_id=correlation_id
                )

                response = await self.client.request(method, url, **kwargs)

                logger.info(
                    "http_request_completed",
                    method=method,
                    url=url,
                    status_code=response.status_code,
                    attempt=attempt + 1,
                    correlation_id=correlation_id
                )

                # Raise for HTTP error status codes
                response.raise_for_status()
                return response

            except (httpx.HTTPError, httpx.RequestError) as e:
                last_exception = e

                logger.warning(
                    "http_request_failed",
                    method=method,
                    url=url,
                    attempt=attempt + 1,
                    error=str(e),
                    correlation_id=correlation_id
                )

                # Don't retry on client errors (4xx)
                if isinstance(e, httpx.HTTPStatusError) and 400 <= e.response.status_code < 500:
                    raise e

                # Wait before retry with exponential backoff
                if attempt < retries:
                    wait_time = (2 ** attempt) + (0.1 * attempt)
                    await asyncio.sleep(wait_time)

        # All retries exhausted
        logger.error(
            "http_request_exhausted",
            method=method,
            url=url,
            retries=retries,
            final_error=str(last_exception),
            correlation_id=correlation_id
        )

        raise last_exception

    def sync_request(
            self,
            method: str,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            data: Optional[Dict[str, Any]] = None,
            json_data: Optional[Dict[str, Any]] = None,
            params: Optional[Dict[str, Any]] = None,
            timeout: Optional[float] = None,
            retries: int = 3,
            correlation_id: Optional[str] = None
    ) -> httpx.Response:
        """
        Make a synchronous HTTP request with retry logic.

        Args:
            method: HTTP method
            url: Request URL
            headers: Additional headers
            data: Form data
            json_data: JSON data
            params: Query parameters
            timeout: Request timeout
            retries: Number of retry attempts
            correlation_id: Correlation ID for request tracking

        Returns:
            HTTP response object
        """
        # Prepare headers
        request_headers = self._prepare_headers(headers, correlation_id)

        # Prepare request kwargs
        kwargs = {
            'headers': request_headers,
            'params': params,
        }

        if json_data:
            kwargs['json'] = json_data
        elif data:
            kwargs['data'] = data

        if timeout:
            kwargs['timeout'] = timeout

        # Retry logic
        last_exception = None
        for attempt in range(retries + 1):
            try:
                response = self.sync_client.request(method, url, **kwargs)
                response.raise_for_status()
                return response

            except (httpx.HTTPError, httpx.RequestError) as e:
                last_exception = e

                # Don't retry on client errors (4xx)
                if isinstance(e, httpx.HTTPStatusError) and 400 <= e.response.status_code < 500:
                    raise e

                # Wait before retry
                if attempt < retries:
                    wait_time = (2 ** attempt) + (0.1 * attempt)
                    time.sleep(wait_time)

        raise last_exception

    def _prepare_headers(
            self,
            headers: Optional[Dict[str, str]],
            correlation_id: Optional[str]
    ) -> Dict[str, str]:
        """
        Prepare request headers with authentication and correlation.

        Args:
            headers: Additional headers
            correlation_id: Correlation ID

        Returns:
            Complete headers dictionary
        """
        request_headers = {
            'User-Agent': f'Neubit-PSIM-Core/{getattr(settings, "VERSION", "1.0.0")}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

        # Add correlation ID
        if correlation_id:
            request_headers['X-Correlation-ID'] = correlation_id

        # Add service authentication
        service_config = getattr(settings, 'SERVICE_DISCOVERY', {})
        service_name = service_config.get('SERVICE_NAME', 'core-platform')
        request_headers['X-Service-Name'] = service_name

        # Add any additional headers
        if headers:
            request_headers.update(headers)

        return request_headers

    async def close(self):
        """Close the async HTTP client."""
        await self.client.aclose()

    def close_sync(self):
        """Close the sync HTTP client."""
        self.sync_client.close()

http_client = HTTPClientService()