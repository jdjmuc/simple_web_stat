"""
Pydantic models for Apache log file parsing and storage.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ApacheLogEntry(BaseModel):
    """
    Represents a single entry from Apache Combined Log Format.
    
    Format: 
    remote_host ident authuser [timestamp] "request" status_code bytes_sent "referrer" "user_agent"
    """
    
    remote_host: str = Field(
        description="IP address or hostname of the client making the request"
    )
    
    ident: Optional[str] = Field(
        default=None,
        description="RFC 1413 identity of the client (typically '-' if not available)"
    )
    
    authuser: Optional[str] = Field(
        default=None,
        description="Authenticated username if available (typically '-' if not authenticated)"
    )
    
    timestamp: datetime = Field(
        description="Date and time when the server finished processing the request"
    )
    
    http_method: str = Field(
        description="HTTP method used in the request (GET, POST, HEAD, etc.)"
    )
    
    uri: str = Field(
        description="URI (path and query string) requested by the client"
    )
    
    http_version: str = Field(
        description="HTTP protocol version used by the client (e.g., 'HTTP/1.1')"
    )
    
    status_code: int = Field(
        description="HTTP status code returned by the server (e.g., 200, 404, 302)"
    )
    
    bytes_sent: int = Field(
        description="Size of the response body in bytes (excluding HTTP headers)"
    )
    
    referrer: Optional[str] = Field(
        default=None,
        description="URL of the referring page (HTTP Referer header, '-' if not available)"
    )
    
    user_agent: Optional[str] = Field(
        default=None,
        description="User agent string identifying the client software (browser, bot, etc.)"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "remote_host": "192.168.1.100",
                "ident": None,
                "authuser": None,
                "timestamp": "2025-12-19T00:08:24+01:00",
                "http_method": "GET",
                "uri": "/index.html",
                "http_version": "HTTP/1.1",
                "status_code": 200,
                "bytes_sent": 4998,
                "referrer": "https://example.com/",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            }
        }
