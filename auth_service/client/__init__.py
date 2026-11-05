"""Auth-as-a-Service Python SDK & Microservice Client Library.

Provides a typed async client and FastAPI integration middleware for downstream
microservices authenticating via AaaS.
"""

from auth_service.client.client import AaaSClient

__all__ = ["AaaSClient"]

