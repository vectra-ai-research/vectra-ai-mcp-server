"""Vectra AI API client wrapper with authentication and rate limiting."""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
import base64

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from config import VectraConfig
from utils.logging import get_logger


class VectraAPIError(Exception):
    """Custom exception for Vectra API errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class VectraAuthenticationError(VectraAPIError):
    """Authentication-related API errors."""
    pass


class VectraRateLimitError(VectraAPIError):
    """Rate limiting API errors."""
    pass


class VectraNotFoundError(VectraAPIError):
    """Resource not found API errors."""
    pass


class TokenManager:
    """Manages OAuth2 token lifecycle."""
    
    def __init__(self, client_id: str, client_secret: str, token_url: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[float] = None
        self._token_lock = asyncio.Lock()
        self.logger = get_logger(__name__)
    
    async def get_access_token(self) -> str:
        """Get valid access token, refreshing if necessary."""
        async with self._token_lock:
            if self._is_token_valid():
                return self._access_token
            
            await self._refresh_token()
            return self._access_token
    
    def _is_token_valid(self) -> bool:
        """Check if current token is valid and not expired."""
        if not self._access_token or not self._token_expires_at:
            return False
        
        # Add 60 second buffer for token expiration
        return time.time() < (self._token_expires_at - 60)
    
    async def _refresh_token(self) -> None:
        """Refresh OAuth2 access token."""
        self.logger.info("Refreshing OAuth2 access token")
        
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        payload = {
            "grant_type": "client_credentials"
        }
        auth_string = self.client_id+':'+self.client_secret
        auth_string_base64 = base64.b64encode(auth_string.encode('ascii'))

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    url=self.token_url,
                    data=payload,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded", 
                        'Authorization': 'Basic '+auth_string_base64.decode('ascii')
                    },
                    timeout=30.0
                )
                response.raise_for_status()
                
                token_data = response.json()
                self._access_token = token_data["access_token"]
                expires_in = token_data.get("expires_in", 3600)
                self._token_expires_at = time.time() + expires_in
                
                self.logger.info("OAuth2 token refreshed successfully")
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise VectraAuthenticationError(
                        "Invalid OAuth2 credentials",
                        status_code=401
                    )
                raise VectraAPIError(
                    f"Token refresh failed: {e}",
                    status_code=e.response.status_code
                )
            except Exception as e:
                raise VectraAPIError(f"Token refresh error: {e}")


class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, requests_per_period: int, period: int):
        self.requests_per_period = requests_per_period
        self.period = period
        self.tokens = requests_per_period
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> None:
        """Acquire a token for rate limiting."""
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_update
            
            # Add tokens based on time passed
            self.tokens = min(
                self.requests_per_period,
                self.tokens + (time_passed * self.requests_per_period / self.period)
            )
            self.last_update = now
            
            if self.tokens < 1:
                # Calculate wait time
                wait_time = (1 - self.tokens) * self.period / self.requests_per_period
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class VectraClient:
    """Vectra AI API client with authentication and rate limiting."""
    
    def __init__(self, config: VectraConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Initialize token manager
        self.token_manager = TokenManager(
            client_id=config.client_id,
            client_secret=config.client_secret,
            token_url=config.oauth_token_url
        )
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter(
            requests_per_period=config.rate_limit_requests,
            period=config.rate_limit_period
        )
        
        # HTTP client configuration
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.request_timeout),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)
        )
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException))
    )
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make authenticated HTTP request to Vectra API."""
        await self.rate_limiter.acquire()
        
        # Get access token
        access_token = await self.token_manager.get_access_token()
        
        # Build URL
        url = urljoin(self.config.api_base_url + "/", endpoint.lstrip("/"))
        
        # Prepare headers
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": f"VectraMCPServer/1.0.0"
        }
        
        # Log request
        self.logger.debug(f"Making {method} request to {url}", extra={
            "method": method,
            "url": url,
            "params": params
        })
        
        try:
            response = await self.client.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers
            )
            
            # Handle response
            if response.status_code == 401:
                raise VectraAuthenticationError(
                    "Authentication failed - check credentials",
                    status_code=401
                )
            elif response.status_code == 403:
                raise VectraAuthenticationError(
                    "Access forbidden - insufficient permissions",
                    status_code=403
                )
            elif response.status_code == 404:
                raise VectraNotFoundError(
                    "Resource not found",
                    status_code=404
                )
            elif response.status_code == 429:
                raise VectraRateLimitError(
                    "Rate limit exceeded",
                    status_code=429
                )
            elif not response.is_success:
                error_msg = f"API request failed with status {response.status_code}"
                try:
                    error_data = response.json()
                    if "message" in error_data:
                        error_msg += f": {error_data['message']}"
                except:
                    error_msg += f": {response.text}"
                
                raise VectraAPIError(
                    error_msg,
                    status_code=response.status_code,
                    response_data=error_data if 'error_data' in locals() else None
                )
            
            # Parse JSON response
            if response.headers.get("content-type", "").startswith("application/json"):
                return response.json()
            else:
                return {"data": response.text}
        
        except httpx.HTTPStatusError as e:
            raise VectraAPIError(f"HTTP error: {e}", status_code=e.response.status_code)
        except httpx.RequestError as e:
            raise VectraAPIError(f"Request error: {e}")
    
    async def _get_all_pages(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        max_pages: int = 1000
    ) -> Dict[str, Any]:
        """
        Fetch all pages from a paginated endpoint and return combined results.
        
        Args:
            endpoint: API endpoint to call
            params: Query parameters for the request
            max_pages: Maximum number of pages to fetch (safety limit)
            
        Returns:
            Dict with same structure as single page response but with all results combined:
            {
                "count": total_count,
                "next": null,
                "previous": null,
                "results": [all_items_from_all_pages]
            }
        """
        if params is None:
            params = {}
        
        all_results = []
        current_params = params.copy()
        pages_fetched = 0
        
        # Remove any existing page parameter to start from page 1
        current_params.pop("page", None)
        
        self.logger.debug(f"Starting auto-pagination for {endpoint}")
        
        while pages_fetched < max_pages:
            try:
                response = await self._make_request("GET", endpoint, params=current_params)
                
                # Check if this is a paginated response
                if not isinstance(response, dict) or "results" not in response:
                    # Not a paginated response, return as-is
                    return response
                
                # Add results from current page
                page_results = response.get("results", [])
                all_results.extend(page_results)
                pages_fetched += 1
                
                self.logger.debug(f"Fetched page {pages_fetched}, got {len(page_results)} items, total: {len(all_results)}")
                
                # Check if there's a next page
                next_url = response.get("next")
                if not next_url:
                    # No more pages
                    break
                
                # Extract page number from next URL
                try:
                    parsed_url = urlparse(next_url)
                    query_params = parse_qs(parsed_url.query)
                    next_page = query_params.get("page", [None])[0]
                    
                    if next_page:
                        current_params["page"] = int(next_page)
                    else:
                        # No page parameter in next URL, break to avoid infinite loop
                        break
                        
                except (ValueError, TypeError) as e:
                    self.logger.warning(f"Could not parse next page URL: {next_url}, error: {e}")
                    break
                    
            except Exception as e:
                self.logger.error(f"Error during pagination at page {pages_fetched + 1}: {e}")
                # Return what we have so far
                break
        
        if pages_fetched >= max_pages:
            self.logger.warning(f"Reached maximum page limit ({max_pages}) for {endpoint}")
        
        # Return combined response with same structure
        return {
            "count": len(all_results),
            "next": None,
            "previous": None,
            "results": all_results
        }
    
    # Account endpoints
    async def get_accounts(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        account_type: Optional[str] = None,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        min_threat: Optional[int] = None,
        max_threat: Optional[int] = None,
        min_certainty: Optional[int] = None,
        max_certainty: Optional[int] = None,
        tags: Optional[str] = None,
        name: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of accounts with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "account_type": account_type,
            "state": state,
            "severity": severity,
            "min_threat": min_threat,
            "max_threat": max_threat,
            "min_certainty": min_certainty,
            "max_certainty": max_certainty,
            "tags": tags,
            "name": name,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("accounts", params)
        else:
            return await self._make_request("GET", "accounts", params=params)
    
    async def get_account(self, account_id: int) -> Dict[str, Any]:
        """Get specific account by ID."""
        return await self._make_request("GET", f"accounts/{account_id}")
    
    # Host endpoints
    async def get_hosts(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        min_threat: Optional[int] = None,
        max_threat: Optional[int] = None,
        min_certainty: Optional[int] = None,
        max_certainty: Optional[int] = None,
        is_key_asset: Optional[bool] = None,
        name: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of hosts with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "state": state,
            "severity": severity,
            "min_threat": min_threat,
            "max_threat": max_threat,
            "min_certainty": min_certainty,
            "max_certainty": max_certainty,
            "is_key_asset": is_key_asset,
            "name": name,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("hosts", params)
        else:
            return await self._make_request("GET", "hosts", params=params)
    
    async def get_host(self, host_id: int) -> Dict[str, Any]:
        """Get specific host by ID."""
        return await self._make_request("GET", f"hosts/{host_id}")
    
    # Entity endpoints
    async def get_entities(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of entities with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("entities", params)
        else:
            return await self._make_request("GET", "entities", params=params)
    
    async def get_entity(self, entity_id: int, entity_type: str) -> Dict[str, Any]:
        """Get specific entity by ID."""
        params = {"type": entity_type}
        return await self._make_request("GET", f"entities/{entity_id}", params=params)
    
    # Detection endpoints
    async def get_detections(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        detection_category: Optional[str] = None,
        detection_type: Optional[str] = None,
        state: Optional[str] = None,
        min_threat: Optional[int] = None,
        max_threat: Optional[int] = None,
        min_certainty: Optional[int] = None,
        max_certainty: Optional[int] = None,
        is_targeting_key_asset: Optional[bool] = None,
        src_ip: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of detections with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "detection_category": detection_category,
            "detection_type": detection_type,
            "state": state,
            "min_threat": min_threat,
            "max_threat": max_threat,
            "min_certainty": min_certainty,
            "max_certainty": max_certainty,
            "is_targeting_key_asset": is_targeting_key_asset,
            "src_ip": src_ip,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("detections", params)
        else:
            return await self._make_request("GET", "detections", params=params)
    
    async def get_detection(self, detection_id: int) -> Dict[str, Any]:
        """Get specific detection by ID."""
        return await self._make_request("GET", f"detections/{detection_id}")
    
    # Detection Action endpoints
    async def mark_detection_fixed(self, detection_ids: list, fixed_status: bool) -> Dict[str, Any]:
        """Marks or unmark detection as fixed."""

        mark_data = {
            "detectionIdList": detection_ids,
            "mark_as_fixed": str(fixed_status)
        }
        return await self._make_request("PATCH", f"detections", json_data=mark_data)
    
    # Event endpoints
    async def get_events(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        category: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of events with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "category": category,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("events", params)
        else:
            return await self._make_request("GET", "events", params=params)
    
    # Assignment endpoints
    async def get_assignments(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        resolved: Optional[bool] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of assignments with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "resolved": resolved,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("assignments", params)
        else:
            return await self._make_request("GET", "assignments", params=params)
    
    async def get_assignment(self, assignment_id: int) -> Dict[str, Any]:
        """Get specific assignment by ID."""
        return await self._make_request("GET", f"assignments/{assignment_id}")
    
    async def create_assignment(self, assignment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new assignment."""
        return await self._make_request("POST", "assignments", json_data=assignment_data)
    
    async def update_assignment(self, assignment_id: int, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing assignment."""
        return await self._make_request("PATCH", f"assignments/{assignment_id}", json_data=update_data)
    
    # Health endpoints
    async def get_health(self) -> Dict[str, Any]:
        """Get system health status."""
        return await self._make_request("GET", "health")
    
    # Notes endpoints
    async def add_entity_note(self, entity_id: int, type: str, note: str) -> Dict[str, Any]:
        """Add note to entity."""
        return await self._make_request("POST", f"/entities/{entity_id}/notes", params={"type": type}, data={"note": note})
    
    # Tagging endpoints
    async def add_tags(self, entity_type: str, entity_id: int, tags: List[str]) -> Dict[str, Any]:
        """Add tags to entity."""
        tag_data = {"tags": tags}
        return await self._make_request("PATCH", f"{entity_type}s/{entity_id}/tags", json_data=tag_data)
    
    # Groups endpoints
    async def get_groups(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        group_type: Optional[str] = None,
        name: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of groups with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "type": group_type,
            "name": name,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("groups", params)
        else:
            return await self._make_request("GET", "groups", params=params)
    
    async def get_group(self, group_id: int) -> Dict[str, Any]:
        """Get specific group by ID."""
        return await self._make_request("GET", f"groups/{group_id}")
    
    async def create_group(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new group."""
        return await self._make_request("POST", "groups", json_data=group_data)
    
    async def update_group(self, group_id: int, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing group."""
        return await self._make_request("PATCH", f"groups/{group_id}", json_data=update_data)
    
    async def delete_group(self, group_id: int) -> Dict[str, Any]:
        """Delete group."""
        return await self._make_request("DELETE", f"groups/{group_id}")
    
    async def get_group_members(
        self,
        group_id: int,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get group members."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages(f"groups/{group_id}/members", params)
        else:
            return await self._make_request("GET", f"groups/{group_id}/members", params=params)

    # Rules endpoints
    async def get_rules(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of triage rules with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("rules", params)
        else:
            return await self._make_request("GET", "rules", params=params)
    
    async def get_rule(self, rule_id: int) -> Dict[str, Any]:
        """Get specific triage rule by ID."""
        return await self._make_request("GET", f"rules/{rule_id}")
    
    async def create_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new triage rule."""
        return await self._make_request("POST", "rules", json_data=rule_data)
    
    async def update_rule(self, rule_id: int, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing triage rule."""
        return await self._make_request("PATCH", f"rules/{rule_id}", json_data=update_data)
    
    async def delete_rule(self, rule_id: int) -> Dict[str, Any]:
        """Delete triage rule."""
        return await self._make_request("DELETE", f"rules/{rule_id}")

    # Users endpoints
    async def get_users(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of users."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("users", params)
        else:
            return await self._make_request("GET", "users", params=params)
    
    async def get_user(self, user_id: int) -> Dict[str, Any]:
        """Get specific user by ID."""
        return await self._make_request("GET", f"users/{user_id}")
    
    async def get_user_roles(self) -> Dict[str, Any]:
        """Get available user roles."""
        return await self._make_request("GET", "users/roles")

    # Lockdown endpoints
    async def get_lockdown_status(self, **kwargs) -> Dict[str, Any]:
        """Get lockdown status."""
        params = {k: v for k, v in kwargs.items() if v is not None}
        return await self._make_request("GET", "lockdown", params=params)
    
    async def initiate_lockdown(self, lockdown_data: Dict[str, Any]) -> Dict[str, Any]:
        """Initiate lockdown operation."""
        return await self._make_request("POST", "lockdown", json_data=lockdown_data)

    # Threat feeds endpoints
    async def get_threat_feeds(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of threat feeds."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("threatFeeds", params)
        else:
            return await self._make_request("GET", "threatFeeds", params=params)
    
    async def get_threat_feed(self, feed_id: int) -> Dict[str, Any]:
        """Get specific threat feed by ID."""
        return await self._make_request("GET", f"threatFeeds/{feed_id}")
    
    async def upload_threat_feed(self, feed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Upload new threat feed."""
        return await self._make_request("POST", "threatFeeds", json_data=feed_data)
    
    async def delete_threat_feed(self, feed_id: int) -> Dict[str, Any]:
        """Delete threat feed."""
        return await self._make_request("DELETE", f"threatFeeds/{feed_id}")

    # Unique hosts endpoints
    async def get_unique_hosts_observed(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get unique hosts observed statistics."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("unique_hosts_observed", params)
        else:
            return await self._make_request("GET", "unique_hosts_observed", params=params)
    
    async def get_unique_hosts_monthly(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get monthly unique hosts observed statistics."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("unique_hosts_observed_monthly", params)
        else:
            return await self._make_request("GET", "unique_hosts_observed_monthly", params=params)

    # Vectra Match endpoints
    async def get_vectra_match_stats(self) -> Dict[str, Any]:
        """Get Vectra Match statistics."""
        return await self._make_request("GET", "vectra-match/stats")
    
    async def get_vectra_match_rules(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get Vectra Match rules."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("vectra-match/rules", params)
        else:
            return await self._make_request("GET", "vectra-match/rules", params=params)
    
    async def get_vectra_match_status(self) -> Dict[str, Any]:
        """Get Vectra Match status."""
        return await self._make_request("GET", "vectra-match/status")
    
    async def get_vectra_match_enablement(self) -> Dict[str, Any]:
        """Get Vectra Match enablement status."""
        return await self._make_request("GET", "vectra-match/enablement")
    
    async def get_vectra_match_available_devices(self) -> Dict[str, Any]:
        """Get available devices for Vectra Match."""
        return await self._make_request("GET", "vectra-match/available-devices")
    
    # Vectra pcap endpoints
    async def get_detection_pcap(self, detection_id) -> Dict[str, Any]:
        """Get Vectra Match statistics."""
        return await self._make_request("GET", f"detections/{detection_id}/pcap")
    
    # Vectra lockdown endpoints
    async def get_lockdown_entities(self) -> Dict[str, Any]:
        """Get Vectra Match statistics."""
        return await self._make_request("GET", f"lockdown")

    # Search functionality
    async def search_by_name(self, name: str, entity_type: Optional[str] = None) -> Dict[str, Any]:
        """Search entities by name."""
        if entity_type == "account":
            return await self.get_accounts(name=name)
        elif entity_type == "host":
            return await self.get_hosts(name=name)
        else:
            # Search both accounts and hosts
            accounts = await self.get_accounts(name=name)
            hosts = await self.get_hosts(name=name)
            return {
                "accounts": accounts.get("results", []),
                "hosts": hosts.get("results", [])
            }