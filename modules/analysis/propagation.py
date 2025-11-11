#!/usr/bin/env python3
import asyncio
import dns.resolver
from typing import Dict
from ..config import PUBLIC_RESOLVERS

async def propagation_check(domain: str, timeout: int) -> Dict[str, str]:
    """Checks domain 'A' record propagation against public resolvers."""
    results = {}
    
    async def check_resolver(name, ip):
        # Use the default resolver configuration, which does not set the
        # 'DNSSEC OK' (DO) bit. This prevents SERVFAIL errors from resolvers
        # when querying unsigned domains.
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = [ip]
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, "A")
            results[name] = str(answers[0])
        except Exception as e:
            results[name] = f"Error: {type(e).__name__}"
            
    await asyncio.gather(*(check_resolver(name, ip) for name, ip in PUBLIC_RESOLVERS.items()))
    return results