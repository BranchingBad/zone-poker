#!/usr/bin/env python3
import asyncio
import dns.resolver
from typing import Dict
from ..config import PUBLIC_RESOLVERS

async def propagation_check(domain: str, timeout: int, **kwargs) -> Dict[str, str]:
    """Checks domain 'A' record propagation against public resolvers."""
    results = {}
    
    async def check_resolver(name, ip):
        # --- THIS IS THE FIX ---
        # Create a resolver with configure=False to avoid sending DNSSEC OK (DO)
        # bits, which can cause SERVFAIL for unsigned domains on some resolvers.
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