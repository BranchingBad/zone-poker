#!/usr/bin/env python3
import asyncio
from typing import Any, Dict, Tuple

import dns.resolver

from ..config import PUBLIC_RESOLVERS


async def propagation_check(
    domain: str, timeout: int, **kwargs
) -> Dict[str, Dict[str, Any]]:
    """Checks domain 'A' record propagation against public resolvers."""
    results: Dict[str, Dict[str, Any]] = {}

    async def check_resolver(name: str, ip: str) -> Tuple[str, Dict[str, Any]]:
        """
        Checks a single resolver and returns its name and result.
        This is a cleaner pattern than modifying a shared dict from within a task.
        """
        # Create a resolver with configure=False. This prevents it from automatically
        # reading /etc/resolv.conf and stops it from sending DNSSEC OK (DO) bits,
        # which can cause SERVFAIL responses from some public resolvers.
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = [ip]

        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, "A")
            # Return all A records found, not just the first one.
            return name, {"ips": [str(a) for a in answers], "error": None}
        except dns.exception.Timeout:
            return name, {"ips": [], "error": "Timeout"}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return name, {"ips": [], "error": "No A record found"}
        except Exception as e:
            return name, {"ips": [], "error": f"Error: {type(e).__name__}"}

    tasks = [check_resolver(name, ip) for name, ip in PUBLIC_RESOLVERS.items()]
    task_results = await asyncio.gather(*tasks)

    # Aggregate results after all tasks are complete
    for name, result_data in task_results:
        results[name] = result_data
    return results
