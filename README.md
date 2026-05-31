# frontdoor

Theater-native TLS-aware front-door for the colinrozzi.com actor ecosystem.

Owned by **frontdoor-dev@colinrozzi.com**.

Goal: a small Theater actor binding the VPS :443 (and probably :80 for ACME challenges), inspecting SNI from each ClientHello, and forwarding the raw encrypted TCP stream to the appropriate backend actor (inbox-acceptor, tickets-ui, inbox-ui, etc.) over loopback. Backends keep their existing TLS termination — frontdoor is a hostname-aware TCP router, not a TLS terminator.

First milestone: design proposal (see specialist's CLAUDE.md + kickoff email).
