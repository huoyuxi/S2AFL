"""Protocol-aware mutation guardrails for the runtime mutation agent."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProtocolMutationPolicy:
    protocol: str
    default_boundary_lengths: tuple[int, ...]
    default_vuln_lengths: tuple[int, ...]
    default_injections: tuple[str, ...]
    default_fixups: tuple[str, ...]
    message_style: str = "request-style"
    line_body_methods: tuple[str, ...] = ()
    line_body_terminator: str = "\r\n.\r\n"
    line_body_end_markers: tuple[str, ...] = (".",)
    max_candidates: int = 8
    default_preserve_prefix: bool = True
    required_prefix_chain: tuple[str, ...] = ()
    prefix_optional_methods: tuple[str, ...] = ()
    single_message_methods: tuple[str, ...] = ()
    parser_function_keywords: tuple[str, ...] = ("parse", "parser", "lex")
    parser_single_message_allowed: bool = True
    sequence_anchor_methods: tuple[str, ...] = ()
    sequence_terminal_methods: tuple[str, ...] = ()
    sequence_completion_methods: tuple[str, ...] = ()
    content_length_validation: bool = False
    request_region_start_methods: tuple[str, ...] = ()
    boundary_line_length_cap: int = 4096
    vuln_line_length_cap: int = 16384
    aflnet_region_rules: tuple[str, ...] = ()



_COMMON_INJECTIONS = ("%n", "%s", "%x", "../", "..\\", "\\u0000", ";", " ", "\t")

_POLICIES: dict[str, ProtocolMutationPolicy] = {
    "FTP": ProtocolMutationPolicy(
        protocol="FTP",
        default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 127, 128),
        default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
        default_injections=_COMMON_INJECTIONS,
        default_fixups=(),
        message_style="line-command",
        max_candidates=8,
        required_prefix_chain=("USER", "PASS"),
        prefix_optional_methods=("USER", "PASS", "QUIT", "SYST", "NOOP"),
        single_message_methods=("USER", "PASS", "QUIT", "SYST", "NOOP", "HELP"),
        aflnet_region_rules=("One region ends at each \r\n.",),
    ),
    "SMTP": ProtocolMutationPolicy(
        protocol="SMTP",
        default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 127, 128),
        default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
        default_injections=_COMMON_INJECTIONS,
        default_fixups=("content_length",),
        message_style="line-command",
        line_body_methods=("DATA", "BDAT"),
        line_body_end_markers=(".",),
        max_candidates=8,
        single_message_methods=("HELO", "EHLO", "NOOP", "QUIT", "RSET"),
        content_length_validation=True,
        aflnet_region_rules=("One region ends at each \r\n.", "DATA body lines and the final . line are separate AFLNet regions."),
    ),
    "RTSP": ProtocolMutationPolicy(
        protocol="RTSP",
        default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 127, 128),
        default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
        default_injections=_COMMON_INJECTIONS,
        default_fixups=("content_length", "cseq", "session"),
        max_candidates=8,
        single_message_methods=("OPTIONS", "DESCRIBE"),
        sequence_anchor_methods=("OPTIONS", "DESCRIBE", "SETUP"),
        sequence_terminal_methods=("TEARDOWN",),
        sequence_completion_methods=("RECORD", "PLAY"),
        content_length_validation=True,
        aflnet_region_rules=("One region ends at \r\n\r\n.", "AFLNet does not use Content-Length to keep a body in the same region."),
    ),
    "HTTP": ProtocolMutationPolicy(
        protocol="HTTP",
        default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 127, 128),
        default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
        default_injections=_COMMON_INJECTIONS,
        default_fixups=("content_length",),
        max_candidates=8,
        single_message_methods=("GET", "HEAD", "OPTIONS"),
        content_length_validation=True,
        aflnet_region_rules=("One region ends at \\r\\n\\r\\n.", "AFLNet does not use Content-Length to keep a body in the same region."),
    ),
    "DAAP": ProtocolMutationPolicy(
        protocol="DAAP",
        default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 127, 128),
        default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
        default_injections=_COMMON_INJECTIONS,
        default_fixups=("content_length",),
        max_candidates=8,
        single_message_methods=("GET", "HEAD", "OPTIONS"),
        content_length_validation=True,
        aflnet_region_rules=("One region ends at \\r\\n\\r\\n.", "AFLNet does not use Content-Length to keep a body in the same region."),
    ),
    "HTTP/1.1": ProtocolMutationPolicy(
        protocol="HTTP/1.1",
        default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 127, 128),
        default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
        default_injections=_COMMON_INJECTIONS,
        default_fixups=("content_length",),
        max_candidates=8,
        single_message_methods=("GET", "HEAD", "OPTIONS"),
        content_length_validation=True,
        aflnet_region_rules=("One region ends at \\r\\n\\r\\n.", "AFLNet does not use Content-Length to keep a body in the same region."),
    ),
    "DAAP-HTTP": ProtocolMutationPolicy(
        protocol="DAAP-HTTP",
        default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 127, 128),
        default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
        default_injections=_COMMON_INJECTIONS,
        default_fixups=("content_length",),
        max_candidates=8,
        single_message_methods=("GET", "HEAD", "OPTIONS"),
        content_length_validation=True,
        aflnet_region_rules=("One region ends at \\r\\n\\r\\n.", "AFLNet does not use Content-Length to keep a body in the same region."),
    ),
    "SIP": ProtocolMutationPolicy(
        protocol="SIP",
        default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 95, 127),
        default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
        default_injections=_COMMON_INJECTIONS + ("z9hG4bK",),
        default_fixups=("content_length", "cseq"),
        max_candidates=8,
        single_message_methods=("REGISTER", "OPTIONS"),
        parser_single_message_allowed=False,
        content_length_validation=True,
        request_region_start_methods=("REGISTER", "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "MESSAGE", "SUBSCRIBE", "NOTIFY", "REFER", "INFO", "PRACK", "UPDATE", "PUBLISH"),
        boundary_line_length_cap=4096,
        vuln_line_length_cap=8192,
        aflnet_region_rules=("A new region starts only when the next bytes after CRLF are a SIP request method.",),
    ),
}


def get_protocol_policy(protocol: str) -> ProtocolMutationPolicy:
    proto = str(protocol or "").upper()
    return _POLICIES.get(
        proto,
        ProtocolMutationPolicy(
            protocol=proto or "UNKNOWN",
            default_boundary_lengths=(0, 1, 2, 3, 7, 15, 31, 63, 64, 65, 127, 128),
            default_vuln_lengths=(32, 64, 128, 256, 512, 1024, 2048, 4096, 8192),
            default_injections=_COMMON_INJECTIONS,
            default_fixups=("content_length",),
            max_candidates=6,
            single_message_methods=(),
            aflnet_region_rules=("Preserve the existing AFLNet region boundaries for this protocol.",),
        ),
    )


def function_allows_single_message(policy: ProtocolMutationPolicy, function_name: str, method: str) -> bool:
    fn = str(function_name or "").lower()
    current_method = str(method or "").upper()
    allowed_methods = set(policy.single_message_methods)
    if current_method in allowed_methods:
        return True
    if any(keyword in fn for keyword in policy.parser_function_keywords):
        return bool(policy.parser_single_message_allowed)
    return False
