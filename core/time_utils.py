"""
Time Utilities for CipherShare
Provides standardized UTC timestamp generation, parsing, and conversion to IST (Asia/Kolkata, UTC+05:30).
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Union

# Define IST timezone (+05:30)
IST = timezone(timedelta(hours=5, minutes=30), name="IST")


def utc_now() -> datetime:
    """Returns the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_now_str(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Returns the current UTC datetime as a formatted string."""
    return utc_now().strftime(fmt)


def parse_utc_timestamp(dt_input: Union[str, datetime, None]) -> Optional[datetime]:
    """
    Parses a string or datetime object into a timezone-aware UTC datetime.
    Supports formats:
    - %Y-%m-%d %H:%M:%S
    - %Y-%m-%d %H:%M:%S.%f
    - ISO 8601 strings (e.g. 2026-10-30T20:01:40Z or 2026-10-30T20:01:40)
    """
    if dt_input is None:
        return None

    if isinstance(dt_input, datetime):
        if dt_input.tzinfo is None:
            # Naive datetime is assumed to represent UTC storage
            return dt_input.replace(tzinfo=timezone.utc)
        return dt_input.astimezone(timezone.utc)

    if not isinstance(dt_input, str):
        return None

    dt_str = dt_input.strip()
    if not dt_str:
        return None

    # Handle ISO formats
    if "T" in dt_str:
        clean_str = dt_str.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

    # Try common SQLite and standard formats
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(dt_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def utc_to_ist(dt_input: Union[str, datetime, None]) -> Optional[datetime]:
    """Converts a UTC string or datetime into a timezone-aware IST datetime."""
    dt_utc = parse_utc_timestamp(dt_input)
    if dt_utc is None:
        return None
    return dt_utc.astimezone(IST)


def format_ist(dt_input: Union[str, datetime, None], fmt: str = "%d %b %Y, %I:%M:%S %p IST") -> str:
    """
    Formats a UTC timestamp string or datetime into an IST formatted string.
    Default: '31 Oct 2026, 01:30:45 AM IST'
    If input is missing or unparseable, returns 'Not available' or string as-is.
    """
    if dt_input is None or dt_input == "":
        return "Not available"

    dt_ist = utc_to_ist(dt_input)
    if dt_ist is None:
        return str(dt_input)

    return dt_ist.strftime(fmt)


def time_ago(dt_input: Union[str, datetime, None]) -> str:
    """
    Returns a human-readable relative time string (e.g., 'Just now', '5 mins ago', '2 hours ago', 'Yesterday').
    Calculated relative to current UTC time.
    """
    if dt_input is None or dt_input == "":
        return ""

    dt_utc = parse_utc_timestamp(dt_input)
    if dt_utc is None:
        return ""

    now = utc_now()
    diff = now - dt_utc
    total_seconds = int(diff.total_seconds())

    if total_seconds < 0:
        return "Just now"
    if total_seconds < 30:
        return "Just now"
    if total_seconds < 60:
        return f"{total_seconds}s ago"
    
    minutes = total_seconds // 60
    if minutes < 60:
        return f"{minutes} min{'s' if minutes != 1 else ''} ago"
    
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hr{'s' if hours != 1 else ''} ago"
    
    days = hours // 24
    if days == 1:
        return "Yesterday"
    if days < 30:
        return f"{days} days ago"
    
    months = days // 30
    if months < 12:
        return f"{months} mo{'s' if months != 1 else ''} ago"
    
    years = months // 12
    return f"{years} yr{'s' if years != 1 else ''} ago"

