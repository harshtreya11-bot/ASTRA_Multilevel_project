import csv
import io
import re
from datetime import datetime
from django.utils import timezone
from django.utils.dateparse import parse_datetime


class LogParserEngine:
    """
    Unified parsing engine for CSV, LOG, and TXT files.
    Normalizes log levels, timestamps, log sources, and extra field data.
    """

    LOG_LEVEL_MAP = {
        'DEBUG': 'DEBUG',
        'DBG': 'DEBUG',
        'TRACE': 'DEBUG',
        'INFO': 'INFO',
        'INF': 'INFO',
        'NOTICE': 'INFO',
        'WARN': 'WARNING',
        'WARNING': 'WARNING',
        'WRN': 'WARNING',
        'ERR': 'ERROR',
        'ERROR': 'ERROR',
        'FATAL': 'CRITICAL',
        'CRITICAL': 'CRITICAL',
        'SEVERE': 'CRITICAL',
        'EMERG': 'CRITICAL',
        'SUCCESS': 'INFO',
    }

    # Standard Regex Patterns for LOG and TXT line matching
    PATTERN_ISO_LOG = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
        r'(?:\[(?P<level>[A-Za-z]+)\]|(?P<level_alt>[A-Za-z]+):?)\s+'
        r'(?:\[(?P<source>[^\]]+)\]|(?P<source_alt>[\w\.\-]+):)?\s*'
        r'(?P<message>.*)$'
    )

    PATTERN_BRACKET_LOG = re.compile(
        r'^\[(?P<timestamp>[^\]]+)\]\s+'
        r'\[(?P<level>[A-Za-z]+)\]\s+'
        r'(?:\[(?P<source>[^\]]+)\]\s+)?'
        r'(?P<message>.*)$'
    )

    PATTERN_APACHE_ACCESS = re.compile(
        r'^(?P<source>\S+)\s+\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<message>[^"]*)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<bytes>\S+)'
    )

    PATTERN_GENERIC_LEVEL = re.compile(
        r'\b(?P<level>DEBUG|DBG|INFO|INF|WARN|WARNING|ERR|ERROR|FATAL|CRITICAL|SEVERE)\b',
        re.IGNORECASE
    )

    PATTERN_GENERIC_TIMESTAMP = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})'
    )

    @classmethod
    def normalize_level(cls, level_raw: str) -> str:
        if not level_raw:
            return 'UNKNOWN'
        clean = level_raw.strip().upper()
        return cls.LOG_LEVEL_MAP.get(clean, 'UNKNOWN')

    @classmethod
    def parse_timestamp(cls, raw_ts: str):
        if not raw_ts:
            return None
        raw_ts = raw_ts.strip()
        
        # 1. Try standard Django dateparse (ISO format)
        dt = parse_datetime(raw_ts)
        if dt:
            return timezone.make_aware(dt) if timezone.is_naive(dt) else dt

        # 2. Try common strftime formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S,%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%b %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(raw_ts, fmt)
                if fmt == "%b %d %H:%M:%S":
                    dt = dt.replace(year=datetime.now().year)
                return timezone.make_aware(dt) if timezone.is_naive(dt) else dt
            except ValueError:
                continue

        return None

    @classmethod
    def parse_file(cls, file_obj, file_format: str):
        """
        Parses an uploaded file object based on format ('csv', 'log', 'txt').
        Yields normalized log dict entries.
        """
        file_format = file_format.lower()
        if file_format == 'csv':
            yield from cls._parse_csv(file_obj)
        elif file_format in ['log', 'txt']:
            yield from cls._parse_text_log(file_obj)
        else:
            raise ValueError(f"Unsupported file format: '{file_format}'")

    @classmethod
    def _parse_csv(cls, file_obj):
        """
        Processes CSV content line by line using DictReader or header identification.
        """
        content = file_obj.read()
        if isinstance(content, bytes):
            try:
                text = content.decode('utf-8-sig')
            except UnicodeDecodeError:
                text = content.decode('latin-1', errors='replace')
        else:
            text = content

        stream = io.StringIO(text)
        
        # Detect delimiter
        sample = text[:2048]
        delimiter = ','
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
            delimiter = dialect.delimiter
        except Exception:
            pass

        reader = csv.DictReader(stream, delimiter=delimiter)
        
        # Column mapping detection
        fieldnames = [f.strip() for f in (reader.fieldnames or [])]
        ts_col = cls._find_column(fieldnames, ['timestamp', 'time', 'datetime', 'date', 'created_at', 'ts'])
        level_col = cls._find_column(fieldnames, ['level', 'log_level', 'loglevel', 'severity', 'status_code', 'type'])
        msg_col = cls._find_column(fieldnames, ['message', 'msg', 'log', 'detail', 'details', 'description', 'content', 'text'])
        source_col = cls._find_column(fieldnames, ['source', 'service', 'module', 'logger', 'ip', 'host', 'client_ip', 'user'])

        for idx, row in enumerate(reader, start=2):
            if not row or not any(row.values()):
                continue

            raw_ts = row.get(ts_col, '') if ts_col else ''
            raw_level = row.get(level_col, '') if level_col else ''
            raw_msg = row.get(msg_col, '') if msg_col else ''
            raw_source = row.get(source_col, '') if source_col else ''

            if not raw_msg and not raw_level and not raw_ts:
                # Fallback: join row values into a message
                raw_msg = " | ".join([f"{k}: {v}" for k, v in row.items() if v])

            parsed_ts = cls.parse_timestamp(raw_ts)
            norm_level = cls.normalize_level(raw_level)

            # Collect extra key-values
            known_cols = {ts_col, level_col, msg_col, source_col}
            extra_data = {k: v for k, v in row.items() if k not in known_cols and v}

            yield {
                'line_number': idx,
                'raw_timestamp': raw_ts,
                'timestamp': parsed_ts,
                'log_level': norm_level,
                'source': raw_source,
                'message': raw_msg,
                'raw_line': " | ".join([f"{k}={v}" for k, v in row.items() if v]),
                'extra_data': extra_data,
            }

    @classmethod
    def _parse_text_log(cls, file_obj):
        """
        Parses unstructured text or structured log files (.log, .txt).
        Supports multi-line stack traces and standard log regexes.
        """
        content = file_obj.read()
        if isinstance(content, bytes):
            try:
                lines = content.decode('utf-8-sig').splitlines()
            except UnicodeDecodeError:
                lines = content.decode('latin-1', errors='replace').splitlines()
        else:
            lines = content.splitlines()

        current_entry = None

        for idx, line in enumerate(lines, start=1):
            line_str = line.rstrip()
            if not line_str:
                continue

            # Try parsing with ISO pattern
            match = cls.PATTERN_ISO_LOG.match(line_str)
            if match:
                if current_entry:
                    yield current_entry
                groups = match.groupdict()
                raw_ts = groups.get('timestamp') or ''
                raw_lvl = groups.get('level') or groups.get('level_alt') or ''
                raw_src = groups.get('source') or groups.get('source_alt') or ''
                msg = groups.get('message') or ''

                current_entry = {
                    'line_number': idx,
                    'raw_timestamp': raw_ts,
                    'timestamp': cls.parse_timestamp(raw_ts),
                    'log_level': cls.normalize_level(raw_lvl),
                    'source': raw_src.strip() if raw_src else '',
                    'message': msg.strip(),
                    'raw_line': line_str,
                    'extra_data': {},
                }
                continue

            # Try Bracket Pattern
            match = cls.PATTERN_BRACKET_LOG.match(line_str)
            if match:
                if current_entry:
                    yield current_entry
                groups = match.groupdict()
                raw_ts = groups.get('timestamp') or ''
                raw_lvl = groups.get('level') or ''
                raw_src = groups.get('source') or ''
                msg = groups.get('message') or ''

                current_entry = {
                    'line_number': idx,
                    'raw_timestamp': raw_ts,
                    'timestamp': cls.parse_timestamp(raw_ts),
                    'log_level': cls.normalize_level(raw_lvl),
                    'source': raw_src.strip() if raw_src else '',
                    'message': msg.strip(),
                    'raw_line': line_str,
                    'extra_data': {},
                }
                continue

            # Try Apache Access Log Pattern
            match = cls.PATTERN_APACHE_ACCESS.match(line_str)
            if match:
                if current_entry:
                    yield current_entry
                groups = match.groupdict()
                raw_ts = groups.get('timestamp') or ''
                status = groups.get('status') or ''
                
                # Http status >= 500 error, >= 400 warn
                lvl = 'INFO'
                if status.startswith('5'):
                    lvl = 'ERROR'
                elif status.startswith('4'):
                    lvl = 'WARNING'

                current_entry = {
                    'line_number': idx,
                    'raw_timestamp': raw_ts,
                    'timestamp': cls.parse_timestamp(raw_ts),
                    'log_level': lvl,
                    'source': groups.get('source') or '',
                    'message': f"{groups.get('message')} - Status: {status} ({groups.get('bytes')} bytes)",
                    'raw_line': line_str,
                    'extra_data': {'status_code': status, 'bytes': groups.get('bytes')},
                }
                continue

            # Check if this is a continuation of previous entry (e.g., Exception stack trace)
            if current_entry and (line_str.startswith((' ', '\t', 'Traceback', 'Caused by', '  at ')) or not cls.PATTERN_GENERIC_TIMESTAMP.search(line_str)):
                current_entry['message'] += f"\n{line_str}"
                current_entry['raw_line'] += f"\n{line_str}"
                continue

            # Generic fallback matching for plain .txt or custom format lines
            if current_entry:
                yield current_entry

            lvl_match = cls.PATTERN_GENERIC_LEVEL.search(line_str)
            ts_match = cls.PATTERN_GENERIC_TIMESTAMP.search(line_str)

            raw_lvl = lvl_match.group('level') if lvl_match else 'UNKNOWN'
            raw_ts = ts_match.group('timestamp') if ts_match else ''

            current_entry = {
                'line_number': idx,
                'raw_timestamp': raw_ts,
                'timestamp': cls.parse_timestamp(raw_ts),
                'log_level': cls.normalize_level(raw_lvl),
                'source': '',
                'message': line_str,
                'raw_line': line_str,
                'extra_data': {},
            }

        if current_entry:
            yield current_entry

    @staticmethod
    def _find_column(fieldnames, candidates):
        for name in fieldnames:
            clean_name = name.strip().lower().replace('_', '').replace(' ', '')
            for cand in candidates:
                if clean_name == cand or cand in clean_name:
                    return name
        return None
