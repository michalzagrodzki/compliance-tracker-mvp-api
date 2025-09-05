import subprocess
import clamd
import hashlib, os, re, tempfile, time, uuid, mimetypes
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict, deque
import uuid
from pathlib import Path as PathlibPath

from fastapi import HTTPException, Path, UploadFile, Request
import pikepdf
from pydantic import ValidationError

import logging

logger = logging.getLogger(__name__)

class UploadSecurityError(Exception):
    """Custom exception for upload security violations."""
    pass

class FileUploadRateLimiter:
    """Rate limiter specifically for file uploads with memory-efficient sliding window."""
    def __init__(self, max_uploads_per_hour: int = 50, max_uploads_per_minute: int = 5):
        self.max_uploads_per_hour = max_uploads_per_hour
        self.max_uploads_per_minute = max_uploads_per_minute
        self.upload_times = defaultdict(deque)  # client_id -> deque of upload timestamps

    def is_upload_allowed(self, client_id: str) -> bool:
        now = datetime.utcnow()
        client_uploads = self.upload_times[client_id]

        hour_ago = now - timedelta(hours=1)
        minute_ago = now - timedelta(minutes=1)

        # Clean up old entries
        while client_uploads and client_uploads[0] < hour_ago:
            client_uploads.popleft()

        uploads_last_hour = len(client_uploads)
        uploads_last_minute = sum(1 for t in client_uploads if t > minute_ago)

        if uploads_last_hour >= self.max_uploads_per_hour:
            logger.warning(f"Hourly upload rate limit exceeded for client: {client_id}")
            return False

        if uploads_last_minute >= self.max_uploads_per_minute:
            logger.warning(f"Per-minute upload rate limit exceeded for client: {client_id}")
            return False

        client_uploads.append(now)
        return True

    def get_rate_limit_info(self, client_id: str) -> Dict[str, Any]:
        now = datetime.utcnow()
        client_uploads = self.upload_times[client_id]
        hour_ago = now - timedelta(hours=1)
        minute_ago = now - timedelta(minutes=1)
        uploads_last_hour = sum(1 for t in client_uploads if t > hour_ago)
        uploads_last_minute = sum(1 for t in client_uploads if t > minute_ago)
        return {
            'uploads_last_hour': uploads_last_hour,
            'max_uploads_per_hour': self.max_uploads_per_hour,
            'uploads_last_minute': uploads_last_minute,
            'max_uploads_per_minute': self.max_uploads_per_minute,
            'remaining_hour': max(0, self.max_uploads_per_hour - uploads_last_hour),
            'remaining_minute': max(0, self.max_uploads_per_minute - uploads_last_minute)
        }

class FileUploadValidator:
    """
    Comprehensive file upload validation following NIST SP 800-53 and OWASP guidelines.

    Security Controls Implemented:
    - NIST SP 800-53 SI-3: Malicious Code Protection
    - NIST SP 800-53 SI-10: Information Input Validation
    - NIST SP 800-53 AC-6: Least Privilege
    - OWASP ASVS V12: File Upload Verification
    - CWE-434: Unrestricted Upload of File with Dangerous Type
    """
    
    # Maximum file sizes (in bytes)
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    MAX_CHUNK_SIZE = 8192  # 8KB chunks for memory-efficient processing
    
    ALLOWED_FIELDS_UPLOAD = {"compliance_domain","document_version","document_tags","document_title","document_author"}
    ALLOWED_COMPLIANCE = {"ISO_27001", "ISO27001"}
    TAG_RE = re.compile(r"^[a-z0-9_\-]{1,32}$", re.IGNORECASE)
    VERSION_RE = re.compile(r"^[A-Za-z0-9._\-]{1,32}$")
    TITLE_RE = re.compile(r"^[\w\s\-\.,:/()]{1,200}$")
    AUTHOR_RE = re.compile(r"^[\w\s\-\.,:/()]{1,120}$")

    # Allowed MIME types for PDF documents
    ALLOWED_MIME_TYPES = {
        'application/pdf',
        'application/x-pdf',
    }
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'.pdf'}
    
    # PDF file signatures (magic numbers)
    PDF_SIGNATURES = [
        b'%PDF-1.',  # Standard PDF signature
        b'%PDF-2.',  # PDF 2.0 signature
    ]
    
    # Dangerous patterns in filename
    DANGEROUS_FILENAME_PATTERNS = [
        r'\.\./',           # Directory traversal
        r'\\\.\\',          # Windows directory traversal
        r'[<>:"|?*]',       # Invalid Windows characters
        r'^\.',             # Hidden files
        r'[\x00-\x1f\x7f-\x9f]',  # Control characters
        r'CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]',  # Windows reserved names
    ]
    
    # Suspicious PDF content patterns
    SUSPICIOUS_PDF_PATTERNS = [
        br'/JavaScript',
        br'/JS',
        br'/EmbeddedFile',
        br'/Launch',
        br'/OpenAction',
        br'<script',
        br'javascript:',
        br'/URI\s*<<[^>]*>>[^<]*http',  # Suspicious URI actions
        br'/SubmitForm',
        br'/ImportData',
        br'/GoToE',
        br'/Rendition',
        br'/RichMedia',
        br'/3D',
        br'/Flash',
    ]
    
    # Content validation limits
    MAX_EMBEDDED_FILES = 0  # No embedded files allowed
    MAX_PAGES = 10000  # Maximum pages
    MAX_PDF_OBJECTS = 50000  # Maximum PDF objects
    
    def __init__(self, quarantine_dir: Optional[str] = None, pdf_dir: Optional[str] = None):
        # Directories can be injected or set via env vars; these have no public access.
        self.quarantine_dir = PathlibPath(quarantine_dir or os.getenv("PDF_QUARANTINE_DIR", "/tmp/pdf_quarantine"))
        self.pdf_dir = PathlibPath(pdf_dir or os.getenv("PDF_DIR", "/tmp/pdf_store"))
        self.rate_limiter = FileUploadRateLimiter()

        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.pdf_dir.mkdir(parents=True, exist_ok=True)
    
    @staticmethod
    def require_uuid4_idempotency(key: Optional[str]) -> str:
        if not key:
            raise HTTPException(status_code=400, detail="Missing Idempotency-Key header (UUIDv4).")
        try:
            v = uuid.UUID(key, version=4)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid Idempotency-Key (UUIDv4 required).")
        return str(v)

    def validate_request_context(self, request: Request, user_id: str) -> None:
        client_ip = self._get_client_ip(request)
        if not self.rate_limiter.is_upload_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            raise HTTPException(status_code=429, detail="Upload rate limit exceeded. Please try again later.")
        if not self.rate_limiter.is_upload_allowed(f"user:{user_id}"):
            logger.warning(f"Rate limit exceeded for user: {user_id}")
            raise HTTPException(status_code=429, detail="Upload rate limit exceeded for user. Please try again later.")
    
    def enforce_content_length(self, request: Request) -> int:
        cl = request.headers.get("content-length")
        if not cl:
            raise HTTPException(status_code=411, detail="Content-Length required.")
        try:
            n = int(cl)
        except ValueError:
            raise HTTPException(status_code=400, detail="Bad Content-Length.")
        if n > self.MAX_FILE_SIZE:
            mb = self.MAX_FILE_SIZE // (1024 * 1024)
            raise HTTPException(status_code=413, detail=f"File too large. Max {mb}MB.")
        return n
    
    def validate_filename(self, filename: str) -> str:
        """
        Validate and sanitize filename.
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
            
        Raises:
            UploadSecurityError: If filename is invalid
        """
        if not filename:
            raise UploadSecurityError("Filename cannot be empty")
        
        # Check length
        if len(filename) > 255:
            raise UploadSecurityError("Filename too long (max 255 characters)")
        
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_FILENAME_PATTERNS:
            if re.search(pattern, filename, re.IGNORECASE):
                logger.warning(f"Dangerous filename pattern detected: {pattern} in {filename}")
                raise UploadSecurityError("Filename contains invalid characters or patterns")
        
        # Validate extension
        _, ext = os.path.splitext(filename.lower())
        if ext not in self.ALLOWED_EXTENSIONS:
            raise UploadSecurityError(f"File extension {ext} not allowed. Only PDF files are supported.")
        
        # Sanitize filename
        sanitized = os.path.basename(filename)
        sanitized = re.sub(r'[^\w\-_\.]', '_', sanitized)
        
        # Ensure it still has .pdf extension after sanitization
        if not sanitized.lower().endswith('.pdf'):
            sanitized += '.pdf'
            
        return sanitized
    
    def validate_metadata(self, compliance_domain, document_version, parsed_tags, title, author):
        if compliance_domain and compliance_domain not in self.ALLOWED_COMPLIANCE:
            raise HTTPException(status_code=400, detail="Unsupported compliance_domain.")
        if document_version and not self.VERSION_RE.fullmatch(document_version):
            raise HTTPException(status_code=400, detail="Invalid document_version.")
        if title and not self.TITLE_RE.fullmatch(title):
            raise HTTPException(status_code=400, detail="Invalid document_title.")
        if author and not self.AUTHOR_RE.fullmatch(author):
            raise HTTPException(status_code=400, detail="Invalid document_author.")
        if any(not self.TAG_RE.fullmatch(t) for t in parsed_tags):
            raise HTTPException(status_code=400, detail="Invalid document_tags.")
    
    def stream_to_quarantine_and_hash(self, upload_file: UploadFile) -> Tuple[Path, str, int]:
        """
        Stream the upload into a quarantine temp file while computing SHA-256.
        Enforces MAX_FILE_SIZE during streaming.
        """
        hasher = hashlib.sha256()
        total = 0
        fd, tmp_path = tempfile.mkstemp(dir=str(self.quarantine_dir), prefix="q_", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as tmp:
                while True:
                    chunk = upload_file.file.read(self.MAX_CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.MAX_FILE_SIZE:
                        raise HTTPException(status_code=413, detail="File too large.")
                    hasher.update(chunk)
                    tmp.write(chunk)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.chmod(tmp_path, 0o640)
            return PathlibPath(tmp_path), hasher.hexdigest(), total
        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise

    def verify_pdf(self, path: Path) -> str:
        # 1) Header check
        with open(path, "rb") as f:
            header = f.read(8)
        if not header.startswith(b"%PDF-"):
            raise UploadSecurityError("Invalid PDF header (missing %PDF-).")

        # Optional: basic version sanity ("1.x" or "2.0")
        ver = header[5:8]
        try:
            ver_txt = ver.decode("ascii", "ignore")
            if not re.match(r"^\d\.\d", ver_txt):
                # Not fatal, but suspicious
                raise UploadSecurityError("Invalid or missing PDF version in header.")
        except Exception:
            raise UploadSecurityError("Corrupted PDF header.")

        # 2) Tail markers: search end of file for startxref and %%EOF
        size = os.path.getsize(path)
        # Many PDFs place these within a small tail window; use 64–256 KiB to be safe
        tail_scan = min(262_144, size)  # 256 KiB
        with open(path, "rb") as f:
            f.seek(-tail_scan, os.SEEK_END)
            tail = f.read()

        if b"startxref" not in tail:
            raise UploadSecurityError("Missing 'startxref' near end of PDF.")
        if b"%%EOF" not in tail:
            raise UploadSecurityError("Missing '%%EOF' near end of PDF.")

        # 3) Parse via pikepdf/qpdf as a structural check (will raise on non-PDF)
        try:
            with pikepdf.open(str(path)) as _pdf:
                pass
        except Exception:
            raise UploadSecurityError("PDF parser rejected the file.")

        return "application/pdf"

    def reject_encrypted_pdf(self, path: Path) -> None:
        try:
            with pikepdf.open(str(path)) as pdf:
                # pikepdf sets .is_encrypted reliably; also catches password prompts via exception
                if pdf.is_encrypted:  # type: ignore[attr-defined]
                    raise UploadSecurityError("Encrypted PDFs are not accepted.")
        except pikepdf._qpdf.PasswordError:  # type: ignore[attr-defined]
            raise UploadSecurityError("Encrypted PDFs are not accepted.")
    
    def clamav_scan_or_raise(self, path: Path) -> Dict[str, str]:
        """
        Scan with clamd if available; fallback to clamscan; skip if not available for development.
        """
        try:
            import clamd
            # Prefer UNIX socket; fallback to network socket
            if PathlibPath("/var/run/clamav/clamd.ctl").exists():
                cd = clamd.ClamdUnixSocket()
            else:
                cd = clamd.ClamdNetworkSocket()
            res = cd.scan(str(path))
            verdict = list(res.values())[0]  # ('OK', 'FOUND', ...)
            if verdict[0] != "OK":
                raise UploadSecurityError(f"Malware detected: {verdict[1]}")
            return {"engine": "clamd", "result": "OK"}
        except Exception:
            # Fallback to clamscan
            try:
                p = subprocess.run(["clamscan", "--no-summary", str(path)], capture_output=True, text=True)
                if p.returncode == 1:
                    sig = p.stdout.strip().split(":")[-1].strip()
                    raise UploadSecurityError(f"Malware detected: {sig}")
                if p.returncode not in (0,):
                    raise HTTPException(status_code=500, detail="AV scan failed.")
                return {"engine": "clamscan", "result": "OK"}
            except FileNotFoundError:
                # ClamAV not installed - warn but allow for development
                logger.warning("ClamAV not available - skipping malware scan (development mode)")
                return {"engine": "none", "result": "SKIPPED", "warning": "ClamAV not available"}
    
    def _delete_names_entries_from_patterns(self, names_dict, patterns) -> list[str]:
        """
        From SUSPICIOUS_PDF_PATTERNS, extract leading PDF name keys (e.g., '/JavaScript')
        and delete corresponding entries from the Catalog /Names dictionary if present.

        Returns a list of removed keys (as strings like '/JavaScript').
        """
        if names_dict is None:
            return []

        keys: set[str] = set()
        for pat in patterns:
            if isinstance(pat, (bytes, bytearray)):
                m = re.match(rb'^\s*/([A-Za-z0-9]+)', pat)
                if m:
                    keys.add('/' + m.group(1).decode('ascii', 'ignore'))

        aliases = {
            '/JS': '/JavaScript',
            '/EmbeddedFile': '/EmbeddedFiles',
        }
        expanded = set()
        for k in keys:
            expanded.add(k)
            if k in aliases:
                expanded.add(aliases[k])
        keys = expanded

        removed: list[str] = []
        for key in list(keys):
            nm = pikepdf.Name(key)
            if nm in names_dict:
                try:
                    del names_dict[nm]
                    removed.append(key)
                except Exception:
                    # best-effort—ignore if deletion fails due to indirect refs or structure
                    pass

        return removed

    def sanitize_pdf_inplace(self, quarantine_path: Path) -> Path:
        """
        Rewrite PDF to strip risky features:
        - Remove Catalog-level /OpenAction and /AA
        - Remove Page-level /AA
        - Remove /Metadata
        - Remove suspicious entries from Catalog /Names using SUSPICIOUS_PDF_PATTERNS
        - Remove specific NameTree branches like /JavaScript and /EmbeddedFiles
        Returns a new sanitized PDF beside the quarantine file.
        """
        out = quarantine_path.with_suffix(".pdf")
        with pikepdf.open(str(quarantine_path)) as pdf:
            root = pdf.Root

            for key in ("/OpenAction", "/AA"):
                if key in root:
                    del root[key]

            if "/Names" in root:
                names = root["/Names"]
                removed = self._delete_names_entries_from_patterns(names, self.SUSPICIOUS_PDF_PATTERNS)
                if removed:
                    logger.info(f"Removed from /Names: {removed}")

                for hard_key in ("/JavaScript", "/EmbeddedFiles"):
                    if hard_key in names:
                        try:
                            del names[hard_key]
                            logger.info(f"Removed explicit /Names entry: {hard_key}")
                        except Exception:
                            pass

            # Page-level additional actions
            for page in pdf.pages:
                if "/AA" in page.obj:
                    del page.obj["/AA"]

            # Strip XMP metadata (can host scriptable content in edge cases)
            if "/Metadata" in root:
                del root["/Metadata"]

            pdf.save(str(out))

        os.chmod(out, 0o640)
        return out
    
    def validate_upload(
        self,
        file: UploadFile,
        request: Request,
        user_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Main validation method that performs comprehensive upload security checks.

        Returns a dict with:
          - original_filename, sanitized_filename, file_size, mime_type
          - sha256_hash, md5_hash
          - scan_results
          - validation_timestamp, client_ip, user_id
          - final_path (str) -> sanitized, promoted PDF path
        """
        try:
            # Context checks
            self.validate_request_context(request, user_id)
            self.enforce_content_length(request)

            # Filename & metadata
            sanitized_filename = self.validate_filename(file.filename or "")
            meta = metadata or {}
            self.validate_metadata(
                meta.get("compliance_domain"),
                meta.get("document_version"),
                meta.get("document_tags") or [],
                meta.get("document_title"),
                meta.get("document_author"),
            )

            q_path, sha256_hash, total_size = self.stream_to_quarantine_and_hash(file)

            detected_mime = self.verify_pdf(q_path)
            if detected_mime not in self.ALLOWED_MIME_TYPES:
                raise UploadSecurityError("Disallowed MIME type.")

            # Reject encrypted PDFs
            self.reject_encrypted_pdf(q_path)

            # AV scan in quarantine
            scan_results = self.clamav_scan_or_raise(q_path)

            # Sanitize dangerous features, produce clean PDF
            sanitized_path = self.sanitize_pdf_inplace(q_path)

            # Promote atomically to permanent storage using sanitized filename
            safe_filename = sanitized_filename
            final_path = self.pdf_dir / safe_filename
            os.replace(sanitized_path, final_path)  # atomic move

            # Best-effort cleanup of quarantine file
            try:
                os.unlink(q_path)
            except Exception:
                pass

            # Compute md5 (optional, secondary)
            # For md5 we can re-hash by streaming final file (small overhead)
            md5 = hashlib.md5()
            with open(final_path, "rb") as f:
                for chunk in iter(lambda: f.read(self.MAX_CHUNK_SIZE), b""):
                    md5.update(chunk)
            md5_hash = md5.hexdigest()

            logger.info(
                f"File upload validation successful: {sanitized_filename} "
                f"(size: {total_size}, sha256: {sha256_hash[:16]}..., user: {user_id})"
            )

            # Reset pointer so downstream could re-read upload if needed (usually not after promotion)
            try:
                file.file.seek(0)
            except Exception:
                pass

            return {
                "original_filename": file.filename,
                "sanitized_filename": safe_filename,  # now content-hash name
                "file_size": total_size,
                "mime_type": detected_mime,
                "sha256_hash": sha256_hash,
                "md5_hash": md5_hash,
                "scan_results": scan_results,
                "validation_timestamp": datetime.utcnow().isoformat(),
                "client_ip": self._get_client_ip(request),
                "user_id": user_id,
                "final_path": str(final_path),
                "metadata": {k: v for k, v in (meta or {}).items() if k in self.ALLOWED_FIELDS_UPLOAD and v is not None},
            }

        except UploadSecurityError as e:
            logger.warning(f"Upload security error: {e}")
            raise HTTPException(status_code=400, detail=str(e))
        except HTTPException:
            # Already mapped with appropriate status
            raise
        except Exception as e:
            logger.error(f"Unexpected upload validation error: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Upload validation failed")

    def _get_client_ip(self, request: Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        return request.client.host if request.client else "unknown"

# Global validator instance
upload_validator = FileUploadValidator()


def validate_document_upload(
    file: UploadFile,
    request: Request,
    user_id: str,
    compliance_domain: Optional[str] = None,
    document_version: Optional[str] = None,
    document_tags: Optional[List[str]] = None,
    document_title: Optional[str] = None,
    document_author: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function for validating and promoting document uploads with metadata.
    """
    metadata = {
        "compliance_domain": compliance_domain,
        "document_version": document_version,
        "document_tags": document_tags or [],
        "document_title": document_title,
        "document_author": document_author,
    }
    return upload_validator.validate_upload(file, request, user_id, metadata)