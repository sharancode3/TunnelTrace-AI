"""Section-aware parser and chunker for authoritative standards documents.

Extracts structured sections, normative keywords (MUST, SHALL, SHOULD, MUST NOT, SHALL NOT),
and computes deterministic SHA-256 hashes for documents and chunks.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

NORMATIVE_KEYWORDS = ["MUST", "MUST NOT", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED"]


@dataclass(frozen=True)
class ParsedSectionChunk:
    """Represents a discrete semantic chunk of a standard tied to a specific section."""

    document_code: str
    authority: str
    revision: str
    section_reference: str
    section_title: str
    chunk_index: int
    chunk_text: str
    chunk_sha256: str
    normative_keywords: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_code": self.document_code,
            "authority": self.authority,
            "revision": self.revision,
            "section_reference": self.section_reference,
            "section_title": self.section_title,
            "chunk_index": self.chunk_index,
            "chunk_text": self.chunk_text,
            "chunk_sha256": self.chunk_sha256,
            "normative_keywords": list(self.normative_keywords),
        }


@dataclass(frozen=True)
class ParsedDocumentMetadata:
    """Extracted top-level metadata of an authoritative standard."""

    document_code: str
    title: str
    authority: str
    revision: str
    publication_date: str | None
    source_url: str | None
    source_file_path: str
    source_sha256: str
    chunks: tuple[ParsedSectionChunk, ...]


class StandardsDocumentParser:
    """Parses structured Markdown representations of standards into discrete semantic chunks."""

    PARSER_VERSION = "1.0.0"

    @classmethod
    def parse_file(cls, file_path: Path | str) -> ParsedDocumentMetadata:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Standards document not found: {file_path}")

        content = path.read_text(encoding="utf-8")
        file_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Extract header metadata
        lines = content.splitlines()
        title = ""
        doc_code = path.stem.replace("_", " ")
        authority = "IETF" if "RFC" in doc_code.upper() else "NIST"
        revision = "1.0"
        pub_date = None
        source_url = None

        # Look for frontmatter or top lines
        for i, line in enumerate(lines[:20]):
            if line.startswith("# ") and not title:
                title = line[2:].strip()
            elif line.startswith("## ") and title:
                title = f"{title} - {line[3:].strip()}"
            elif "**Authority:**" in line:
                authority = line.split("**Authority:**")[1].strip()
            elif "**Document Code:**" in line:
                doc_code = line.split("**Document Code:**")[1].strip()
            elif "**Publication Date:**" in line:
                pub_date = line.split("**Publication Date:**")[1].strip()
            elif "**URL:**" in line:
                source_url = line.split("**URL:**")[1].strip()
            elif "Rev" in doc_code or "Revision" in line:
                m = re.search(r"Rev(?:ision)?\.?\s*(\w+)", line, re.IGNORECASE)
                if m:
                    revision = f"Rev {m.group(1)}"

        # Split by section headers `### Section ...`
        section_pattern = re.compile(r"^###\s+(Section\s+[0-9a-zA-Z\.\-_]+(?:\s+.*)?)$", re.MULTILINE)
        chunks: list[ParsedSectionChunk] = []
        chunk_idx = 0

        # Find all section headers and their slice positions
        matches = list(section_pattern.finditer(content))
        if not matches:
            # Fallback if no ### Section exists: use entire content as one chunk
            c_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            keywords = tuple(kw for kw in NORMATIVE_KEYWORDS if re.search(rf"\b{kw}\b", content))
            chunks.append(
                ParsedSectionChunk(
                    document_code=doc_code,
                    authority=authority,
                    revision=revision,
                    section_reference="General",
                    section_title=title or doc_code,
                    chunk_index=0,
                    chunk_text=content.strip(),
                    chunk_sha256=c_hash,
                    normative_keywords=keywords,
                )
            )
        else:
            for idx, m in enumerate(matches):
                sec_header = m.group(1).strip()
                # Parse section reference and section title
                # E.g. "Section 5.1.1 Cryptographic Algorithms for Confidentiality"
                parts = sec_header.split(maxsplit=2)
                if len(parts) >= 2 and parts[0].lower() == "section":
                    sec_ref = f"Section {parts[1]}"
                    sec_title = parts[2] if len(parts) > 2 else sec_ref
                else:
                    sec_ref = sec_header
                    sec_title = sec_header

                start_pos = m.end()
                end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
                sec_body = content[start_pos:end_pos].strip()

                chunk_text = f"[{doc_code}] {sec_ref}: {sec_title}\n\n{sec_body}"
                c_hash = hashlib.sha256(chunk_text.encode("utf-8")).hexdigest()
                keywords = tuple(kw for kw in NORMATIVE_KEYWORDS if re.search(rf"\b{kw}\b", chunk_text))

                chunks.append(
                    ParsedSectionChunk(
                        document_code=doc_code,
                        authority=authority,
                        revision=revision,
                        section_reference=sec_ref,
                        section_title=sec_title,
                        chunk_index=chunk_idx,
                        chunk_text=chunk_text,
                        chunk_sha256=c_hash,
                        normative_keywords=keywords,
                    )
                )
                chunk_idx += 1

        return ParsedDocumentMetadata(
            document_code=doc_code,
            title=title or doc_code,
            authority=authority,
            revision=revision,
            publication_date=pub_date,
            source_url=source_url,
            source_file_path=str(path.resolve()),
            source_sha256=file_sha256,
            chunks=tuple(chunks),
        )
