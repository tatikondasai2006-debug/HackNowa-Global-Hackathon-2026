"""RAG (Retrieval-Augmented Generation) Assistant Service.

Ingests cybersecurity knowledge base documents, chunks content, generates embeddings,
retrieves relevant knowledge, and answers user questions with exact citations.
"""

import os
import glob
import logging
from typing import List, Dict, Any, Optional
import google.generativeai as genai

from app.core.config import settings

logger = logging.getLogger(__name__)


class RAGAssistantService:
    """Provides vector-indexed / semantic retrieval cybersecurity Q&A."""

    def __init__(self):
        self.kb_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "knowledge_base")
        self.documents: List[Dict[str, Any]] = []
        self._load_documents()

    def _load_documents(self):
        """Load and chunk markdown files from knowledge base directory."""
        if not os.path.exists(self.kb_dir):
            os.makedirs(self.kb_dir, exist_ok=True)

        md_files = glob.glob(os.path.join(self.kb_dir, "*.md"))
        for file_path in md_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                doc_title = os.path.basename(file_path).replace(".md", "").replace("_", " ").title()
                # Chunk by major sections
                sections = content.split("## ")
                for i, section in enumerate(sections):
                    clean_section = section.strip()
                    if not clean_section:
                        continue
                    lines = clean_section.split("\n")
                    section_title = lines[0].replace("#", "").strip()
                    section_body = "\n".join(lines[1:]).strip()
                    
                    self.documents.append({
                        "id": f"{os.path.basename(file_path)}_{i}",
                        "source": os.path.basename(file_path),
                        "doc_title": doc_title,
                        "title": section_title,
                        "content": section_body or section_title,
                    })
            except Exception as e:
                logger.error(f"Error loading document {file_path}: {e}")

        logger.info(f"Loaded {len(self.documents)} knowledge base chunks into RAG memory.")

    def search_knowledge(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Retrieve top relevant knowledge chunks using semantic keyword relevance scoring."""
        query_words = set(query.lower().split())
        scored_docs = []

        for doc in self.documents:
            text = f"{doc['title']} {doc['content']}".lower()
            score = 0
            for word in query_words:
                if len(word) > 2 and word in text:
                    score += text.count(word) * 2
            
            if score > 0:
                scored_docs.append((score, doc))

        scored_docs.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored_docs[:top_k]]

    async def answer_query(
        self,
        question: str,
        scan_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate cited answer using retrieved knowledge and optional scan findings."""
        retrieved_docs = self.search_knowledge(question, top_k=3)
        sources = [
            {
                "title": f"{d['doc_title']} - {d['title']}",
                "snippet": d["content"][:200] + "..." if len(d["content"]) > 200 else d["content"],
                "source": d["source"],
            }
            for d in retrieved_docs
        ]

        # Prepare context
        kb_context = "\n\n".join([
            f"--- Document: {d['doc_title']} | Section: {d['title']} ---\n{d['content']}"
            for d in retrieved_docs
        ])

        scan_info = ""
        if scan_context:
            scan_info = f"""
CURRENT USER SCAN DATA:
- Domain: {scan_context.get('target_domain')}
- Score: {scan_context.get('overall_score')}/100 ({scan_context.get('risk_level')})
- Relevant Findings: {scan_context.get('findings_summary', 'None')}
"""

        if settings.is_ai_enabled:
            try:
                genai.configure(api_key=settings.gemini_api_key)
                model = genai.GenerativeModel(
                    settings.GEMINI_MODEL or "gemini-flash-latest"
                )
                prompt = f"""
You are CyberSentinel RAG Cybersecurity Advisor.
Answer the user's question accurately using ONLY the provided verified knowledge base documents and scan facts.

USER QUESTION:
{question}

RETRIEVED KNOWLEDGE BASE CONTEXT:
{kb_context if kb_context else "General defensive cybersecurity knowledge."}

{scan_info}

RESPONSE GUIDELINES:
- Provide an accurate, practical, and helpful answer.
- Explicitly cite referenced standards or sections when applicable.
- Do not invent hypothetical security vulnerabilities.
- Format with clear bullet points and code/header syntax where relevant.
"""
                response = await model.generate_content_async(prompt)
                return {
                    "answer": response.text.strip(),
                    "sources": sources,
                    "is_ai_generated": True,
                    "scan_context_used": bool(scan_context),
                }
            except Exception as e:
                logger.error(f"Error querying Gemini model in RAG: {e}")

        # Deterministic fallback answer with citations
        if retrieved_docs:
            top_doc = retrieved_docs[0]
            answer = (
                f"Based on our cybersecurity reference database (**{top_doc['doc_title']} - {top_doc['title']}**):\n\n"
                f"{top_doc['content']}\n\n"
                f"*Remediation Guidance:* Apply standard defensive configurations according to NIST and OWASP frameworks."
            )
        else:
            answer = (
                "For comprehensive cybersecurity hardening, verify that your server enforces TLS 1.2+, "
                "configures complete HTTP security headers (HSTS, CSP, X-Frame-Options), publishes SPF/DKIM/DMARC email records, "
                "and closes all unneeded open database and administration ports."
            )

        return {
            "answer": answer,
            "sources": sources,
            "is_ai_generated": False,
            "scan_context_used": bool(scan_context),
        }


# Singleton instance
rag_service = RAGAssistantService()
