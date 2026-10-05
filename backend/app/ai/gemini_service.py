"""Compatibility wrapper around the service-layer Gemini client."""

from app.services.gemini_service import GeminiService, gemini_service

GeminiAIService = GeminiService
ai_service = gemini_service
