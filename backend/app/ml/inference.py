import logging
import os

from app.core.text.pipeline import analyze_and_normalize
from app.ml.schemas import InferenceRequest, InferenceResponse, ScamCategory

try:
    import torch
    import torch.nn.functional as F
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
except ImportError:
    torch, F = None, None
    AutoModelForSequenceClassification, AutoTokenizer = None, None

logger = logging.getLogger(__name__)

# Security: Hardcoded expected path to prevent path traversal
MODEL_ARTIFACT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "model_artifact"))

# Security: Input length limits
MAX_TOKENS = 128
LOW_CONFIDENCE_THRESHOLD = 0.65


class ScamClassifier:
    """Singleton inference engine."""

    _instance = None
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = None
        self.model_version = "v1.0.0-xlm-roberta"
        self._load_model()
        
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_model(self):
        if torch is None:
            logger.warning("PyTorch not installed. Running in Mock Inference Mode for static verification.")
            return

        if not os.path.exists(MODEL_ARTIFACT_PATH):
            logger.error(f"Model artifact not found at {MODEL_ARTIFACT_PATH}")
            raise RuntimeError("Model artifact missing. Inference disabled.")

        logger.info(f"Loading model from {MODEL_ARTIFACT_PATH}")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Inference device: {self.device}")
        
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_ARTIFACT_PATH)
        self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_ARTIFACT_PATH)
        self.model.to(self.device)
        self.model.eval()

    def predict(self, request: InferenceRequest) -> InferenceResponse:
        """
        Secure inference pipeline:
        1. Normalize Text
        2. Check limits
        3. Tokenize
        4. Predict
        5. Calibrate confidence
        """
        # 1. Text Normalization
        text_result = analyze_and_normalize(request.text)
        
        # Security: if text is empty after normalization
        if not text_result.normalized_text.strip():
            return InferenceResponse(
                text_analysis=text_result,
                risk_score=0.0,
                risk_level="SAFE",
                scam_family=ScamCategory.SAFE,
                confidence=1.0,
                model_version=self.model_version,
                is_low_confidence=False,
            )

        # Mock Mode Fallback (if torch not installed)
        if torch is None or self.model is None:
            return InferenceResponse(
                text_analysis=text_result,
                risk_score=0.9,
                risk_level="MALICIOUS",
                scam_family=ScamCategory.OTHER_SCAM,
                confidence=0.8,
                model_version="mock-v1",
                is_low_confidence=False,
            )

        # 2 & 3. Tokenize with strict length cap
        inputs = self.tokenizer(
            text_result.normalized_text,
            return_tensors="pt",
            truncation=True,
            max_length=MAX_TOKENS,
            padding=False,
        ).to(self.device)

        # 4. Predict
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = F.softmax(logits, dim=-1)
            
        max_prob, pred_idx = torch.max(probs, dim=1)
        confidence = max_prob.item()
        label = self.model.config.id2label[pred_idx.item()]
        
        # Multiply text engine confidence with ML confidence
        final_confidence = confidence * text_result.confidence
        
        # 5. Calibration
        is_low_confidence = final_confidence < LOW_CONFIDENCE_THRESHOLD
        
        if is_low_confidence:
            # Revert to SAFE/UNKNOWN if we aren't confident enough to accuse
            risk_level = "SAFE"
            scam_family = ScamCategory.SAFE
            risk_score = final_confidence * 0.3  # Scale down
        else:
            scam_family = ScamCategory(label)
            if scam_family == ScamCategory.SAFE:
                risk_level = "SAFE"
                risk_score = 1.0 - final_confidence
            else:
                risk_level = "MALICIOUS"
                risk_score = final_confidence

        return InferenceResponse(
            text_analysis=text_result,
            risk_score=risk_score,
            risk_level=risk_level,
            scam_family=scam_family,
            confidence=final_confidence,
            model_version=self.model_version,
            is_low_confidence=is_low_confidence,
        )
