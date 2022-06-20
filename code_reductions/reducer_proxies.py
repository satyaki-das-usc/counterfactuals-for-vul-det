import sys
sys.path.append("..")

from counterfactuals.base_proxy import BasePerturbationProxy
from typing import List, Tuple

class RedundantCodeClassifier:

    OFFENSIVE_WORD_SCORE_INCREASE:float = 0.15
    FORBIDDEN_WORD_SCORE_INCREASE:float = 0.2

    def __init__(
        self,
        offensive_words: List[str],
        forbidden_words: List[str]
    ):
        self.forbidden_words = forbidden_words
        self.offensive_words = offensive_words

    def predict(self, sentence: str) -> Tuple[int, float]:
        sequence = sentence.split(' ')
        forbidden_word_count = 0
        offensive_word_count = 0
        for token in sequence:
            if token in self.forbidden_words:
                forbidden_word_count += 1
                continue
            if token in self.offensive_words:
                offensive_word_count += 1

        # if a forbidden word is used, score is at least 0.5
        # and goes up in increments from there from there
        score = 0.0
        if forbidden_word_count > 0:
            score += 0.5 + ((forbidden_word_count-1)*self.FORBIDDEN_WORD_SCORE_INCREASE)

        # Add 0.15 score for each offensive word
        score += offensive_word_count*self.OFFENSIVE_WORD_SCORE_INCREASE
        label = 1 if score >= 0.5 else 0

        return (label, min(score, 1.0))

class CCodePerturbationProxy(BasePerturbationProxy):
    def classify(self, document) -> Tuple[bool, float]:
        code_classifier = RedundantCodeClassifier(
            # primitive datatypes are offensive
            offensive_words=["int", "char'" "float", "double'" "unsigned"],
            # keywords are forbidden
            forbidden_words=["break", "continue", "for", "if", "else", "while", "do"]
        )
        return code_classifier.predict(document)