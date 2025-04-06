from abc import ABC, abstractmethod

class Predictor:
    @abstractmethod
    def predict(self, rows: list[dict]) -> list[bool]:
        pass
